/**
 * @file src/multipath_fec.cpp
 * @brief Deterministic shard planner for the controlled multipath FEC recovery experiment.
 */

// standard includes
#include <charconv>
#include <system_error>
#include <utility>

// local includes
#include "multipath_fec.h"

namespace multipath_fec {
  namespace {
    /**
     * @brief splitmix64 generator.
     * @details Used only to pick shard indices. It is seeded per block so the same block always
     * selects the same shards, which is what makes the experiment repeatable.
     */
    struct rng_t {
      std::uint64_t state;

      std::uint64_t next() {
        std::uint64_t z = (state += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
      }

      /// Returns a value in [0, bound). Returns 0 when bound is 0.
      std::size_t below(std::size_t bound) {
        return bound ? static_cast<std::size_t>(next() % bound) : 0;
      }
    };

    /**
     * @brief Append up to `count` distinct elements drawn from `pool`.
     * @details Partial Fisher-Yates shuffle; `pool` is reordered in place. Sampling fewer than the
     * pool size leaves the remaining order well-defined for a given seed.
     */
    void sample_distinct(rng_t &rng, std::vector<std::uint32_t> &pool, std::size_t count, std::vector<std::uint32_t> &out) {
      count = std::min(count, pool.size());
      for (std::size_t i = 0; i < count; ++i) {
        std::size_t j = i + rng.below(pool.size() - i);
        std::swap(pool[i], pool[j]);
        out.push_back(pool[i]);
      }
    }
  }  // namespace

  shard_plan_t plan(const config_t &config, std::uint64_t sequence, std::size_t nr_shards, std::size_t data_shards, std::size_t blocksize) {
    shard_plan_t result;
    if (!config.enabled || nr_shards == 0 || data_shards > nr_shards) {
      return result;
    }

    rng_t rng {config.seed ^ (sequence * 0x9E3779B97F4A7C15ULL)};

    // Suppress data shards on the primary path.
    std::vector<std::uint32_t> data_pool;
    data_pool.reserve(data_shards);
    for (std::uint32_t i = 0; i < data_shards; ++i) {
      data_pool.push_back(i);
    }
    sample_distinct(rng, data_pool, config.drop_data, result.primary_drop);

    // Suppress parity shards on the primary path.
    std::vector<std::uint32_t> parity;
    parity.reserve(nr_shards - data_shards);
    for (std::uint32_t i = static_cast<std::uint32_t>(data_shards); i < nr_shards; ++i) {
      parity.push_back(i);
    }
    std::vector<std::uint32_t> parity_pool = parity;
    sample_distinct(rng, parity_pool, config.drop_parity, result.primary_drop);

    std::sort(result.primary_drop.begin(), result.primary_drop.end());

    // Secondary path carries existing parity shards only, bounded by the per-shard byte cap.
    std::size_t copy_budget = 0;
    if (config.byte_cap != 0) {
      copy_budget = config.copy_parity;
      if (blocksize != 0) {
        copy_budget = std::min(copy_budget, config.byte_cap / blocksize);
      }
    }

    if (copy_budget != 0 && !parity.empty()) {
      std::vector<std::uint32_t> dropped_parity;
      std::vector<std::uint32_t> other_parity;
      for (auto index : parity) {
        if (result.drop(index)) {
          dropped_parity.push_back(index);
        } else {
          other_parity.push_back(index);
        }
      }

      // Prefer parity that the primary path is also suppressing, so the experiment measures
      // delivery of a shard the primary path lost. Fill any remaining budget from the rest.
      sample_distinct(rng, dropped_parity, copy_budget, result.secondary_send);
      if (result.secondary_send.size() < copy_budget) {
        sample_distinct(rng, other_parity, copy_budget - result.secondary_send.size(), result.secondary_send);
      }

      std::sort(result.secondary_send.begin(), result.secondary_send.end());
    }

    return result;
  }

  std::vector<std::uint32_t> primary_send_indices_in_range(std::uint32_t begin, std::uint32_t end, const shard_plan_t &plan) {
    std::vector<std::uint32_t> indices;
    if (end > begin) {
      indices.reserve(end - begin);
    }
    for (std::uint32_t i = begin; i < end; ++i) {
      if (!plan.drop(i)) {
        indices.push_back(i);
      }
    }
    return indices;
  }

  std::vector<std::uint32_t> primary_send_indices(std::size_t nr_shards, const shard_plan_t &plan) {
    return primary_send_indices_in_range(0, static_cast<std::uint32_t>(nr_shards), plan);
  }

  std::size_t distinct_surviving(std::size_t nr_shards, const shard_plan_t &plan, bool secondary) {
    std::size_t surviving = nr_shards;
    for (auto index : plan.primary_drop) {
      if (secondary && plan.secondary(index)) {
        continue;  // restored by the secondary path, not a second distinct shard
      }
      --surviving;
    }
    return surviving;
  }

  std::optional<std::uint64_t> parse_quantity(std::string_view text) {
    if (text.empty()) {
      return std::nullopt;
    }

    std::uint64_t value = 0;
    const char *first = text.data();
    const char *last = text.data() + text.size();
    const std::from_chars_result result = std::from_chars(first, last, value);

    // Require the whole input to be consumed: std::from_chars accepts a leading '-' only for signed
    // types, so unsigned rejects it, and it reports out-of-range overflow separately.
    if (result.ec != std::errc() || result.ptr != last) {
      return std::nullopt;
    }

    return value;
  }
}  // namespace multipath_fec
