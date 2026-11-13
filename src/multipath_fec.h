/**
 * @file src/multipath_fec.h
 * @brief Deterministic shard planner for the controlled multipath FEC recovery experiment.
 *
 * An opt-in experiment that suppresses selected shards on
 * the primary (Ethernet/MoCA) path after real FEC generation and forwards a bounded set of the
 * already-generated parity shards to a second path. This header contains only the deterministic
 * decision logic; the transport lives in the caller so the same plan can be exercised by tests
 * without sockets.
 */
#pragma once

// standard includes
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace multipath_fec {
  /**
   * @brief Opt-in experiment configuration.
   * @details Default-constructed config is disabled and produces an empty plan, so callers that
   * never opt in are unaffected.
   */
  struct config_t {
    bool enabled = false;

    /// Base for the deterministic per-block shard selection.
    std::uint64_t seed = 0;

    /// Data shards suppressed on the primary path per FEC block (clamped to the data shard count).
    std::size_t drop_data = 0;

    /// Parity shards suppressed on the primary path per FEC block (clamped to the parity count).
    std::size_t drop_parity = 0;

    /// Existing parity shards forwarded on the secondary path per FEC block (clamped to the parity
    /// count and to the byte cap). Selection only ever returns parity shard indices.
    std::size_t copy_parity = 0;

    /// Per-frame total wire byte budget for the secondary path. Zero disables secondary copies
    /// entirely. The planner additionally bounds a single FEC block's copies by `byte_cap /
    /// blocksize`; the sender tracks the running per-frame total against this same budget.
    std::size_t byte_cap = 0;
  };

  /**
   * @brief Plan for a single FEC block.
   * @details Both index lists are ascending and contain unique shard indices. `secondary_send`
   * contains parity shard indices only.
   */
  struct shard_plan_t {
    std::vector<std::uint32_t> primary_drop;
    std::vector<std::uint32_t> secondary_send;

    /// True if the shard must not be transmitted on the primary path.
    bool drop(std::uint32_t index) const {
      return std::binary_search(primary_drop.begin(), primary_drop.end(), index);
    }

    /// True if the shard is also forwarded on the secondary path.
    bool secondary(std::uint32_t index) const {
      return std::binary_search(secondary_send.begin(), secondary_send.end(), index);
    }
  };

  /**
   * @brief Build the deterministic plan for one FEC block.
   * @param config Experiment configuration.
   * @param sequence A monotonically increasing identifier for this block (for example frame index
   *                 combined with block index). The same sequence always yields the same plan.
   * @param nr_shards Total shards in the block (data + parity).
   * @param data_shards Number of data shards in the block.
   * @param blocksize Encoded byte size of one shard, used to bound the secondary path by byte_cap.
   * @return The shard plan. When `config.enabled` is false the plan is empty.
   */
  shard_plan_t plan(const config_t &config, std::uint64_t sequence, std::size_t nr_shards, std::size_t data_shards, std::size_t blocksize);

  /**
   * @brief Ascending shard indices in [begin, end) that the caller should transmit on the primary
   * path.
   * @details Every index in the range except the suppressed ones. The sender loop calls this for
   * each batch range so that the suppression decision applied to a batched send is identical to
   * the one applied to the per-packet fallback.
   */
  std::vector<std::uint32_t> primary_send_indices_in_range(std::uint32_t begin, std::uint32_t end, const shard_plan_t &plan);

  /**
   * @brief Ascending indices that the caller should transmit on the primary path.
   * @details Every shard index in [0, nr_shards) except the suppressed ones, in ascending order.
   */
  std::vector<std::uint32_t> primary_send_indices(std::size_t nr_shards, const shard_plan_t &plan);

  /**
   * @brief Count of distinct shards that survive a path configuration.
   * @details Suppressed shards are removed; when `secondary` is true, shards forwarded on the
   * secondary path are restored. Shards present in both sets are not double counted.
   */
  std::size_t distinct_surviving(std::size_t nr_shards, const shard_plan_t &plan, bool secondary);

  /**
   * @brief Parse a non-negative decimal quantity for the experiment knobs.
   * @details Rejects empty input, a leading sign, trailing characters, non-digits and overflow.
   * Used instead of the unchecked `util::from_view` so config values cannot silently overflow or
   * truncate.
   * @return The parsed value, or std::nullopt on any error.
   */
  std::optional<std::uint64_t> parse_quantity(std::string_view text);

  /**
   * @brief Dispatch one FEC block's shard range to the primary and secondary paths.
   * @details Shared by the sender loop and the transport PoC so both apply the identical decision
   * and fallback behaviour. The primary path uses a batched send for a contiguous, unsuppressed
   * range and otherwise sends shards individually; a suppressed shard is never dispatched and each
   * primary shard is dispatched at most once. Selected parity shards are also dispatched on the
   * secondary path.
   * @param begin First shard index of the range (inclusive).
   * @param end One past the last shard index of the range.
   * @param plan Plan for the block.
   * @param batch Attempts a batched primary send of [begin, end); returns true on success.
   * @param primary Sends one shard index on the primary path.
   * @param secondary Sends one shard index on the secondary path.
   * @param on_fallback Invoked once when a contiguous batched send fails and individual sends are
   *                    used instead.
   * @return Number of shards dispatched on the primary path.
   */
  template<typename BatchFn, typename PrimaryFn, typename SecondaryFn, typename FallbackFn>
  std::size_t dispatch_block(std::uint32_t begin, std::uint32_t end, const shard_plan_t &plan, BatchFn &&batch, PrimaryFn &&primary, SecondaryFn &&secondary, FallbackFn &&on_fallback) {
    if (begin >= end) {
      return 0;
    }

    if (plan.primary_drop.empty() && plan.secondary_send.empty()) {
      // Experiment disabled (or nothing selected): the original batched send with a per-packet
      // fallback, with no per-shard filtering or secondary dispatch.
      if (batch(begin, end)) {
        return static_cast<std::size_t>(end - begin);
      }
      on_fallback();
      for (std::uint32_t index = begin; index < end; ++index) {
        primary(index);
      }
      return static_cast<std::size_t>(end - begin);
    }

    const auto indices = primary_send_indices_in_range(begin, end, plan);
    const bool contiguous = indices.size() == static_cast<std::size_t>(end - begin);
    std::size_t primary_count = 0;
    if (contiguous && batch(begin, end)) {
      primary_count = indices.size();
    } else {
      if (contiguous) {
        on_fallback();
      }
      for (auto index : indices) {
        primary(index);
        ++primary_count;
      }
    }

    for (std::uint32_t index = begin; index < end; ++index) {
      if (plan.secondary(index)) {
        secondary(index);
      }
    }
    return primary_count;
  }
}  // namespace multipath_fec
