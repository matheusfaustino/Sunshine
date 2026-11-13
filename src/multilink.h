/**
 * @file src/multilink.h
 * @brief Sender-side state and helpers for duplicating video shards over a second network path.
 *
 * Deviation from the design plan (section 4.2): association is a plain datagram carrying the
 * session's secret ping payload, not a GCM-authenticated QUIC-style path challenge. The secondary
 * endpoint is only ever taken from a datagram that presented that secret.
 */
#pragma once

// standard includes
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

// lib includes
#include <boost/asio/ip/address_v4.hpp>

namespace multilink {
  enum class mode_e {
    disabled,  ///< Feature off; behaviour is unchanged.
    duplicate,  ///< Send every shard on both paths.
    parity,  ///< Send only parity shards on the secondary path.
  };

  /**
   * @brief Host configuration.
   */
  struct config_t {
    mode_e mode = mode_e::disabled;
    int secondary_max_kbps = 0;  ///< Secondary path cap; 0 is unlimited.
    int test_drop_every_n_blocks = 0;  ///< Test only: suppress P+1 shards on the primary every Nth FEC block.
    int test_outage_primary_start_s = 0;  ///< Test only: primary outage start, seconds after the first block.
    int test_outage_primary_duration_s = 0;  ///< Test only: primary outage length; 0 disables.
  };

  constexpr std::size_t ASSOC_SIZE = 22;  ///< 'M','L','M','P' | version=1 | 16-byte ping payload | path_id=1.
  constexpr std::int64_t ASSOC_TIMEOUT_MS = 2000;

  /**
   * @brief Extract the ping payload from an association datagram.
   * @return The 16-byte payload view, or nullopt if the datagram is not a version 1, path 1 association.
   */
  inline std::optional<std::string_view> parse_association(std::string_view datagram) {
    if (datagram.size() != ASSOC_SIZE || datagram.substr(0, 4) != "MLMP" || datagram[4] != 1 || datagram[21] != 1) {
      return std::nullopt;
    }
    return datagram.substr(5, 16);
  }

  /**
   * @brief Token bucket; a rate of 0 means unlimited. Not thread safe.
   */
  struct token_bucket_t {
    double rate = 0;  ///< Units per second.
    double burst = 0;  ///< Bucket capacity.
    double tokens = 0;  ///< Tokens currently available.
    std::chrono::steady_clock::time_point last {};  ///< Time of the last refill.

    bool take(double n, std::chrono::steady_clock::time_point now) {
      if (rate <= 0) {
        return true;
      }
      if (last == std::chrono::steady_clock::time_point {}) {
        tokens = burst;
      } else {
        tokens = std::min(burst, tokens + rate * std::chrono::duration<double>(now - last).count());
      }
      last = now;
      if (tokens < n) {
        return false;
      }
      tokens -= n;
      return true;
    }
  };

  /**
   * @brief Pack an IPv4 endpoint into one word so threads can share it lock-free; 0 means none.
   * @param address IPv4 address.
   * @param port UDP port.
   */
  inline std::uint64_t pack(const boost::asio::ip::address_v4 &address, std::uint16_t port) {
    return (static_cast<std::uint64_t>(address.to_uint()) << 16) | port;
  }

  /// Steady-clock milliseconds.
  inline std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
  }

  /**
   * @brief Per-session multilink state, shared by the receive thread and the video sender.
   */
  struct state_t {
    std::atomic<std::uint64_t> peer {0};  ///< Packed secondary endpoint.
    std::atomic<std::int64_t> last_seen_ms {0};  ///< Steady-clock time of the last valid association datagram.
    std::atomic<std::uint64_t> rej_primary_endpoint {0};  ///< Associations rejected: source equals the primary peer.
    std::atomic<std::uint64_t> rej_not_ipv4 {0};  ///< Associations rejected: source is not IPv4.
    std::atomic<std::uint64_t> rej_rate_limited {0};  ///< Associations rejected: too many datagrams.
    token_bucket_t assoc_limit {10, 20};  ///< Receive thread only.

    // Counters written by the video sender, read when logging.
    std::atomic<std::uint64_t> primary_shards {0};  ///< Shards sent on the primary path.
    std::atomic<std::uint64_t> secondary_shards {0};  ///< Shards sent on the secondary path.
    std::atomic<std::uint64_t> secondary_bytes {0};  ///< Wire bytes sent on the secondary path.
    std::atomic<std::uint64_t> cap_skips {0};  ///< Secondary shards skipped by the rate cap.
    std::atomic<std::uint64_t> send_errors {0};  ///< Failed secondary sends.

    // Video sender thread only.
    token_bucket_t cap;  ///< Secondary byte cap.
    bool active = false;  ///< Whether the sender currently treats the secondary as usable.
    std::uint64_t blocks = 0;  ///< FEC blocks sent, for the test drop knob.
    std::chrono::steady_clock::time_point started {};  ///< Time of the first FEC block.
    std::chrono::steady_clock::time_point last_log {};  ///< Time of the last periodic summary.
    int outage_phase = 0;  ///< 0 before, 1 during, 2 after the test outage.

    /**
     * @brief True when a secondary endpoint presented the secret recently enough to be used.
     * @param now Current steady-clock milliseconds.
     */
    bool fresh(std::int64_t now) const {
      return peer.load() != 0 && now - last_seen_ms.load() < ASSOC_TIMEOUT_MS;
    }

    /**
     * @brief Format one bounded log line containing counters only, never keys or payloads.
     * @param mode Active mode.
     * @param final_line Mark the session-end line.
     */
    std::string summary(mode_e mode, bool final_line) const {
      std::ostringstream ss;
      ss << "multilink: mode=" << (mode == mode_e::duplicate ? "duplicate" : "parity")
         << " associated=" << (fresh(now_ms()) ? 1 : 0)
         << " primary_shards=" << primary_shards << " secondary_shards=" << secondary_shards
         << " secondary_bytes=" << secondary_bytes << " cap_skips=" << cap_skips
         << " send_errors=" << send_errors
         << " rejected{primary_endpoint:" << rej_primary_endpoint << ",not_ipv4:" << rej_not_ipv4
         << ",rate_limited:" << rej_rate_limited << '}' << (final_line ? " final=1" : "");
      return ss.str();
    }
  };
}  // namespace multilink
