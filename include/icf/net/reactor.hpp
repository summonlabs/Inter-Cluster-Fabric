// Inter-Cluster Fabric - single-threaded event loop.
//
// The loop owns every socket, connection, and timer. Handlers run inside the loop thread with
// no lock held, and destruction is always deferred to the end of an iteration, so a handler may
// close its own connection, close another connection, or stop the loop without invalidating the
// iteration it runs inside.
//
// Ownership rules (audited in docs/CONCURRENCY.md):
//   * Connection objects are owned by EventLoop and addressed by a stable id. Handlers receive a
//     reference that stays valid for the duration of the call, but must not be stored.
//   * Closing marks a connection; the loop erases it after the current dispatch.
//   * Timers fire from a snapshot taken before any callback runs, so scheduling or cancelling
//     timers inside a callback cannot invalidate the iteration.
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "icf/core/time.hpp"
#include "icf/net/socket.hpp"
#include "icf/net/platform.hpp"
#include "icf/wire/frame.hpp"

namespace icf::net {

class EventLoop;

class Connection {
 public:
  struct Config {
    std::uint32_t max_payload = limits::kMaxFramePayload;
    std::uint64_t max_queued_bytes = limits::kMaxSendQueueBytes;
    std::size_t max_pending_frames = limits::kMaxPendingSends;
    Duration idle_deadline = Duration::from_millis(limits::kDefaultReadDeadlineMillis);
    // Key used to verify every inbound frame. When empty, inbound frames must be unsigned.
    std::vector<std::byte> verify_key;
    // Whether outbound frames carry a MAC. A peer enables this once the handshake is answered.
    bool sign_outbound = false;
  };

  using FrameHandler = std::function<Status(Connection&, const wire::Frame&)>;
  using CloseHandler = std::function<void(Connection&, const Status&)>;

  Connection(std::uint64_t id, Socket socket, Config config, FrameHandler on_frame, CloseHandler on_close);
  ~Connection();
  Connection(const Connection&) = delete;
  Connection& operator=(const Connection&) = delete;

  [[nodiscard]] std::uint64_t id() const noexcept { return id_; }
  [[nodiscard]] bool closed() const noexcept { return closed_; }
  [[nodiscard]] bool has_output() const noexcept { return queued_bytes_ > 0; }
  [[nodiscard]] std::uint64_t queued_bytes() const noexcept { return queued_bytes_; }
  [[nodiscard]] std::size_t queued_frames() const noexcept { return queue_.size(); }
  [[nodiscard]] const std::string& peer() const noexcept { return peer_; }
  [[nodiscard]] Timestamp last_activity() const noexcept { return last_activity_; }
  [[nodiscard]] const std::string& label() const noexcept { return label_; }
  void set_label(std::string label) { label_ = std::move(label); }
  [[nodiscard]] bool signed_frames() const noexcept { return config_.sign_outbound; }

  [[nodiscard]] Status queue(wire::MessageType type, std::span<const std::byte> payload);
  [[nodiscard]] Status queue_frame(wire::MessageType type, std::span<const std::byte> payload, bool sign);
  // Installs the channel key after the handshake established which domain (and therefore which
  // key) the peer belongs to. From this point every inbound frame must carry a valid MAC, and
  // every outbound frame is signed.
  void enable_signing(std::vector<std::byte> key) {
    config_.verify_key = std::move(key);
    config_.sign_outbound = !config_.verify_key.empty();
  }
  // Starts signing outbound frames after the handshake was answered (the peer side of a channel
  // that already knows which key to verify with).
  void enable_outbound_signing() noexcept { config_.sign_outbound = !config_.verify_key.empty(); }
  [[nodiscard]] bool signing_enabled() const noexcept { return config_.sign_outbound; }
  [[nodiscard]] bool verification_enabled() const noexcept { return !config_.verify_key.empty(); }
  // Marks the connection closed and reports the reason once. The socket is shut down immediately
  // so the peer observes the close, but the object survives until the loop sweeps it.
  void close(const Status& reason);
  void close_now(const Status& reason) { close(reason); }

  [[nodiscard]] Status flush();
  [[nodiscard]] Status fill();
  [[nodiscard]] const Status& close_reason() const noexcept { return close_reason_; }

 private:
  friend class EventLoop;
  [[nodiscard]] Status dispatch();

  std::uint64_t id_ = 0;
  Socket socket_;
  Config config_;
  FrameHandler on_frame_;
  CloseHandler on_close_;
  wire::FrameParser parser_;
  std::deque<std::vector<std::byte>> queue_;
  std::size_t queue_offset_ = 0;
  std::uint64_t queued_bytes_ = 0;
  std::string peer_;
  std::string label_;
  Timestamp last_activity_{};
  Status close_reason_;
  bool closed_ = false;
  bool close_reported_ = false;
};

class EventLoop {
 public:
  // Receives an accepted socket. The handler adopts it (EventLoop::adopt) or lets it fall out of
  // scope, in which case the socket is closed. Returning a negative status is logged, not fatal.
  using ListenerHandler = std::function<Status(Socket)>;
  using TimerCallback = std::function<void()>;

  explicit EventLoop(const Clock& clock);
  ~EventLoop();
  EventLoop(const EventLoop&) = delete;
  EventLoop& operator=(const EventLoop&) = delete;

  [[nodiscard]] Status add_listener(TcpListener listener, ListenerHandler on_ready);
  [[nodiscard]] Result<std::uint64_t> adopt(Socket socket, Connection::Config config,
                                            Connection::FrameHandler on_frame, Connection::CloseHandler on_close);
  [[nodiscard]] Connection* find(std::uint64_t id);
  [[nodiscard]] std::size_t connection_count() const noexcept { return connections_.size(); }
  [[nodiscard]] std::size_t max_connections() const noexcept { return max_connections_; }
  void set_max_connections(std::size_t limit) noexcept { max_connections_ = limit; }

  [[nodiscard]] std::uint64_t schedule(Timestamp deadline, TimerCallback callback);
  void cancel(std::uint64_t timer_id);

  [[nodiscard]] Status run();
  void stop() noexcept { running_ = false; }
  [[nodiscard]] bool running() const noexcept { return running_; }

  [[nodiscard]] const Clock& clock() const noexcept { return *clock_; }
  [[nodiscard]] Timestamp now() const noexcept { return clock_->now(); }

  // Number of loop iterations performed; used by tests to assert bounded behaviour.
  [[nodiscard]] std::uint64_t iterations() const noexcept { return iterations_; }

 private:
  [[nodiscard]] Status pump(int timeout_millis);
  int compute_timeout() const;
  void fire_due_timers();
  void sweep_connections();

  const Clock* clock_;
  std::vector<std::pair<TcpListener, ListenerHandler>> listeners_;
  std::map<std::uint64_t, std::unique_ptr<Connection>> connections_;
  std::vector<std::uint64_t> pending_erase_;
  std::map<std::pair<std::int64_t, std::uint64_t>, TimerCallback> timers_;
  std::uint64_t next_connection_id_ = 1;
  std::uint64_t next_timer_id_ = 1;
  std::size_t max_connections_ = limits::kMaxConnections;
  bool running_ = false;
  std::uint64_t iterations_ = 0;
};

}  // namespace icf::net
