#include "icf/net/reactor.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include "icf/core/limits.hpp"
#include "icf/core/log.hpp"
#include "icf/net/poller.hpp"

namespace icf::net {
namespace {

constexpr std::size_t kMaxFramesPerIteration = 64;
constexpr std::size_t kReadChunk = 16 * 1024;

}  // namespace

Connection::Connection(std::uint64_t id, Socket socket, Config config, FrameHandler on_frame, CloseHandler on_close)
    : id_(id),
      socket_(std::move(socket)),
      config_(std::move(config)),
      on_frame_(std::move(on_frame)),
      on_close_(std::move(on_close)),
      parser_(config_.max_payload) {
  peer_ = socket_.peer_endpoint();
}

Connection::~Connection() {
  if (!closed_) {
    close_reason_ = Status::make(Outcome::Cancelled, "connection destroyed");
    closed_ = true;
  }
}

Status Connection::queue(wire::MessageType type, std::span<const std::byte> payload) {
  return queue_frame(type, payload, config_.sign_outbound);
}

Status Connection::queue_frame(wire::MessageType type, std::span<const std::byte> payload, bool sign) {
  if (closed_) {
    return Status::make(Outcome::Cancelled, "connection is closed");
  }
  if (payload.size() > config_.max_payload) {
    return Status::make(Outcome::CapacityExceeded, "outbound frame exceeds the negotiated payload limit");
  }
  if (queue_.size() >= config_.max_pending_frames) {
    return Status::make(Outcome::Busy, "outbound frame queue is full");
  }
  if (sign && config_.verify_key.empty()) {
    return Status::make(Outcome::Unauthorized, "cannot sign a frame without a channel key");
  }

  const bool signed_frame = sign;
  std::vector<std::byte> encoded;
  encoded.reserve(wire::frame_wire_size(static_cast<std::uint32_t>(payload.size()), signed_frame));
  wire::FrameHeader header;
  header.version = limits::kProtocolVersionMax;
  header.type = type;
  header.flags = signed_frame ? wire::kFlagSigned : 0u;
  const auto key = signed_frame ? std::span<const std::byte>(config_.verify_key) : std::span<const std::byte>();
  const Status appended = wire::append_frame(encoded, header, payload, key);
  if (!appended) {
    return appended;
  }
  if (queued_bytes_ + encoded.size() > config_.max_queued_bytes) {
    return Status::make(Outcome::Busy, "outbound byte queue is full");
  }
  queued_bytes_ += encoded.size();
  queue_.push_back(std::move(encoded));
  return Status::ok();
}

void Connection::close(const Status& reason) {
  if (closed_) {
    return;
  }
  closed_ = true;
  close_reason_ = reason;
  socket_.close();
  queue_.clear();
  queue_offset_ = 0;
  queued_bytes_ = 0;
}

Status Connection::flush() {
  while (!queue_.empty()) {
    const std::vector<std::byte>& front = queue_.front();
    const std::size_t remaining = front.size() - queue_offset_;
    Result<std::size_t> written =
        socket_.send(std::span<const std::byte>(front.data() + queue_offset_, remaining));
    if (!written) {
      if (written.status().outcome() == Outcome::Busy) {
        return Status::ok();  // the loop will retry when the socket becomes writable
      }
      return written.status();
    }
    if (written.value() == 0) {
      return Status::ok();
    }
    queue_offset_ += written.value();
    queued_bytes_ -= written.value();
    if (queue_offset_ == front.size()) {
      queue_.pop_front();
      queue_offset_ = 0;
    }
  }
  return Status::ok();
}

Status Connection::fill() {
  std::array<std::byte, kReadChunk> buffer{};
  for (;;) {
    Result<std::size_t> received = socket_.receive(buffer);
    if (!received) {
      if (received.status().outcome() == Outcome::Busy) {
        return Status::ok();
      }
      return received.status();
    }
    if (received.value() == 0) {
      return Status::make(Outcome::Unreachable, "peer closed the connection");
    }
    const Status pushed = parser_.push(std::span<const std::byte>(buffer.data(), received.value()));
    if (!pushed) {
      return pushed;
    }
    if (received.value() < buffer.size()) {
      return Status::ok();
    }
  }
}

Status Connection::dispatch() {
  for (std::size_t processed = 0; processed < kMaxFramesPerIteration; ++processed) {
    // The verification key is read per frame: a handshake handler may install one for everything
    // that follows the HELLO it is processing.
    const auto key =
        config_.verify_key.empty() ? std::span<const std::byte>() : std::span<const std::byte>(config_.verify_key);
    Result<std::optional<wire::Frame>> frame = parser_.next(key);
    if (!frame) {
      return frame.status();
    }
    if (!frame.value().has_value()) {
      return Status::ok();
    }
    if (!on_frame_) {
      return Status::make(Outcome::Internal, "connection has no frame handler");
    }
    const Status handled = on_frame_(*this, frame.value().value());
    if (!handled) {
      return handled;
    }
    if (closed_) {
      return Status::ok();
    }
  }
  return Status::ok();
}

EventLoop::EventLoop(const Clock& clock) : clock_(&clock) {}

EventLoop::~EventLoop() = default;

Status EventLoop::add_listener(TcpListener listener, ListenerHandler on_ready) {
  if (!listener.valid()) {
    return Status::make(Outcome::Invalid, "listener is not bound");
  }
  if (listeners_.size() >= 4) {
    return Status::make(Outcome::CapacityExceeded, "too many listeners registered");
  }
  listeners_.emplace_back(std::move(listener), std::move(on_ready));
  return Status::ok();
}

Result<std::uint64_t> EventLoop::adopt(Socket socket, Connection::Config config, Connection::FrameHandler on_frame,
                                       Connection::CloseHandler on_close) {
  if (!socket.valid()) {
    return Status::make(Outcome::Invalid, "cannot adopt an invalid socket");
  }
  if (connections_.size() >= max_connections_) {
    return Status::make(Outcome::CapacityExceeded, "connection limit reached");
  }
  const std::uint64_t id = next_connection_id_++;
  auto connection = std::make_unique<Connection>(id, std::move(socket), std::move(config), std::move(on_frame),
                                                 std::move(on_close));
  connection->last_activity_ = clock_->now();
  connections_.emplace(id, std::move(connection));
  return id;
}

Connection* EventLoop::find(std::uint64_t id) {
  const auto it = connections_.find(id);
  return it == connections_.end() ? nullptr : it->second.get();
}

std::uint64_t EventLoop::schedule(Timestamp deadline, TimerCallback callback) {
  const std::uint64_t id = next_timer_id_++;
  timers_.emplace(std::make_pair(deadline.unix_nanos(), id), std::move(callback));
  return id;
}

void EventLoop::cancel(std::uint64_t timer_id) {
  for (auto it = timers_.begin(); it != timers_.end();) {
    if (it->first.second == timer_id) {
      it = timers_.erase(it);
    } else {
      ++it;
    }
  }
}

int EventLoop::compute_timeout() const {
  const Timestamp now = clock_->now();
  // With live connections the loop must wake periodically so idle deadlines are enforced even
  // when no timer is registered.
  std::int64_t best = connections_.empty() ? -1 : 1000000000;
  for (const auto& entry : timers_) {
    const std::int64_t delta = entry.first.first - now.unix_nanos();
    if (delta <= 0) {
      return 0;
    }
    if (best < 0 || delta < best) {
      best = delta;
    }
  }
  if (best < 0) {
    return -1;
  }
  std::int64_t millis = best / 1000000;
  if (millis == 0) {
    millis = 1;
  }
  if (millis > 1000) {
    millis = 1000;  // wake at least once a second so clock changes are observed
  }
  return static_cast<int>(millis);
}

void EventLoop::fire_due_timers() {
  const Timestamp now = clock_->now();
  std::vector<TimerCallback> due;
  for (auto it = timers_.begin(); it != timers_.end();) {
    if (it->first.first <= now.unix_nanos()) {
      due.push_back(it->second);
      it = timers_.erase(it);
    } else {
      break;
    }
  }
  for (TimerCallback& callback : due) {
    callback();
  }
}

void EventLoop::sweep_connections() {
  // Every connection that has been closed since the last sweep is reported exactly once and then
  // erased. Reporting before erasing is what makes a handler's "peer went away" path run at all:
  // a connection that is erased silently leaves its owner waiting forever.
  const auto report_and_erase = [this]() {
    for (const std::uint64_t id : pending_erase_) {
      const auto it = connections_.find(id);
      if (it == connections_.end()) {
        continue;
      }
      Connection& connection = *it->second;
      if (!connection.closed_ || connection.close_reported_) {
        continue;
      }
      connection.close_reported_ = true;
      if (connection.on_close_) {
        connection.on_close_(connection, connection.close_reason_);
      }
    }
    for (const std::uint64_t id : pending_erase_) {
      connections_.erase(id);
    }
    pending_erase_.clear();
  };

  report_and_erase();

  const Timestamp now = clock_->now();
  for (auto& entry : connections_) {
    Connection& connection = *entry.second;
    if (connection.closed_) {
      pending_erase_.push_back(entry.first);
      continue;
    }
    if (connection.config_.idle_deadline.nanos() > 0 && !connection.last_activity_.is_zero()) {
      const Duration idle = now.since(connection.last_activity_);
      if (idle.nanos() > connection.config_.idle_deadline.nanos()) {
        connection.close(Status::make(Outcome::Unreachable, "connection idle deadline expired"));
        pending_erase_.push_back(entry.first);
      }
    }
  }
  report_and_erase();
}

Status EventLoop::pump(int timeout_millis) {
  std::vector<PollItem> items;
  items.reserve(connections_.size() + listeners_.size());
  std::vector<std::pair<std::uint64_t, std::size_t>> connection_index;
  connection_index.reserve(connections_.size());
  std::vector<std::size_t> listener_index;
  listener_index.reserve(listeners_.size());

  for (auto& entry : listeners_) {
    if (!entry.first.valid()) {
      continue;
    }
    PollItem item;
    item.handle = entry.first.handle();
    item.want_read = true;
    listener_index.push_back(items.size());
    items.push_back(item);
  }
  for (auto& entry : connections_) {
    Connection& connection = *entry.second;
    if (connection.closed_) {
      pending_erase_.push_back(entry.first);
      continue;
    }
    PollItem item;
    item.handle = connection.socket_.handle();
    item.want_read = true;
    item.want_write = connection.has_output();
    connection_index.emplace_back(entry.first, items.size());
    items.push_back(item);
  }

  Result<std::size_t> ready_count = poll_sockets(items, timeout_millis);
  if (!ready_count) {
    return ready_count.status();
  }
  if (Logger::instance().enabled(LogLevel::Trace)) {
    std::string detail;
    for (const auto& index_entry : connection_index) {
      const PollItem& polled = items[index_entry.second];
      detail += " [id=" + std::to_string(index_entry.first) + " read=" + (polled.readable ? "1" : "0") +
                " write=" + (polled.writable ? "1" : "0") + " failed=" + (polled.failed ? "1" : "0") + "]";
    }
    ICF_LOG_TRACE("reactor", "poll returned " + std::to_string(ready_count.value()) + " ready" + detail);
  }
  if (ready_count.value() == 0) {
    return Status::ok();
  }

  for (const std::size_t index : listener_index) {
    if (!items[index].readable && !items[index].failed) {
      continue;
    }
    for (auto& entry : listeners_) {
      if (entry.first.handle() != items[index].handle) {
        continue;
      }
      std::size_t accepted = 0;
      while (accepted < limits::kMaxAcceptBurst) {
        Result<Socket> socket = entry.first.accept();
        if (!socket) {
          if (socket.status().outcome() != Outcome::Busy) {
            ICF_LOG_WARN("net", "accept failed");
          }
          break;
        }
        ++accepted;
        if (entry.second) {
          const Status handled = entry.second(std::move(socket.value()));
          if (!handled) {
            const std::initializer_list<std::pair<std::string_view, std::string_view>> fields{
                {"outcome", ::icf::to_string(handled.outcome())}};
            ICF_LOG_WARN_KF("net", "accepted connection was refused", fields);
          }
        }
        // An unhandled socket is closed when it goes out of scope.
      }
    }
  }

  for (const auto& index_entry : connection_index) {
    Connection* connection = find(index_entry.first);
    if (connection == nullptr) {
      continue;
    }
    const PollItem& item = items[index_entry.second];
    // Readable data is always processed before an error condition is honoured: a peer may send a
    // final frame and close in the same instant, and that frame is still authoritative. Treating
    // the error first would silently discard it.
    if (item.readable) {
      const Status filled = connection->fill();
      connection->last_activity_ = clock_->now();
      // Parse whatever did arrive, even when the read ended in an error, so a message that
      // arrived together with the close is handled (and a protocol violation is classified as
      // such) before the connection is torn down.
      const Status dispatched = connection->dispatch();
      if (!dispatched) {
        connection->close(dispatched);
        pending_erase_.push_back(connection->id());
        continue;
      }
      if (!filled) {
        connection->close(filled);
        pending_erase_.push_back(connection->id());
        continue;
      }
    }
    if (item.failed) {
      connection->close(Status::make(Outcome::Unreachable, "socket reported an error condition"));
      pending_erase_.push_back(connection->id());
      continue;
    }
    Connection* still_there = find(index_entry.first);
    if (still_there == nullptr) {
      continue;
    }
    if (still_there->has_output() && (item.writable || item.readable)) {
      const Status flushed = still_there->flush();
      if (!flushed) {
        still_there->close(flushed);
        pending_erase_.push_back(still_there->id());
        continue;
      }
    }
    if (still_there->has_output() && !items[index_entry.second].writable) {
      // Flush opportunistically after a read too: small replies often fit immediately.
      const Status flushed = still_there->flush();
      if (!flushed) {
        still_there->close(flushed);
        pending_erase_.push_back(still_there->id());
      }
    }
  }
  return Status::ok();
}

Status EventLoop::run() {
  running_ = true;
  while (running_) {
    ++iterations_;
    fire_due_timers();
    if (!running_) {
      break;
    }
    sweep_connections();
    const int timeout = compute_timeout();
    const Status pumped = pump(timeout);
    if (!pumped) {
      running_ = false;
      return pumped;
    }
  }
  return Status::ok();
}

}  // namespace icf::net
