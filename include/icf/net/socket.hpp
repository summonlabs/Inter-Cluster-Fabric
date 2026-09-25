// Inter-Cluster Fabric - TCP sockets.
//
// Sockets are non-blocking once connected; the event loop owns readiness. Connecting honours a
// deadline derived from the injected clock, and every operation returns a typed status rather
// than throwing.
#pragma once

#include <cstdint>
#include <span>
#include <string>

#include "icf/core/status.hpp"
#include "icf/core/time.hpp"
#include "icf/net/platform.hpp"

namespace icf::net {

class Socket {
 public:
  Socket() = default;
  explicit Socket(SocketHandle handle) noexcept : handle_(handle) {}
  ~Socket();

  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidSocket; }
  [[nodiscard]] SocketHandle handle() const noexcept { return handle_; }
  void close() noexcept;

  // Returns the number of bytes transferred; a partial transfer is not an error.
  [[nodiscard]] Result<std::size_t> send(std::span<const std::byte> data);
  [[nodiscard]] Result<std::size_t> receive(std::span<std::byte> buffer);

  [[nodiscard]] Status set_nonblocking(bool enabled);
  [[nodiscard]] Status set_no_delay(bool enabled);
  [[nodiscard]] Status set_keep_alive(bool enabled);
  [[nodiscard]] Status set_reuse_address(bool enabled);

  [[nodiscard]] std::uint16_t local_port() const;
  [[nodiscard]] std::string peer_endpoint() const;

  // Connects to host:port. The deadline is measured on the supplied clock; a ManualClock
  // deadline only expires when the test advances it, which keeps tests deterministic.
  [[nodiscard]] static Result<Socket> connect(const std::string& host, std::uint16_t port, Duration deadline,
                                              const Clock& clock);
  [[nodiscard]] static Result<Socket> connect_loopback(std::uint16_t port, Duration deadline, const Clock& clock);

  // Wraps an accepted handle.
  [[nodiscard]] static Socket adopt(SocketHandle handle) noexcept { return Socket(handle); }

 private:
  SocketHandle handle_ = kInvalidSocket;
};

class TcpListener {
 public:
  TcpListener() = default;
  ~TcpListener();

  TcpListener(TcpListener&& other) noexcept;
  TcpListener& operator=(TcpListener&& other) noexcept;
  TcpListener(const TcpListener&) = delete;
  TcpListener& operator=(const TcpListener&) = delete;

  // Binds to address:port. Port 0 asks the operating system for an ephemeral port, which is
  // reported back through bound_port.
  [[nodiscard]] static Result<TcpListener> bind(const std::string& address, std::uint16_t port, int backlog,
                                                std::uint16_t& bound_port);
  [[nodiscard]] Result<Socket> accept();
  [[nodiscard]] Status set_nonblocking(bool enabled);

  [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidSocket; }
  [[nodiscard]] SocketHandle handle() const noexcept { return handle_; }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  void close() noexcept;

 private:
  SocketHandle handle_ = kInvalidSocket;
  std::uint16_t port_ = 0;
};

}  // namespace icf::net
