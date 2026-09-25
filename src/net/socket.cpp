#include "icf/net/socket.hpp"

#include <cstring>
#include <string>
#include <vector>

#include "icf/core/limits.hpp"
#include "icf/net/poller.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace icf::net {
namespace {

#if defined(_WIN32)
SOCKET to_native(SocketHandle handle) noexcept { return static_cast<SOCKET>(handle); }
#else
int to_native(SocketHandle handle) noexcept { return static_cast<int>(handle); }
#endif

void close_handle(SocketHandle handle) noexcept {
  if (handle == kInvalidSocket) {
    return;
  }
#if defined(_WIN32)
  ::closesocket(static_cast<SOCKET>(handle));
#else
  ::close(static_cast<int>(handle));
#endif
}

Status make_error(SocketError error, const char* what) {
  return Status::make(outcome_for(error), std::string(what) + " failed: " + std::string(to_string(error)));
}

// Bounded wait for a single handle. Returns BUSY when the deadline expires.
Status wait_for(SocketHandle handle, bool want_write, Duration deadline, const Clock& clock) {
  const std::int64_t start = clock.monotonic_nanos();
  for (;;) {
    const std::int64_t elapsed = clock.monotonic_nanos() - start;
    const std::int64_t remaining = deadline.nanos() - elapsed;
    if (remaining <= 0) {
      return Status::make(Outcome::Unreachable, "connect deadline expired");
    }
    int slice = static_cast<int>(remaining / 1000000);
    if (slice <= 0) {
      slice = 1;
    }
    if (slice > 250) {
      slice = 250;  // bounded slices keep the wait responsive to clock changes
    }
    PollItem item;
    item.handle = handle;
    item.want_write = want_write;
    item.want_read = !want_write;
    Result<std::size_t> ready = poll_sockets(std::span<PollItem>(&item, 1), slice);
    if (!ready) {
      return ready.status();
    }
    if (item.failed) {
      const SocketError error = last_socket_error();
      return Status::make(outcome_for(error), std::string("socket failed while waiting: ") + to_string(error));
    }
    if (ready.value() > 0) {
      return Status::ok();
    }
  }
}

Result<SocketHandle> create_socket(int family) {
  const SocketHandle handle = static_cast<SocketHandle>(::socket(family, SOCK_STREAM, IPPROTO_TCP));
  if (handle == kInvalidSocket) {
    return make_error(last_socket_error(), "socket");
  }
  return handle;
}

}  // namespace

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) { other.handle_ = kInvalidSocket; }

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = kInvalidSocket;
  }
  return *this;
}

void Socket::close() noexcept {
  close_handle(handle_);
  handle_ = kInvalidSocket;
}

Result<std::size_t> Socket::send(std::span<const std::byte> data) {
  if (!valid()) {
    return Status::make(Outcome::Invalid, "send on a closed socket");
  }
  if (data.empty()) {
    return static_cast<std::size_t>(0);
  }
#if defined(_WIN32)
  const int written = ::send(static_cast<SOCKET>(handle_), reinterpret_cast<const char*>(data.data()),
                             static_cast<int>(data.size()), 0);
#else
  const ssize_t written = ::send(static_cast<int>(handle_), data.data(), data.size(), MSG_NOSIGNAL);
#endif
  if (written < 0) {
    const SocketError error = last_socket_error();
    return Status::make(outcome_for(error), std::string("send failed: ") + to_string(error));
  }
  return static_cast<std::size_t>(written);
}

Result<std::size_t> Socket::receive(std::span<std::byte> buffer) {
  if (!valid()) {
    return Status::make(Outcome::Invalid, "receive on a closed socket");
  }
  if (buffer.empty()) {
    return static_cast<std::size_t>(0);
  }
#if defined(_WIN32)
  const int received = ::recv(static_cast<SOCKET>(handle_), reinterpret_cast<char*>(buffer.data()),
                              static_cast<int>(buffer.size()), 0);
#else
  const ssize_t received = ::recv(static_cast<int>(handle_), buffer.data(), buffer.size(), 0);
#endif
  if (received < 0) {
    const SocketError error = last_socket_error();
    return Status::make(outcome_for(error), std::string("receive failed: ") + to_string(error));
  }
  return static_cast<std::size_t>(received);
}

Status Socket::set_nonblocking(bool enabled) {
  if (!valid()) {
    return Status::make(Outcome::Invalid, "socket is closed");
  }
#if defined(_WIN32)
  u_long mode = enabled ? 1ul : 0ul;
  if (::ioctlsocket(static_cast<SOCKET>(handle_), FIONBIO, &mode) != 0) {
    return make_error(last_socket_error(), "ioctlsocket");
  }
  return Status::ok();
#else
  const int flags = ::fcntl(static_cast<int>(handle_), F_GETFL, 0);
  if (flags < 0) {
    return make_error(last_socket_error(), "fcntl(F_GETFL)");
  }
  const int updated = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
  if (::fcntl(static_cast<int>(handle_), F_SETFL, updated) < 0) {
    return make_error(last_socket_error(), "fcntl(F_SETFL)");
  }
  return Status::ok();
#endif
}

Status Socket::set_no_delay(bool enabled) {
  if (!valid()) {
    return Status::make(Outcome::Invalid, "socket is closed");
  }
  const int value = enabled ? 1 : 0;
#if defined(_WIN32)
  if (::setsockopt(static_cast<SOCKET>(handle_), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&value),
                   sizeof(value)) != 0) {
    return make_error(last_socket_error(), "setsockopt(TCP_NODELAY)");
  }
#else
  if (::setsockopt(static_cast<int>(handle_), IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) != 0) {
    return make_error(last_socket_error(), "setsockopt(TCP_NODELAY)");
  }
#endif
  return Status::ok();
}

Status Socket::set_keep_alive(bool enabled) {
  if (!valid()) {
    return Status::make(Outcome::Invalid, "socket is closed");
  }
  const int value = enabled ? 1 : 0;
#if defined(_WIN32)
  if (::setsockopt(static_cast<SOCKET>(handle_), SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&value),
                   sizeof(value)) != 0) {
    return make_error(last_socket_error(), "setsockopt(SO_KEEPALIVE)");
  }
#else
  if (::setsockopt(static_cast<int>(handle_), SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(value)) != 0) {
    return make_error(last_socket_error(), "setsockopt(SO_KEEPALIVE)");
  }
#endif
  return Status::ok();
}

Status Socket::set_reuse_address(bool enabled) {
  if (!valid()) {
    return Status::make(Outcome::Invalid, "socket is closed");
  }
  const int value = enabled ? 1 : 0;
#if defined(_WIN32)
  if (::setsockopt(static_cast<SOCKET>(handle_), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&value),
                   sizeof(value)) != 0) {
    return make_error(last_socket_error(), "setsockopt(SO_REUSEADDR)");
  }
#else
  if (::setsockopt(static_cast<int>(handle_), SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) != 0) {
    return make_error(last_socket_error(), "setsockopt(SO_REUSEADDR)");
  }
#endif
  return Status::ok();
}

std::uint16_t Socket::local_port() const {
  sockaddr_storage storage{};
#if defined(_WIN32)
  int length = sizeof(storage);
#else
  socklen_t length = sizeof(storage);
#endif
  if (::getsockname(to_native(handle_), reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
    return 0;
  }
  if (storage.ss_family == AF_INET) {
    return ntohs(reinterpret_cast<sockaddr_in*>(&storage)->sin_port);
  }
  if (storage.ss_family == AF_INET6) {
    return ntohs(reinterpret_cast<sockaddr_in6*>(&storage)->sin6_port);
  }
  return 0;
}

std::string Socket::peer_endpoint() const {
  sockaddr_storage storage{};
#if defined(_WIN32)
  int length = sizeof(storage);
#else
  socklen_t length = sizeof(storage);
#endif
  if (::getpeername(to_native(handle_), reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
    return std::string();
  }
  char host[NI_MAXHOST] = {};
  char service[NI_MAXSERV] = {};
  if (::getnameinfo(reinterpret_cast<sockaddr*>(&storage), length, host, sizeof(host), service, sizeof(service),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
    return std::string();
  }
  return std::string(host) + ":" + service;
}

Result<Socket> Socket::connect(const std::string& host, std::uint16_t port, Duration deadline, const Clock& clock) {
  NetworkScope scope;
  if (!scope.valid()) {
    return Status::make(Outcome::Unsupported, "the socket subsystem could not be initialised");
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  if (::getaddrinfo(host.c_str(), service.c_str(), &hints, &results) != 0 || results == nullptr) {
    return Status::make(Outcome::Unreachable, "cannot resolve the coordinator address");
  }
  Status last_error = Status::make(Outcome::Unreachable, "no address attempted");
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    Result<SocketHandle> handle = create_socket(candidate->ai_family);
    if (!handle) {
      last_error = handle.status();
      continue;
    }
    Socket socket(handle.value());
    const Status nonblocking = socket.set_nonblocking(true);
    if (!nonblocking) {
      last_error = nonblocking;
      continue;
    }
    const int result = ::connect(to_native(socket.handle()), candidate->ai_addr,
                                 static_cast<int>(candidate->ai_addrlen));
    if (result == 0) {
      ::freeaddrinfo(results);
      return socket;
    }
    const SocketError error = last_socket_error();
    if (error != SocketError::WouldBlock && error != SocketError::InProgress && error != SocketError::Interrupted) {
      last_error = Status::make(outcome_for(error), std::string("connect failed: ") + to_string(error));
      continue;
    }
    const Status ready = wait_for(socket.handle(), true, deadline, clock);
    if (!ready) {
      last_error = ready;
      continue;
    }
    int so_error = 0;
#if defined(_WIN32)
    int length = sizeof(so_error);
    if (::getsockopt(static_cast<SOCKET>(socket.handle()), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error),
                     &length) != 0) {
#else
    socklen_t length = sizeof(so_error);
    if (::getsockopt(static_cast<int>(socket.handle()), SOL_SOCKET, SO_ERROR, &so_error, &length) != 0) {
#endif
      last_error = make_error(last_socket_error(), "getsockopt(SO_ERROR)");
      continue;
    }
    if (so_error != 0) {
      const SocketError pending = translate_socket_error(so_error);
      last_error = Status::make(outcome_for(pending), std::string("connect failed: ") + to_string(pending));
      continue;
    }
    ::freeaddrinfo(results);
    return socket;
  }
  ::freeaddrinfo(results);
  return last_error;
}

Result<Socket> Socket::connect_loopback(std::uint16_t port, Duration deadline, const Clock& clock) {
  return Socket::connect("127.0.0.1", port, deadline, clock);
}

TcpListener::~TcpListener() { close(); }

TcpListener::TcpListener(TcpListener&& other) noexcept : handle_(other.handle_), port_(other.port_) {
  other.handle_ = kInvalidSocket;
  other.port_ = 0;
}

TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    port_ = other.port_;
    other.handle_ = kInvalidSocket;
    other.port_ = 0;
  }
  return *this;
}

void TcpListener::close() noexcept {
  close_handle(handle_);
  handle_ = kInvalidSocket;
  port_ = 0;
}

Result<TcpListener> TcpListener::bind(const std::string& address, std::uint16_t port, int backlog,
                                      std::uint16_t& bound_port) {
  NetworkScope scope;
  if (!scope.valid()) {
    return Status::make(Outcome::Unsupported, "the socket subsystem could not be initialised");
  }
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  const char* node = address.empty() ? nullptr : address.c_str();
  if (::getaddrinfo(node, service.c_str(), &hints, &results) != 0 || results == nullptr) {
    return Status::make(Outcome::Invalid, "cannot resolve the listen address");
  }
  Status last_error = Status::make(Outcome::Invalid, "no address attempted");
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    Result<SocketHandle> handle = create_socket(candidate->ai_family);
    if (!handle) {
      last_error = handle.status();
      continue;
    }
    TcpListener listener;
    listener.handle_ = handle.value();
    const Status reuse = [&listener]() {
      const int value = 1;
#if defined(_WIN32)
      return ::setsockopt(static_cast<SOCKET>(listener.handle()), SOL_SOCKET, SO_REUSEADDR,
                          reinterpret_cast<const char*>(&value), sizeof(value)) == 0
                 ? Status::ok()
                 : make_error(last_socket_error(), "setsockopt(SO_REUSEADDR)");
#else
      return ::setsockopt(static_cast<int>(listener.handle()), SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) == 0
                 ? Status::ok()
                 : make_error(last_socket_error(), "setsockopt(SO_REUSEADDR)");
#endif
    }();
    if (!reuse) {
      last_error = reuse;
      continue;
    }
    if (::bind(to_native(listener.handle()), candidate->ai_addr,
               static_cast<int>(candidate->ai_addrlen)) != 0) {
      last_error = make_error(last_socket_error(), "bind");
      continue;
    }
    if (::listen(to_native(listener.handle()), backlog) != 0) {
      last_error = make_error(last_socket_error(), "listen");
      continue;
    }
    sockaddr_storage storage{};
#if defined(_WIN32)
    int length = sizeof(storage);
#else
    socklen_t length = sizeof(storage);
#endif
    if (::getsockname(to_native(listener.handle()), reinterpret_cast<sockaddr*>(&storage),
                      &length) == 0) {
      listener.port_ = ntohs(reinterpret_cast<sockaddr_in*>(&storage)->sin_port);
    }
    const Status nonblocking = listener.set_nonblocking(true);
    if (!nonblocking) {
      last_error = nonblocking;
      continue;
    }
    bound_port = listener.port_;
    ::freeaddrinfo(results);
    return listener;
  }
  ::freeaddrinfo(results);
  return last_error;
}

Result<Socket> TcpListener::accept() {
  if (!valid()) {
    return Status::make(Outcome::Invalid, "listener is closed");
  }
  sockaddr_storage storage{};
#if defined(_WIN32)
  int length = sizeof(storage);
#else
  socklen_t length = sizeof(storage);
#endif
  const SocketHandle handle = static_cast<SocketHandle>(
      ::accept(to_native(handle_), reinterpret_cast<sockaddr*>(&storage), &length));
  if (handle == kInvalidSocket) {
    const SocketError error = last_socket_error();
    return Status::make(outcome_for(error), std::string("accept failed: ") + to_string(error));
  }
  Socket socket(handle);
  (void)socket.set_nonblocking(true);
  (void)socket.set_no_delay(true);
  return socket;
}

Status TcpListener::set_nonblocking(bool enabled) {
  if (!valid()) {
    return Status::make(Outcome::Invalid, "listener is closed");
  }
#if defined(_WIN32)
  u_long mode = enabled ? 1ul : 0ul;
  if (::ioctlsocket(static_cast<SOCKET>(handle_), FIONBIO, &mode) != 0) {
    return make_error(last_socket_error(), "ioctlsocket");
  }
  return Status::ok();
#else
  const int flags = ::fcntl(static_cast<int>(handle_), F_GETFL, 0);
  if (flags < 0) {
    return make_error(last_socket_error(), "fcntl(F_GETFL)");
  }
  const int updated = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
  if (::fcntl(static_cast<int>(handle_), F_SETFL, updated) < 0) {
    return make_error(last_socket_error(), "fcntl(F_SETFL)");
  }
  return Status::ok();
#endif
}

}  // namespace icf::net
