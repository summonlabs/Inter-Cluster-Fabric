// Inter-Cluster Fabric - platform socket layer.
//
// The runtime talks over real TCP sockets. Only the Windows path is built and exercised by the
// verification runs recorded in docs/VALIDATION.md; the POSIX branch is provided for
// portability and is explicitly marked UNVERIFIED there.
#pragma once

#include <cstdint>
#include <string>

#include "icf/core/status.hpp"

#if defined(_WIN32)
#define ICF_WINSOCK 1
#else
#define ICF_POSIX_SOCKETS 1
#endif

namespace icf::net {

using SocketHandle = std::intptr_t;
inline constexpr SocketHandle kInvalidSocket = static_cast<SocketHandle>(-1);

enum class SocketError {
  None = 0,
  WouldBlock,
  Interrupted,
  InProgress,
  AlreadyConnected,
  ConnectionRefused,
  ConnectionReset,
  ConnectionAborted,
  NotConnected,
  TimedOut,
  AddressInUse,
  AddressNotAvailable,
  InvalidArgument,
  MessageTooLarge,
  NetworkUnreachable,
  HostUnreachable,
  NameResolutionFailed,
  Unknown,
};

[[nodiscard]] const char* to_string(SocketError error) noexcept;
[[nodiscard]] Outcome outcome_for(SocketError error) noexcept;
[[nodiscard]] SocketError translate_socket_error(int code) noexcept;
[[nodiscard]] SocketError last_socket_error() noexcept;
[[nodiscard]] std::string socket_error_text(SocketError error);

// Process-wide socket subsystem. Constructing one initialises the platform layer; the last one
// to be destroyed tears it down. Instances are reference counted.
class NetworkScope {
 public:
  NetworkScope();
  ~NetworkScope();
  NetworkScope(const NetworkScope&) = delete;
  NetworkScope& operator=(const NetworkScope&) = delete;
  NetworkScope(NetworkScope&&) = delete;
  NetworkScope& operator=(NetworkScope&&) = delete;

  [[nodiscard]] bool valid() const noexcept { return valid_; }

 private:
  bool valid_ = false;
};

// True when the loopback interface resolved and a probe socket could be created.
[[nodiscard]] bool loopback_available();

}  // namespace icf::net
