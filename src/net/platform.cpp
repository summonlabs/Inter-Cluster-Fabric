#include "icf/net/platform.hpp"

#include <atomic>
#include <cstring>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace icf::net {
namespace {

std::atomic<int> g_network_users{0};

}  // namespace

#if defined(_WIN32)
SocketError translate_socket_error(int code) noexcept {
  switch (code) {
    case 0:
      return SocketError::None;
    case WSAEWOULDBLOCK:
      return SocketError::WouldBlock;
    case WSAEINTR:
      return SocketError::Interrupted;
    case WSAEINPROGRESS:
      return SocketError::InProgress;
    case WSAEISCONN:
      return SocketError::AlreadyConnected;
    case WSAECONNREFUSED:
      return SocketError::ConnectionRefused;
    case WSAECONNRESET:
      return SocketError::ConnectionReset;
    case WSAECONNABORTED:
      return SocketError::ConnectionAborted;
    case WSAENOTCONN:
      return SocketError::NotConnected;
    case WSAETIMEDOUT:
      return SocketError::TimedOut;
    case WSAEADDRINUSE:
      return SocketError::AddressInUse;
    case WSAEADDRNOTAVAIL:
      return SocketError::AddressNotAvailable;
    case WSAEINVAL:
      return SocketError::InvalidArgument;
    case WSAEMSGSIZE:
      return SocketError::MessageTooLarge;
    case WSAENETUNREACH:
      return SocketError::NetworkUnreachable;
    case WSAEHOSTUNREACH:
      return SocketError::HostUnreachable;
    case WSANO_DATA:
    case WSAHOST_NOT_FOUND:
    case WSATRY_AGAIN:
      return SocketError::NameResolutionFailed;
    default:
      return SocketError::Unknown;
  }
}
#else
SocketError translate_socket_error(int code) noexcept {
  switch (code) {
    case 0:
      return SocketError::None;
    case EAGAIN:
    case EWOULDBLOCK:
      return SocketError::WouldBlock;
    case EINTR:
      return SocketError::Interrupted;
    case EINPROGRESS:
      return SocketError::InProgress;
    case EISCONN:
      return SocketError::AlreadyConnected;
    case ECONNREFUSED:
      return SocketError::ConnectionRefused;
    case ECONNRESET:
      return SocketError::ConnectionReset;
    case ECONNABORTED:
      return SocketError::ConnectionAborted;
    case ENOTCONN:
      return SocketError::NotConnected;
    case ETIMEDOUT:
      return SocketError::TimedOut;
    case EADDRINUSE:
      return SocketError::AddressInUse;
    case EADDRNOTAVAIL:
      return SocketError::AddressNotAvailable;
    case EINVAL:
      return SocketError::InvalidArgument;
    case EMSGSIZE:
      return SocketError::MessageTooLarge;
    case ENETUNREACH:
      return SocketError::NetworkUnreachable;
    case EHOSTUNREACH:
      return SocketError::HostUnreachable;
    case EAI_NONAME:
    case EAI_AGAIN:
    case EAI_FAIL:
      return SocketError::NameResolutionFailed;
    default:
      return SocketError::Unknown;
  }
}
#endif

const char* to_string(SocketError error) noexcept {
  switch (error) {
    case SocketError::None:
      return "NONE";
    case SocketError::WouldBlock:
      return "WOULD_BLOCK";
    case SocketError::Interrupted:
      return "INTERRUPTED";
    case SocketError::InProgress:
      return "IN_PROGRESS";
    case SocketError::AlreadyConnected:
      return "ALREADY_CONNECTED";
    case SocketError::ConnectionRefused:
      return "CONNECTION_REFUSED";
    case SocketError::ConnectionReset:
      return "CONNECTION_RESET";
    case SocketError::ConnectionAborted:
      return "CONNECTION_ABORTED";
    case SocketError::NotConnected:
      return "NOT_CONNECTED";
    case SocketError::TimedOut:
      return "TIMED_OUT";
    case SocketError::AddressInUse:
      return "ADDRESS_IN_USE";
    case SocketError::AddressNotAvailable:
      return "ADDRESS_NOT_AVAILABLE";
    case SocketError::InvalidArgument:
      return "INVALID_ARGUMENT";
    case SocketError::MessageTooLarge:
      return "MESSAGE_TOO_LARGE";
    case SocketError::NetworkUnreachable:
      return "NETWORK_UNREACHABLE";
    case SocketError::HostUnreachable:
      return "HOST_UNREACHABLE";
    case SocketError::NameResolutionFailed:
      return "NAME_RESOLUTION_FAILED";
    case SocketError::Unknown:
      return "UNKNOWN";
  }
  return "UNKNOWN";
}

Outcome outcome_for(SocketError error) noexcept {
  switch (error) {
    case SocketError::WouldBlock:
    case SocketError::Interrupted:
    case SocketError::InProgress:
      return Outcome::Busy;
    case SocketError::TimedOut:
      return Outcome::Unreachable;
    case SocketError::ConnectionRefused:
    case SocketError::ConnectionReset:
    case SocketError::ConnectionAborted:
    case SocketError::NetworkUnreachable:
    case SocketError::HostUnreachable:
    case SocketError::NotConnected:
    case SocketError::NameResolutionFailed:
      return Outcome::Unreachable;
    case SocketError::AddressInUse:
    case SocketError::AlreadyConnected:
      return Outcome::AlreadyExists;
    case SocketError::AddressNotAvailable:
    case SocketError::InvalidArgument:
    case SocketError::MessageTooLarge:
      return Outcome::Invalid;
    case SocketError::None:
      return Outcome::Ok;
    case SocketError::Unknown:
      return Outcome::Unknown;
  }
  return Outcome::Unknown;
}

std::string socket_error_text(SocketError error) {
#if defined(_WIN32)
  const int code = WSAGetLastError();
  char* buffer = nullptr;
  const DWORD length = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<char*>(&buffer), 0, nullptr);
  std::string text = to_string(error);
  if (length > 0 && buffer != nullptr) {
    std::string detail(buffer, length);
    while (!detail.empty() && (detail.back() == '\n' || detail.back() == '\r' || detail.back() == ' ')) {
      detail.pop_back();
    }
    text += ": ";
    text += detail;
  }
  if (buffer != nullptr) {
    LocalFree(buffer);
  }
  return text;
#else
  return std::string(to_string(error)) + ": " + std::strerror(errno);
#endif
}

SocketError last_socket_error() noexcept {
#if defined(_WIN32)
  return translate_socket_error(WSAGetLastError());
#else
  return translate_socket_error(errno);
#endif
}

NetworkScope::NetworkScope() {
#if defined(_WIN32)
  if (g_network_users.fetch_add(1) == 0) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
      g_network_users.fetch_sub(1);
      valid_ = false;
      return;
    }
  }
#else
  g_network_users.fetch_add(1);
#endif
  valid_ = true;
}

NetworkScope::~NetworkScope() {
  if (!valid_) {
    return;
  }
  // The socket subsystem is initialised once for the lifetime of the process and is deliberately
  // never torn down again: sockets, listeners, and poll sets outlive the scope that created them,
  // and calling WSACleanup while they are still open invalidates every handle in the process.
  g_network_users.fetch_sub(1);
}

bool loopback_available() {
  NetworkScope scope;
  if (!scope.valid()) {
    return false;
  }
  const SocketHandle handle = static_cast<SocketHandle>(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  if (handle == kInvalidSocket) {
    return false;
  }
#if defined(_WIN32)
  ::closesocket(static_cast<SOCKET>(handle));
#else
  ::close(static_cast<int>(handle));
#endif
  return true;
}

}  // namespace icf::net
