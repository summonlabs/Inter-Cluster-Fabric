#include "icf/net/poller.hpp"

#include <vector>

#include "icf/core/limits.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <poll.h>
#endif

namespace icf::net {

Result<std::size_t> poll_sockets(std::span<PollItem> items, int timeout_millis) {
  if (items.size() > limits::kMaxConnections + 4) {
    return invalid("poll set exceeds the maximum number of connections");
  }
  if (items.empty()) {
    return static_cast<std::size_t>(0);
  }
#if defined(_WIN32)
  std::vector<WSAPOLLFD> descriptors;
  descriptors.reserve(items.size());
  for (const PollItem& item : items) {
    WSAPOLLFD descriptor{};
    descriptor.fd = static_cast<SOCKET>(item.handle);
    descriptor.events = 0;
    if (item.want_read) {
      descriptor.events |= POLLRDNORM;
    }
    if (item.want_write) {
      descriptor.events |= POLLWRNORM;
    }
    descriptors.push_back(descriptor);
  }
  const int ready = ::WSAPoll(descriptors.data(), static_cast<ULONG>(descriptors.size()), timeout_millis);
  if (ready == SOCKET_ERROR) {
    const SocketError error = last_socket_error();
    if (error == SocketError::Interrupted) {
      return static_cast<std::size_t>(0);
    }
    return Status::make(outcome_for(error), std::string("poll failed: ") + to_string(error));
  }
  std::size_t count = 0;
  for (std::size_t i = 0; i < items.size(); ++i) {
    const SHORT events = descriptors[i].revents;
    items[i].readable = (events & (POLLRDNORM | POLLIN)) != 0;
    items[i].writable = (events & (POLLWRNORM | POLLOUT)) != 0;
    items[i].failed = (events & (POLLERR | POLLHUP | POLLNVAL)) != 0;
    if (items[i].readable || items[i].writable || items[i].failed) {
      ++count;
    }
  }
  return count;
#else
  std::vector<struct pollfd> descriptors;
  descriptors.reserve(items.size());
  for (const PollItem& item : items) {
    struct pollfd descriptor {};
    descriptor.fd = static_cast<int>(item.handle);
    descriptor.events = 0;
    if (item.want_read) {
      descriptor.events |= POLLIN;
    }
    if (item.want_write) {
      descriptor.events |= POLLOUT;
    }
    descriptors.push_back(descriptor);
  }
  const int ready = ::poll(descriptors.data(), static_cast<nfds_t>(descriptors.size()), timeout_millis);
  if (ready < 0) {
    const SocketError error = last_socket_error();
    if (error == SocketError::Interrupted) {
      return static_cast<std::size_t>(0);
    }
    return Status::make(outcome_for(error), std::string("poll failed: ") + to_string(error));
  }
  std::size_t count = 0;
  for (std::size_t i = 0; i < items.size(); ++i) {
    const short events = descriptors[i].revents;
    items[i].readable = (events & POLLIN) != 0;
    items[i].writable = (events & POLLOUT) != 0;
    items[i].failed = (events & (POLLERR | POLLHUP | POLLNVAL)) != 0;
    if (items[i].readable || items[i].writable || items[i].failed) {
      ++count;
    }
  }
  return count;
#endif
}

}  // namespace icf::net
