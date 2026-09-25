// Inter-Cluster Fabric - readiness polling.
//
// One wrapper over WSAPoll/poll so the event loop has a single place where platform readiness
// semantics are handled. The number of polled handles is bounded by the connection limit.
#pragma once

#include <cstddef>
#include <span>

#include "icf/core/status.hpp"
#include "icf/net/platform.hpp"

namespace icf::net {

struct PollItem {
  SocketHandle handle = kInvalidSocket;
  bool want_read = false;
  bool want_write = false;
  bool readable = false;
  bool writable = false;
  bool failed = false;
};

// Waits until at least one item is ready or the timeout expires. A timeout of 0 polls without
// blocking; a negative timeout blocks until something happens. Returns the number of ready
// items, or a negative status. Handles that report an error are marked failed and still counted.
[[nodiscard]] Result<std::size_t> poll_sockets(std::span<PollItem> items, int timeout_millis);

}  // namespace icf::net
