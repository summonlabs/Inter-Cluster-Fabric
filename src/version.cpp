#include "icf/version_api.hpp"

#include "icf/core/limits.hpp"
#include "icf/version.hpp"

namespace icf {

const char* version_string() noexcept { return kVersionString; }

// The protocol version is part of the wire contract, so the runtime exposes it as a value that
// operators and tests can compare against what a peer negotiates.
std::uint16_t protocol_version_min() noexcept { return limits::kProtocolVersionMin; }
std::uint16_t protocol_version_max() noexcept { return limits::kProtocolVersionMax; }

}  // namespace icf
