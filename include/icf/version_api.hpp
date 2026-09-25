// Inter-Cluster Fabric - version and protocol accessors.
//
// The numeric version values live in the generated header icf/version.hpp (see
// cmake/version.hpp.in). These accessors let a caller read the same values without depending on
// the generated macros.
#pragma once

#include <cstdint>

namespace icf {

[[nodiscard]] const char* version_string() noexcept;
[[nodiscard]] std::uint16_t protocol_version_min() noexcept;
[[nodiscard]] std::uint16_t protocol_version_max() noexcept;

}  // namespace icf
