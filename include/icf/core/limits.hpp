// Inter-Cluster Fabric - bounded resource limits.
//
// Every limit in the runtime is declared here so that no component invents its own
// unbounded growth. Sizes are validated against these bounds *before* allocation.
#pragma once

#include <cstddef>
#include <cstdint>

namespace icf::limits {

// ---- identities -----------------------------------------------------------------
inline constexpr std::size_t kMaxNameLength = 96;
inline constexpr std::size_t kMaxScopeLength = 192;

// ---- wire -----------------------------------------------------------------------
inline constexpr std::uint16_t kProtocolVersionMin = 1;
inline constexpr std::uint16_t kProtocolVersionMax = 1;
inline constexpr std::size_t kFrameHeaderSize = 20;
inline constexpr std::size_t kFrameTrailerSize = 4;
inline constexpr std::uint32_t kMaxFramePayload = 1u << 20;  // 1 MiB
inline constexpr std::size_t kMaxStringField = 512;
inline constexpr std::size_t kMaxReasonFields = 32;

// ---- model cardinality ----------------------------------------------------------
inline constexpr std::size_t kMaxClusters = 1024;
inline constexpr std::size_t kMaxEndpointsPerCluster = 4096;
inline constexpr std::size_t kMaxEndpointsTotal = 65536;
inline constexpr std::size_t kMaxEdges = 65536;
inline constexpr std::size_t kMaxPathHops = 16;
inline constexpr std::size_t kMaxPaths = 65536;
inline constexpr std::size_t kMaxPolicyRules = 4096;
inline constexpr std::size_t kMaxContracts = 65536;
inline constexpr std::size_t kMaxGrants = 131072;
inline constexpr std::size_t kMaxReservations = 131072;
inline constexpr std::size_t kMaxAuditRecords = 65536;
inline constexpr std::size_t kMaxQueryResults = 4096;
inline constexpr std::size_t kMaxFencePlanEntries = 65536;

// ---- capacity / arithmetic ------------------------------------------------------
inline constexpr std::uint64_t kMaxCapacity = 1ull << 48;
inline constexpr std::uint64_t kMaxDurationNanos = 365ull * 24 * 3600 * 1000000000ull;
inline constexpr std::uint64_t kMaxGeneration = (1ull << 62);

// ---- store ----------------------------------------------------------------------
inline constexpr std::size_t kMaxStoreRecordPayload = 1u << 20;  // 1 MiB
inline constexpr std::uint64_t kMaxStoreBytes = 512ull << 20;    // 512 MiB
inline constexpr std::uint64_t kMaxStoreRecords = 1u << 22;      // 4 Mi
inline constexpr std::size_t kStoreFileNameMax = 260;

// ---- network --------------------------------------------------------------------
inline constexpr std::size_t kMaxConnections = 512;
inline constexpr std::size_t kMaxPendingSends = 256;
inline constexpr std::uint64_t kMaxSendQueueBytes = 8ull << 20;
inline constexpr std::size_t kMaxAcceptBurst = 64;
inline constexpr std::uint32_t kDefaultReadDeadlineMillis = 15000;
inline constexpr std::uint32_t kDefaultWriteDeadlineMillis = 15000;
inline constexpr std::uint32_t kDefaultConnectDeadlineMillis = 5000;
inline constexpr std::uint32_t kDefaultHandshakeDeadlineMillis = 10000;
inline constexpr std::uint32_t kDefaultRetryBackoffMillis = 250;
inline constexpr std::uint32_t kMaxRetryBackoffMillis = 8000;

// ---- runtime --------------------------------------------------------------------
inline constexpr std::size_t kMaxConfigLines = 512;
inline constexpr std::size_t kMaxConfigLineLength = 4096;
inline constexpr std::size_t kMaxLogLineLength = 4096;
inline constexpr std::uint64_t kMaxRevalidateAttempts = 64;
inline constexpr std::size_t kMaxDecisionReasons = 32;
inline constexpr std::size_t kMaxDecisionPaths = 8;

}  // namespace icf::limits
