# Limitations, and what is proven

This chapter is deliberately uncomfortable reading. It states what was verified on real hardware,
what is synthetic, what is unsupported, and what is not verified at all.

## REAL

* **Framed transport over real TCP sockets.** The coordinator, the cluster agents, the CLI, and the
  tests speak the wire protocol over loopback TCP through the Winsock socket API. Frame headers,
  payloads, and HMAC tags are built and verified byte by byte; partial delivery, byte-at-a-time
  delivery, connection resets, and hostile framing are all exercised in the test suite.
* **Independent operating-system processes.** The multiprocess tests start `icfd` and
  `icfclusterd` with `CreateProcess`, drive them over loopback, and kill them with
  `TerminateProcess` (the Windows equivalent of killing a process outright). Two cluster agents
  in two different authority domains are separate processes; the coordinator is a third.
* **Durable state across restarts.** The stores are real files: append-only logs with per-record
  CRC32C, snapshots with a header CRC and a state digest, atomic replace for snapshots, and fsync on
  every durable write by default.
* **SHA-256, HMAC-SHA256, and CRC32C.** Implemented in this repository with known-answer tests
  (FIPS 180-4 vectors, RFC 4231 vectors, RFC 3720 check values).
* **The measurements in docs/VALIDATION.md** are produced by `icf-bench` on the machine the
  build ran on. Nothing in this repository estimates, extrapolates, or invents a number.

## SYNTHETIC

* **Link and path topology.** Edges and paths are operator-declared or derived from declared edges.
  The runtime does not measure a link, probe a path, or observe physical capacity. A
  `LoopbackTcp` edge means that this runtime drives a real transport for this relationship; a
  `SyntheticModel` edge means that a human declared this topology and no transport is checked.
* **Capacity.** Capacity and reservations are accounting units the operator declares. They are not
  derived from hardware, and the runtime does not enforce them on the wire.
* **Lease durations.** Leases are wall-clock windows enforced by each process own clock; there is no
  distributed clock agreement, and a process with a badly wrong clock will behave accordingly.

## UNSUPPORTED

* **Optical, switch, and ASIC control.** A link declared as `OPTICAL_INTERCONNECT` is reported
  `UNSUPPORTED`, never as healthy, and never as down: the runtime holds no hardware control path,
  so it refuses to guess the state of a fabric it cannot see.
* **RDMA, InfiniBand, NVLink, and vendor SDKs.** No such transport is implemented, wrapped, or
  claimed. The only transport in this repository is TCP.
* **Authentication infrastructure.** There is no TLS, no certificate validation, no PKI, and no
  identity provider integration. The optional shared channel key is a symmetric MAC that proves a
  peer knows the key configured for the authority domain it claims; it does not establish identity,
  it does not provide confidentiality, and it must be run over a trusted network or a tunnel the
  operator provides.
* **Workload migration, storage replication, and cluster-internal scheduling.** Out of scope by
  design; the runtime makes no statement about them.

## Not verified here

* **POSIX builds.** The platform layer has a POSIX branch (sockets, poll, fork and exec, fsync,
  rename), but this verification ran on Windows only. **The POSIX branch has not been compiled or
  executed**; it is marked UNVERIFIED and must not be relied on until someone builds it. The same
  applies to the Threads dependency in the exported CMake package, which only takes effect off
  Windows.
* **Multi-host operation.** Every recorded run uses loopback. The protocol is designed for a real
  network (bounded frames, deadlines, retries with backoff, MACs), but no run in this repository
  crossed a physical network boundary, and no latency, loss, or reordering behaviour was measured.
* **Clang, GCC, and libc++.** Only MSVC 19.44 (Visual Studio 2022 BuildTools) was used. The
  sanitizer run uses MSVC AddressSanitizer; there is no ThreadSanitizer or UndefinedBehaviorSanitizer
  run, so data races and undefined behaviour outside the exercised paths are not ruled out by
  tooling.
* **Long-run soak and fuzzing campaigns.** The adversarial tests are seeded and bounded (tens of
  thousands of mutated inputs per run), not a continuous fuzzing campaign. There is no exploration of
  multi-hour clock skew, disk-full behaviour, or syscall failure injection.
* **Memory-leak instrumentation.** The AddressSanitizer configuration available on this platform
  does not support leak detection (`detect_leaks` reports that it is not supported on this
  platform), so leak freedom rests on RAII and on the repeated open and close tests rather than on a
  leak checker.

## Honest summary

The connectivity authority itself is real and is proven from end to end with independent processes:
two-sided consent, incarnation and generation fencing, coordinator restart fencing, replay refusal,
withdrawal with closed accounting, and mid-flow kill safety. The physical world underneath it is not
simulated and not claimed: this runtime governs who may connect, not what the connection physically
is.
