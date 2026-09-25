# Validation

Everything in this chapter was executed against the committed tree. Commands are given verbatim;
results are the observed output, not a summary of intent.

## Environment

| Item | Value |
| --- | --- |
| Operating system | Windows (x64) |
| Compiler | MSVC 19.44.35222.0 (Visual Studio 2022 BuildTools, toolset 14.44.35207) |
| Windows SDK | 10.0.26100.0 |
| CMake | 4.3.2 |
| Generator | Ninja 1.13.2 |
| Logical processors | 16 |
| Warning policy | `/W4 /WX /permissive- /Zc:__cplusplus` for every target (Debug, Release, and the sanitizer build) |

## Builds

```sh
cmake -S . -B build/Release -G Ninja -DCMAKE_BUILD_TYPE=Release      # warning-clean, exit 0
cmake -S . -B build/Debug   -G Ninja -DCMAKE_BUILD_TYPE=Debug        # warning-clean, exit 0
cmake -S . -B build/AsanRelease -G Ninja -DCMAKE_BUILD_TYPE=Release -DICF_ENABLE_ASAN=ON
```

Both Release and Debug compile with `/W4 /WX` and produce zero warnings. The sanitizer build adds
`/fsanitize=address /Zi` and is also warning-clean.

## Test suite

```sh
ctest --test-dir build/Release --output-on-failure
ctest --test-dir build/Debug   --output-on-failure
```

Thirteen test binaries, 111 cases, all passing in Release and in Debug:

| Binary | Cases | Covers |
| --- | --- | --- |
| `icf_core_tests` | 14 | digests and MACs against published vectors, UTF-8 validation, checked arithmetic, byte codec bounds, identity validation, clock and timestamp conversion, configuration strictness, RNG determinism |
| `icf_model_tests` | 8 | registry invariants and digest stability, derived path state, canonical round trips, tamper and truncation refusal, contract terms |
| `icf_wire_tests` | 9 | frame round trips, partial delivery, malformed headers, oversized declared lengths, signed frames and tamper detection, every message schema, truncation, enumeration bounds |
| `icf_store_tests` | 10 | log append and scan, torn-tail recovery, damaged payload handling, header and version refusal, replay refusal, bounds, snapshot integrity, recovery replay, compaction, corruption refusal |
| `icf_engine_tests` | 16 | every distinct outcome, policy two-sidedness, grant lifecycle, degraded and unsupported paths, fence plans, fencing idempotence, accounting closure, recovery fencing, determinism |
| `icf_policy_tests` | 6 | deny-by-default, refuse precedence, stale policy generations, wildcards, degraded and capacity intersection, unrelated domains |
| `icf_property_tests` | 6 | seeded invariants: authorization needs every condition, mutation order independence, fencing completeness with closed accounting, stale incarnations never reauthorize, encoding round trips, decision family consistency |
| `icf_differential_tests` | 2 | 1500 random registries compared against an independent reference model, plus a consent-free corpus |
| `icf_adversarial_tests` | 11 | 20000 random message payloads, every single-bit mutation of a valid message, 4000 hostile framings, oversized counts, extreme values, duplicate identities, invalid UTF-8, snapshot truncation at every length, log bit flips at every third offset |
| `icf_net_tests` | 12 | real loopback TCP: handshake, byte-at-a-time delivery, garbage input, oversized frames, unknown message types, replay refusal, connection limits, idle deadline, signed channels, keep-alive and error non-looping, start and stop cycles |
| `icf_concurrency_tests` | 6 | 8 client threads against one loop, start and stop cycles, connection churn, store open and close cycles, concurrent logging, concurrent registry reads |
| `icf_multiprocess_tests` | 7 | independent daemon processes over loopback with hard kills (below) |
| `icf_cli_tests` | 4 | CLI status, inspection, decision exit codes, fence plans, unsupported link kinds, agent control channel |

Every case is seeded and prints its seed, so any failure is replayable with `--seed <n>`.

### Multiprocess proof

Each of these starts `icfd` and one or two `icfclusterd` processes as separate operating-system
processes, drives them over loopback TCP through the real protocol, and terminates them with a hard
process kill where a reincarnation is required:

| Scenario | What it proves |
| --- | --- |
| `end_to_end_two_sided_authorization` | Two domains, two agent processes, real transport: no contract is `UNAUTHORIZED`, a contract without a grant is still `UNAUTHORIZED`, and after the two-sided consent plus commit the decision is `OK@ with both authority domains named. Both agents hold an `ACTIVE` enforcement record. |
| `agent_reincarnation_fences_the_old_incarnation` | The far agent is hard-killed and restarted with a new incarnation and generation. The grant bound to the old incarnation is `FENCED@ and never becomes authorized again; re-establishing connectivity produces a *different* grant bound to the new incarnation. |
| `coordinator_restart_increments_the_term` | The coordinator is hard-killed and restarted against the same state directory. The term strictly increases, every recovered grant is fenced before the coordinator serves, the pair stops being authorized, and after both agents reconnect a fresh grant restores it under the new term. |
| `one_sided_replay_cannot_recreate_authority` | A stale handshake (older generation) is refused with `STALE`; a message carrying a session token that was never issued is refused with `REPLAYED`; the model digest is unchanged and the pair is still authorized exactly as before. |
| `withdrawal_fences_and_closes_accounting` | Consent is withdrawn from the cluster agent over its own control channel. Connectivity stops being authorized, every reservation is released, and the endpoint reserved counter returns to zero while the declared capacity is unchanged. |
| `conflicting_reports_resolve_deterministically` | A report claiming the same generation with different content, sent from a session that does not own the cluster, is refused as `REPLAYED`; the recorded content is unchanged and the pair still authorizes. The deterministic conflict path itself is covered in-process by the engine and property tests. |
| `agent_killed_mid_flow_leaves_no_usable_grant` | The far agent is killed between grant issue and commit acknowledgement. Every recorded grant is left unusable (`PREPARING`, `PREPARED`, `INDETERMINATE`, `ABORTED`, or `FENCED`), the decision is not authorized, restarting the agent with a new incarnation does not revive it, and a fresh grant restores connectivity. |

## AddressSanitizer

```sh
cmake -S . -B build/AsanRelease -G Ninja -DCMAKE_BUILD_TYPE=Release -DICF_ENABLE_ASAN=ON
# run from a shell where vcvars64 has put the sanitizer runtime on PATH
build/AsanRelease/tests/icf_core_tests.exe        # ... and every other test binary
```

All 111 cases pass under AddressSanitizer with no sanitizer report, including the multiprocess tests
whose daemons are themselves instrumented.

AddressSanitizer found one real defect during hardening: the test harness bound a reference to a
temporary status returned through a helper function, which does not extend the temporary lifetime.
The macros now store the status by value.

Limitation: this platform AddressSanitizer build reports `detect_leaks is not supported on this
platform`, so no leak checker was run. There is no ThreadSanitizer or UndefinedBehaviorSanitizer
run on this toolchain.

## Benchmarks

```
build/Release/benchmarks/icf-bench
```

Measured on the machine described above, Release build, full profile:

| Benchmark | Result |
| --- | --- |
| Hello message encode | 3,469,289 ops/s (122-byte payload) |
| Hello message decode | 7,723,827 ops/s |
| Frame append | 4,696,247 ops/s |
| Frame parse | 3,401,794 ops/s |
| Durable log append (with fsync) | 1,060 ops/s (2000 records, 262,064 bytes) |
| Empty snapshot compaction | 5.0 ms |
| Decision, authorized path | 10,977 ops/s (32 clusters, 128 endpoints, 1 contract, 1 grant) |
| Decision, unauthorized path | 11,187 ops/s |
| TCP connect and handshake | 144 ops/s |
| Status round trip over loopback | 25,592 ops/s (mean 38.8 us, p50 29.6 us, p99 92.7 us) |
| Two-sided contract plus grant commit (two agent processes) | 31.85 flows/s (mean 31.4 ms, p99 32.2 ms per flow, 50 flows) |

The flow benchmark performs, for each flow: propose a contract, wait for both agents to consent over
their own connections, issue the grant, and wait until both agents have acknowledged and enforced it.
Each of those steps is a durable write on three processes.

## Install and downstream consumer

```sh
cmake --install build/Release --prefix <prefix>
cmake -S examples/downstream -B build/downstream -G Ninja -DCMAKE_PREFIX_PATH=<prefix>
cmake --build build/downstream
build/downstream/consumer
```

Observed output of the consumer, which links only against the installed `icf::icf` target and
includes only installed headers:

```
consumer: linked against Inter-Cluster Fabric 1.0.0 (protocol 1..1)
consumer: decision outcome=OK detail=connectivity is authorized by both authority domains
consumer: all checks passed
```

## Defects found and fixed during hardening

These were reproducible defects in this repository, each found by a test or a tool and fixed before
closure. They are listed because the verification is only meaningful if the failures are visible too.

| # | Defect | Effect | Found by |
| --- | --- | --- | --- |
| 1 | SHA-256 round constants were computed from the cube of each prime instead of the cube root | Every digest was wrong; consent binding, conflict detection, and view digests were all meaningless | Known-answer test (FIPS 180-4 vectors) |
| 2 | Registry insert took the map key by reference to the record it then moved | Records were stored under empty keys: lookups, validation, decisions, and snapshots were all affected | Model and engine tests |
| 3 | The socket layer called `WSACleanup` when a scope object went out of scope | Listeners and sockets were invalidated between calls; every connection attempt was refused | Smoke test of the daemons |
| 4 | The message decoder rejected an absent cluster identity in a handshake | Observer sessions (the CLI) could not complete a handshake at all | CLI smoke test |
| 5 | Connections closed by the poller were erased without reporting the close | A cluster agent never noticed a coordinator restart, never reconnected, and kept enforcing stale grants until their lease expired | Multiprocess restart test plus a manual scenario with trace logging |
| 6 | The engine considered only the first contract covering an endpoint pair | A fenced historical contract masked a newer valid one; revalidation after a reincarnation could never succeed | Multiprocess reincarnation test |
| 7 | A reincarnation did not take the new content digest with it | The next report looked like a same-generation content conflict, permanently blocking the cluster | Multiprocess mid-flow kill test |
| 8 | A policy rule bound to one policy generation was compared against both clusters | Rules were judged stale whenever the two clusters had different policy generations, so authorization failed for correct configurations | Policy and engine tests |
| 9 | Keep-alive replies and error reports were treated as unknown messages | The coordinator answered `PONG` with an error, the agent answered the error with an error, and the two peers exchanged errors indefinitely (23,924 rejected frames in one benchmark run) | Benchmark counters |
| 10 | The store reported a store with a live log but no snapshot as freshly created | Recovered evidence was mislabelled as fresh | Store recovery test |
| 11 | The test harness bound a reference to a temporary status returned through a helper | Dangling reference in the harness itself | AddressSanitizer (stack-use-after-scope) |
| 12 | Signing was a single flag, so a peer could not verify a signed handshake acknowledgement | Keyed domains could not complete a handshake | Network signing test |
| 13 | The connected-agent count included observer sessions | Readiness checks reported agents that were not connected | Multiprocess restart test |
| 14 | The CLI required `--connect` even for agent-local commands | The agent control channel was unreachable from the CLI | CLI test |
| 15 | Recovery reported a fresh store for a directory that already held a log | Same class as 10, found while fixing it | Store recovery test |

## Adversarial results

The adversarial binary runs, by default and in every suite run:

* 20,000 random byte strings through six different decoders, none of which may crash or accept;
* every single-bit mutation of a valid handshake message (8 x message length cases), asserting that
  a decoded value is still well formed;
* 4,000 hostile framings (random bytes with a broken magic), asserting that the parser either refuses
  or produces a bounded, valid frame;
* declared collection counts above the configured maximum, before any allocation;
* extreme values (maximum generation and capacity, zero and negative durations);
* duplicate identities, invalid UTF-8 in every identity position;
* snapshot truncation at every length from zero to full size;
* every third byte of a log file flipped, asserting that a damaged log either refuses to load or only
  ever loses records from the trusted prefix, never gains one.

## Cleanliness

```sh
git status --porcelain          # empty after the closure commit
```

No temporary build, test, debug, or fresh-clone artifacts are part of the committed tree; the
`.gitignore` excludes build trees, runtime state files, and object files.
