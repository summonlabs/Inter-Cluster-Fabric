# Inter-Cluster Fabric

**Governed connectivity authority between independently managed accelerator clusters.**

Inter-Cluster Fabric (ICF) answers one question, continuously and with evidence:

> Given authoritative cluster identities, endpoint scopes, inter-cluster links and paths, capacity,
> policy, administrative boundaries, failures, and exact generations — **which cross-cluster
> connectivity is authorized now, under whose authority, and what must be fenced when either
> cluster changes?**

Reachability is not authorization. A link being up says nothing about whether the two clusters have
agreed to use it, whether the agreement is still bound to the current incarnation of both sides, or
whether an operator has withdrawn consent. ICF owns that decision, the two-sided consent behind it,
the fencing that follows a change, and the audit trail that records all of it.

## What ICF owns, and what it does not

ICF owns **cross-cluster connectivity authority**:

* authoritative cluster identities, incarnations, generations, and policy generations;
* endpoint scopes declared by each cluster, and the inter-cluster edges and paths between them;
* capacity accounting for cross-cluster reservations;
* two-sided connectivity contracts (explicit consent from *each* administrative domain);
* grants and leases that bind a contract to exact incarnations, generations, and a coordinator term;
* fencing: what is withdrawn when a cluster reincarnates, withdraws consent, changes bound policy,
  or when the coordinator itself restarts;
* provenance, verification state, typed outcomes, and an audit trail.

ICF does **not** own, and does not pretend to own:

* cluster internals (schedulers, device managers, node agents);
* generic WAN or site routing;
* workload migration or placement;
* storage replication;
* authentication infrastructure (no TLS, no PKI, no identity provider integration);
* optical or switch hardware control (a declared optical link is reported **UNSUPPORTED**).

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the exact boundary, including what is REAL,
what is SYNTHETIC, and what is UNSUPPORTED.

## Concepts

| Concept | Meaning |
| --- | --- |
| `ClusterId` | An authoritative cluster identity, validated against a fixed character set. |
| `IncarnationId` | One *run* of a cluster's agent. A restart produces a new incarnation. |
| `Generation` | Monotonic counter of a cluster's content. A reincarnation must also advance the generation. |
| `PolicyGeneration` | The policy snapshot a consent was issued under. A bump invalidates dependent grants. |
| `Term` | The coordinator's fencing token. A restart increments it, fencing everything issued before. |
| `AuthorityDomainId` | The administrative domain that governs a cluster. Consent is per domain. |
| Contract | The terms both domains consent to. Consent binds to a digest, never to "similar words". |
| Grant | A committed, capacity-reserved authorization bound to exact incarnations/generations/term. |
| Reservation | Capacity held on an endpoint scope while a grant is in force. |
| Provenance | Where evidence came from and whether it is verified. Recovered state is historical. |

## Outcomes are typed and distinct

The runtime never collapses negative results, and never turns missing evidence into success. Only
`OK` is a plain success; `DEGRADED_AUTHORIZED` is authorized but explicitly not a healthy-path grant.

| Outcome | Meaning |
| --- | --- |
| `OK` | Authorized by both domains, over a live path, under a committed grant. |
| `DEGRADED_AUTHORIZED` | Authorized, but only over a degraded path, and only where policy and both endpoint scopes permit it. |
| `UNAUTHORIZED` | No contract, no allow rule from every domain, or no grant covers this pair. |
| `REFUSED` | An authority domain explicitly refuses, or the cluster/endpoint scope is suspended or draining. |
| `FENCED` | Evidence bound to a superseded incarnation, generation, or coordinator term. |
| `STALE` | The evidence exists but belongs to an older generation, policy generation, or incarnation. |
| `CONFLICTING` | Two updates claim the same generation with different contents; an operator must resolve it. |
| `INCOMPLETE` | Consent, acknowledgement, or a grant is not in place yet. |
| `INDETERMINATE` | A commit/acknowledgement exchange is unresolved; the grant is not usable. |
| `PARTITIONED` | No path between the endpoint scopes is registered and up. |
| `UNREACHABLE` | The transport could not reach a peer. |
| `UNKNOWN` | The runtime holds no evidence either way. This is not a denial. |
| `UNSUPPORTED` | The link kind or operation is outside what this runtime drives. |
| `EXPIRED` | The validity window elapsed. |
| `CAPACITY_EXCEEDED`, `NOT_FOUND`, `INVALID`, `CANCELLED`, `REPLAYED`, `REINCARNATED`, `CORRUPT`, `INCOMPATIBLE`, `OVERFLOW`, `BUSY`, `ALREADY_EXISTS`, `INTERNAL` | The remaining distinct results. |

## Quick start

Build (C++20, CMake 3.20+, no third-party dependencies):

```sh
cmake -S . -B build/Release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/Release --parallel
ctest --test-dir build/Release --output-on-failure
```

Run a coordinator and two cluster agents (each an independent operating-system process) over
loopback TCP:

```sh
# Coordinator (authority domain "domain-north")
build/Release/apps/icfd --state-dir /var/lib/icf --domain domain-north --listen 127.0.0.1:7700

# Cluster agent for cluster-a, governed by domain-north
build/Release/apps/icfclusterd --cluster cluster-a --domain domain-north \
    --coordinator 127.0.0.1:7700 --state-dir /var/lib/icf-cluster-a --control 127.0.0.1:7801 \
    --endpoint.a-scope.scope=/accelerator/a --endpoint.a-scope.capacity=1000

# Cluster agent for cluster-b, governed by a different domain
build/Release/apps/icfclusterd --cluster cluster-b --domain domain-south \
    --coordinator 127.0.0.1:7700 --state-dir /var/lib/icf-cluster-b --control 127.0.0.1:7802 \
    --endpoint.b-scope.scope=/accelerator/b --endpoint.b-scope.capacity=1000
```

Then, with the CLI (see [docs/OPERATIONS.md](docs/OPERATIONS.md) for the full command set):

```sh
icfctl --connect 127.0.0.1:7700 status
icfctl --connect 127.0.0.1:7700 policies allow north-allow --owner domain-north --a cluster-a --b cluster-b
icfctl --connect 127.0.0.1:7700 policies allow south-allow --owner domain-south --a cluster-a --b cluster-b
icfctl --connect 127.0.0.1:7700 links add edge-ab --a a-scope --b b-scope --kind loopback --capacity 1000
icfctl --connect 127.0.0.1:7700 paths add path-ab --a a-scope --b b-scope --hops edge-ab
icfctl --connect 127.0.0.1:7700 propose --a cluster-a --endpoint a-scope --b cluster-b --endpoint-b b-scope
icfctl --connect 127.0.0.1:7700 grant --contract <contract-id>

# The core question:
icfctl --connect 127.0.0.1:7700 decide --src a-scope --dst b-scope
```

The CLI's exit code mirrors the decision: `0` authorized, `3` authorized-but-degraded, `4` any typed
negative outcome (the outcome name is printed), `2` transport failure, `1` usage error.

## How authorization is decided

1. **Identity and generation.** Both endpoint scopes must exist, belong to active clusters with
   active scopes, and carry no unresolved generation conflict or withdrawn consent. An expected
   generation supplied by the caller is checked, never assumed.
2. **Policy, twice.** Policy is deny-by-default and two-sided: each authority domain must have an
   explicit allow rule covering the pair. A refuse rule from either domain wins. A rule that only
   exists at a superseded policy generation produces `STALE`, not a silent fallback.
3. **Path.** A registered path between the scopes must be up (or degraded, where policy and both
   scopes permit it). No path is `PARTITIONED`; an unsupported link kind is `UNSUPPORTED`.
4. **Contract.** Both domains must have consented to *identical terms*, bound to the incarnations,
   generations, and policy generations that are current *now*. A consent bound to a superseded
   incarnation is `STALE`; disagreeing consents are `CONFLICTING`.
5. **Grant.** A grant must be committed, acknowledged by both agents on the same attempt, issued
   under the current coordinator term, bound to the current incarnations/generations/policies,
   within its validity window, and large enough for the requested capacity.
6. **Capacity.** Reservations on both endpoint scopes are checked with checked arithmetic before a
   grant is committed; the decision never over-commits.

The engine is a pure function of the registry: identical inputs always produce the identical
decision, and the decision names the exact contract, grant, authorities, paths, and view digest it
was made against.

## What is fenced when something changes

| Trigger | Effect |
| --- | --- |
| Cluster reincarnation (new incarnation, higher generation) | Every grant bound to the old incarnation is fenced, dependent contracts are closed, reservations are released. Fresh consent and a fresh grant are required. |
| Consent withdrawal | The same, with `REFUSED` on subsequent decisions. Accounting closes: every reservation is released. |
| Policy generation change | Grants bound to the old policy generation are fenced. |
| Coordinator restart | The authority term increments durably, and every grant recovered from disk is fenced before the coordinator serves anything. |
| Endpoint scope suspension/retirement | Decisions become `REFUSED`/`FENCED`; dependent grants are fenced. |
| Lease expiry | The grant expires and its reservations are released. |

Recovery never resurrects authority. State read back from disk is marked historical, and every
dynamic record inside it must be revalidated with the authority that produced it.

## Persistence

Both the coordinator and every cluster agent keep a versioned, integrity-checked store: a snapshot
for bulk state and an append-only log for everything since. Every record carries a CRC32C and a
sequence number; the file header carries a format version and its own CRC. Recovery replays the log
with the same function the live path uses, so a recovered state is exactly the state the log
describes. Malformed headers, unsupported versions, sequence regressions, and implausible lengths are
refused outright; a torn tail is conservatively truncated and reported, which can only ever remove
authority, never create it.

## Verification

The claims above are backed by a test suite that runs by default, including real multi-process
scenarios over loopback TCP with hard process kills. See [docs/VALIDATION.md](docs/VALIDATION.md)
for the exact commands and results, and [docs/CONCURRENCY.md](docs/CONCURRENCY.md) for the
concurrency and ownership audit.

```
ctest --test-dir build/Release --output-on-failure     # 13 binaries
build/Release/benchmarks/icf-bench                     # measured throughput and latency
```

There is no CTest `TIMEOUT` property and no watchdog anywhere in this repository: a hang is a defect
to be diagnosed and fixed, never masked.

## Install and consume

```sh
cmake --install build/Release --prefix /opt/icf
cmake -S examples/downstream -B build/downstream -DCMAKE_PREFIX_PATH=/opt/icf
cmake --build build/downstream
build/downstream/consumer
```

The package exports `icf::icf`; the consumer in `examples/downstream` uses nothing but
`find_package(icf CONFIG REQUIRED)`.

## Repository layout

```
include/icf/core/      typed identities, outcomes, digests, byte codec, clock, RNG, config, logging
include/icf/model/     clusters, endpoints, links, paths, policy, contracts, grants, decisions
include/icf/wire/      frame codec and the message schema
include/icf/store/     write-ahead log, snapshots, mutations, recovery
include/icf/net/       sockets, poller, event loop, connections
include/icf/runtime/   decision engine, fencing, coordinator, cluster agent
include/icf/client/    synchronous protocol client used by the CLI, benchmarks, and tests
apps/                  icfd, icfclusterd, icfctl (and shared command-line support)
benchmarks/            icf-bench: measured throughput and latency
examples/              inspect_authority (library only), downstream (installed package consumer)
tests/                 unit, property, differential, adversarial, network, concurrency, multiprocess
docs/                  architecture, protocol, operations, validation, concurrency, limitations
```

## Documentation

* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — components, state ownership, lifecycle.
* [docs/PROTOCOL.md](docs/PROTOCOL.md) — frame format, message schema, handshake, grant flow.
* [docs/OPERATIONS.md](docs/OPERATIONS.md) — running, inspecting, and recovering a deployment.
* [docs/VALIDATION.md](docs/VALIDATION.md) — what was built, run, and measured, defect by defect.
* [docs/CONCURRENCY.md](docs/CONCURRENCY.md) — threads, ownership, lock order, shutdown.
* [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — REAL vs SYNTHETIC vs UNSUPPORTED, and what is untested.

## Contributing and security

Contributions are accepted under the Apache License 2.0 with no CLA; see
[CONTRIBUTING.md](CONTRIBUTING.md). The runtime transmits no telemetry: it communicates only with
the peers an operator configures, and every persisted artifact stays inside the configured state
directory.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
