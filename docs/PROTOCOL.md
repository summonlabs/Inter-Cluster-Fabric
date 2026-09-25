# Protocol

The coordinator, the cluster agents, and the operator tooling speak one framed, versioned protocol
over TCP. The schema is small on purpose: every message is bounded, every field is validated before
use, and a message that carries fields this build does not know about is rejected rather than
silently trimmed.

## Frame format

All integers are big-endian.

```
offset  size  field
0       4     magic "ICF1"
4       2     protocol version (1)
6       2     message type
8       4     flags (bit 0 = signed; all other bits must be zero)
12      4     payload length (at most 1 MiB)
16      4     header CRC32C over bytes [0,16)
20      N     payload
20+N    4     payload CRC32C
24+N    32    HMAC-SHA256 tag (only when the signed flag is set)
```

Refusals are typed: a bad magic is `INVALID`, an unsupported version is `INCOMPATIBLE`, a CRC
mismatch is `CORRUPT`, an unknown flag or message type is `INVALID`, and a missing or wrong MAC
is `UNAUTHORIZED`. Lengths are validated against the configured maximum *before* any allocation,
and the parser accepts input incrementally, so a peer that dribbles one byte at a time is handled the
same as one that sends a whole frame.

## Channel authentication

A shared key can be configured per authority domain (`domain_key.<domain>` on the coordinator,
`--shared-key` on an agent). When a domain has a key:

* the handshake is sent **unsigned** (the peer cannot know which key to verify with before it has
  read the claimed identity),
* every frame after the handshake is signed in both directions, and
* a frame without a valid MAC is refused and the connection is closed.

This is a channel key, not authentication infrastructure: there is no PKI, no certificate
validation, and no identity provider integration. See docs/LIMITATIONS.md.

## Message types

| Type | Direction | Purpose |
| --- | --- | --- |
| `HELLO` / `HELLO_ACK` | peer to coordinator | Handshake: role, identity, domain, incarnation, generation, policy generation, agent term, protocol range, capabilities. |
| `PING` / `PONG` | both | Liveness. A `PONG` is never answered. |
| `REFUSE` / `ERROR` | both | Typed refusal or error. An `ERROR` is never answered with another error. |
| `REPORT_CLUSTER` / `REPORT_ACK` | agent to coordinator | The cluster authoritative record: endpoints, state, generation, content digest. |
| `PROPOSE_CONTRACT` | coordinator to agent | The exact terms both sides are asked to consent to. |
| `CONTRACT_CONSENT` | agent to coordinator | Accept or refuse, bound to the terms digest, the agent incarnation, generation, policy generation, and term. |
| `PREPARE_GRANT` | coordinator to agent | The exact grant record and attempt id to prepare. |
| `GRANT_PREPARED` | agent to coordinator | Accepted, with the agent term and the digest of the record it durably stored. |
| `COMMIT_GRANT` / `GRANT_COMMITTED` | both | Commit the prepared attempt and acknowledge enforcement. |
| `ABORT_GRANT` / `GRANT_ABORTED` | both | Abandon an attempt. |
| `FENCE` / `FENCE_ACK` | coordinator to agent | Withdraw the listed grants. |
| `WITHDRAW` / `WITHDRAW_ACK` | agent to coordinator | The cluster withdraws consent. |
| `STATUS_REQUEST` / `STATUS_REPORT` | both | Durable enforcement state, used to resolve commit and acknowledgement ambiguity. |
| `QUERY` / `QUERY_RESULT` | tooling to any | Status, listings, decisions, fence plans, accounting. |
| `ADMIN` / `ADMIN_RESULT` | tooling to any | Administrative actions; the result names the artifact that was created or addressed. |

## Handshake

```
agent                                          coordinator
  |-- HELLO (identity, domain, incarnation, ------>|
  |   generation, policy generation, term)         |  refuses stale generations,
  |                                                |  refuses identity/domain mismatch,
  |                                                |  detects reincarnation and fences,
  |<-- HELLO_ACK (session token, coordinator term, |  installs the channel key if any
  |    incarnation, view digest, ...)              |
  |<-- FENCE (grants bound to the old incarnation) |
  |<-- STATUS_REQUEST -----------------------------|
  |-- REPORT_CLUSTER ----------------------------->|
  |-- STATUS_REPORT ------------------------------>|  resolves any interrupted commit
  |-- CONTRACT_CONSENT / GRANT_* ----------------->|  (only when flows are in progress)
```

A session token is issued per connection. Every subsequent message from that peer must carry it; a
message with a token that was never issued (a replay from an older session, or a forgery) is refused
with `REPLAYED` and counted.

## Two-sided consent

1. The coordinator proposes terms and creates the contract; the terms digest covers both parties,
   their endpoints, the capacity, the lease, and both sides incarnation, generation, and policy
   generation.
2. Each agent independently decides. It refuses if the terms do not name it, if they are bound to an
   incarnation, generation, or policy generation it no longer holds, if the endpoint scope is not its
   own or does not accept inter-cluster connectivity, if it is not active, or if consent was
   withdrawn.
3. The coordinator records a consent only if its digest equals the contract terms digest *and* the
   consent incarnation and generation equal the live session. Otherwise the answer is
   `CONFLICTING` or `STALE` and nothing is recorded.

## Grant commit, and why ambiguity is safe

```
coordinator                      agent A                agent B
  |-- PREPARE_GRANT(attempt T) -->|                      |
  |-- PREPARE_GRANT(attempt T) ------------------------->|
  |<-- GRANT_PREPARED(T) ---------|                      |
  |<-- GRANT_PREPARED(T) --------------------------------|
  |-- COMMIT_GRANT(T) ----------->|                      |
  |-- COMMIT_GRANT(T) ---------------------------------->|
  |<-- GRANT_COMMITTED(T) --------|                      |
  |<-- GRANT_COMMITTED(T) -------------------------------|
  |   both acknowledged -> reservations taken, state = COMMITTED
```

* A grant is usable only when **both** sides acknowledged the **same attempt id**.
* If a peer disconnects between prepare and commit, the grant becomes `INDETERMINATE` and stays
  unusable. On reconnect, a `STATUS_REQUEST` obtains the durable record from the agent:
  * the agent reports the same attempt as committed, so the acknowledgement is recovered and the
    grant can be finalized;
  * the agent reports a different attempt or nothing, so the grant is fenced and its reservations
    are released.
* A restarted agent has a new incarnation, so any grant bound to the old incarnation is fenced by the
  handshake before it can be used, no matter what a half-written log says.

## Bounds

Frame payloads (1 MiB), collection counts, string lengths, identity lengths, path hops, capacity
values, generations, queued frames and bytes per connection, connections per listener, audit records,
store record size, store size, and store record count all have explicit limits that are validated
before allocation.
