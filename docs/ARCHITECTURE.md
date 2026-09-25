# Architecture

## The one sentence

Inter-Cluster Fabric is a small, deterministic authority service plus one agent per cluster: the
coordinator owns what is authorized, each agent owns what it enforces, and neither can authorize
anything on its own.

## Components

```
                   +-----------------------------+
                   |        icfd (coordinator)   |
                   |  registry  |  term  | audit |
                   +------+--------------+-------+
                          |              |
        framed TCP        |              |        framed TCP
        (loopback/WAN)    |              |        (loopback/WAN)
                   +------v------+  +----v--------+
                   | icfclusterd |  | icfclusterd |     one process per cluster
                   |  cluster-a  |  |  cluster-b  |
                   +-------------+  +-------------+
                          ^              ^
                          |              |  local control channel (inspection, local admin)
                     icfctl / operator tooling
```

| Component | Owns | Never does |
| --- | --- | --- |
| `icfd` (coordinator) | The authoritative registry, the authority term, two-sided contracts, grants, reservations, capacity accounting, the audit trail, the decision engine. | Touch cluster internals, drive links, decide policy for a domain it does not own. |
| `icfclusterd` (cluster agent) | Its own incarnation, generation, policy generation, endogenous term, endpoint scopes, local consents, durable enforcement records, and its own refusal to consent. | Authorize a grant it did not prepare and commit on the exact attempt the coordinator named. |
| `icfctl` | Operator inspection and administration. | Bypass the protocol: every command is a normal protocol message. |
| `icf-bench` | Measured throughput and latency of the library and the daemons. | Produce synthetic numbers: it reports only what it measures. |

## State ownership

* The **coordinator registry** is owned by the coordinator event loop thread. Nothing else ever
  mutates it. Client reads are served on that same thread, which is why a reply can carry a
  self-consistent view digest.
* Each **agent registry** is owned by that agent event loop thread and holds only what that
  cluster knows: its own record, the contracts it consented to, the grants it enforces.
* **Sockets, connections, and timers** are owned by the event loop that created them; connection
  destruction is always deferred to the end of an iteration (see docs/CONCURRENCY.md).
* **Durable state** is owned by the component store object, touched only from that component
  thread.

## Authority model

Three independent fences must agree before connectivity is usable:

1. **Coordinator term** - incremented and persisted on every coordinator start. A grant is only
   usable under the term that issued it.
2. **Cluster incarnation and generation** - an agent restart produces a new incarnation and a higher
   generation. Consents and grants are bound to both.
3. **Cluster-local (endogenous) term** - incremented and persisted by each agent on every start, used
   to fence its own recovered enforcement records.

On top of those, a grant is usable only when *both* agents acknowledged the *same attempt id*, and
only while its lease is valid. A half-committed grant on one side is never usable.

## Lifecycle

**Coordinator start**

1. Open the durable store (snapshot, then log replay).
2. If anything was recovered, fence every recovered grant and release every recovered reservation,
   and record the incident durably.
3. Increment the authority term and persist the new incarnation *before* serving anything.
4. Bind the listener, install the tick timer, write the readiness file.

**Coordinator shutdown** - hard kill is explicitly supported: nothing is buffered that is not
already durable, and the next start increments the term.

**Agent start**

1. Open the durable store; fence every recovered enforcement record (it is historical).
2. Increment the endogenous term, persist the new incarnation and term.
3. Apply configuration, connect to the coordinator, and send `HELLO` with the incarnation,
   generation, policy generation, and capabilities.
4. On `HELLO_ACK`: adopt the coordinator term, fence anything not issued under it, report the
   cluster record, and answer the coordinator status request with the durable enforcement state.

**Agent restart with the same configuration** bumps the generation automatically (an incarnation
change without a generation change is refused by the coordinator as `STALE`), which is what makes
old grants unusable rather than merely suspicious.

## The decision engine

`runtime::decide` is a pure function from (registry, query, view) to a Decision. It never mutates,
never allocates unboundedly, and is deterministic: the same registry always produces the same
outcome, the same reasons, and the same view digest. Every contract covering the endpoint pair is
considered in a deterministic order (most recently updated first, then by identity), so a fenced
contract cannot mask a newer valid one.

`runtime::plan_fence` is the complementary pure function: given a trigger and a cluster, it lists
exactly which grants, contracts, and reservations must be withdrawn. Applying a plan is idempotent
and closes capacity accounting as it goes.

## Failure semantics

| Situation | Result |
| --- | --- |
| Coordinator unreachable | Agents keep enforcing grants whose lease has not elapsed; nothing new can be authorized. |
| Cluster agent unreachable | Its sessions disappear, in-flight grants become `INDETERMINATE`, and the pair stops being authorized until a status exchange resolves it. |
| Link down | Paths over it become down; decisions become `PARTITIONED` if no alternative path is up, `DEGRADED_AUTHORIZED` if a degraded path exists and is permitted. |
| Link kind unsupported | `UNSUPPORTED`, never a healthy path. |
| Corrupt or truncated durable state | Refused for headers, versions, and sequences; a torn tail is truncated conservatively and reported as an incident. |
| Two updates, same generation, different content | `CONFLICTING`, dependent grants fenced, and an explicit operator resolution is required. |
