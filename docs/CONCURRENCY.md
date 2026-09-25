# Concurrency and ownership audit

This chapter is the audit the runtime was built against: which threads exist, what each one owns,
which locks exist, in what order they may be taken, and how shutdown works. Every claim here is
either enforced by construction (the type system and the ownership rules in the code) or covered by a
test in `tests/net/concurrency_tests.cpp` and `tests/integration/multiprocess_tests.cpp`.

## Thread model

| Thread | Count | Owns | Never touches |
| --- | --- | --- | --- |
| Coordinator event loop | exactly one per `icfd` process | the registry, every socket, every connection, every timer, the durable store, the audit trail | anything another process owns |
| Agent event loop | exactly one per `icfclusterd` process | that cluster record, its consents, its enforcement records, its store, its control-channel clients | the coordinator registry |
| Benchmark load generators | N in `icf-bench` only | their own client sockets | never the server library internals |
| Test client threads | N in the test binaries only | their own client sockets | never the server library internals |

The runtime itself contains no worker pool, no background writer, and no detached thread. Durability
is synchronous: a durable write completes (including fsync) before the effect it authorizes becomes
observable. That is a deliberate trade: it removes an entire class of races at the cost of throughput
that the benchmarks report honestly.

## Ownership rules

1. **One loop owns its objects.** A `Connection`, its socket, its parser, its queue, and its timers
   are created, used, and destroyed by the loop that adopted them. `Connection` is non-copyable and
   non-movable.
2. **Handlers never own connections.** A frame handler receives a `Connection` reference valid only for
   the duration of the call and must not store it. The runtime stores the numeric connection id in its
   session map and re-looks it up by id whenever it needs the connection again.
3. **Destruction is deferred.** `Connection::close()` marks a connection closed and shuts its socket
   down immediately, but the object is erased only after the current dispatch finishes. A handler may
   therefore close its own connection, close another, or stop the loop.
4. **Close is reported exactly once.** Every closed connection is reported to its owner through the
   close handler before it is erased; a connection is never erased silently. This rule was added
   after AddressSanitizer plus multiprocess testing exposed a silent erase that left a cluster agent
   waiting forever after a coordinator restart; it is now covered by the multiprocess restart test.
5. **Timers fire from a snapshot.** Due timers are collected and removed from the timer map before any
   callback runs, so scheduling or cancelling a timer inside a callback cannot invalidate the
   iteration.
6. **Payloads are copied before dispatch.** A decoded frame owns its bytes, so a handler can act on
   the payload after the receive buffer has been reused.

## Locks

There is exactly one lock in the runtime:

| Lock | Where | Scope | Order |
| --- | --- | --- | --- |
| logger mutex | `icf::Logger` | protects the output stream and the level | leaf: no other lock is ever taken while it is held, and no callback is invoked under it |

Everything else is single-threaded by construction. The consequences of that design are audited
explicitly:

| Hazard | Why it cannot occur here |
| --- | --- |
| Self-deadlock | The only lock is a leaf lock taken by the logger write path; nothing inside it acquires another lock or calls out. |
| Mutex re-entry | Logging from inside the logger is impossible: the lock is not recursive and the write path never logs. |
| Lock inversion | There is one lock, so there is no order to invert. |
| Read-to-write upgrade | There is no reader/writer lock and no locked read that later needs a write. |
| Callbacks under a lock | Frame handlers, timer callbacks, and close handlers all run outside any lock. |
| Joining workers while holding state they need | There are no workers; shutdown joins nothing while holding the registry or a connection. |
| Shutdown races | The stop request only clears a flag; the loop finishes its current iteration and then returns. Connections and timers are destroyed by the loop owner after the run returns. |
| Stale completion | Every asynchronous completion carries the connection id and the attempt id it belongs to; a reply for a superseded attempt is refused as `REPLAYED` or `STALE`. |
| Iterator or reference invalidation | Handlers never hold iterators into the connection map; the map is only iterated while sweeping, and the sweep collects ids before erasing. |
| Use after free | Connection objects are owned by `std::unique_ptr` inside the map, and no raw pointer outlives a dispatch call. |
| Resource leaks | Every socket is RAII; connections are erased after they are reported; the store, listener, and loop are members of their owner. |
| Inconsistent lock order | One lock. |

## What the concurrency tests actually do

`tests/net/concurrency_tests.cpp` runs, by default in the suite:

* eight client threads doing 25 connect, handshake, and query cycles each against one event loop,
  asserting that every reply carries a view digest equal to the registry digest the coordinator holds
  and that every request succeeds;
* repeated loop start and stop cycles (the harness starts a coordinator, uses it, and stops it, eight
  times) with no leak and no hang;
* connection churn: sixty clients that connect, query, and abandon their socket without a clean
  shutdown, followed by a probe that must still succeed;
* twenty-five store open, append, compact, and reopen cycles, including snapshot compaction;
* six threads writing 200 log lines each through the leaf lock;
* eight threads reading an unmodified registry digest concurrently, asserting that every reader
  observes the same value (mutation is owned by the loop, so this is the read-only side of the
  ownership rule).

The multiprocess tests add the genuinely concurrent dimension: separate operating-system processes,
real sockets, hard kills, and restarts (see docs/VALIDATION.md).
