# Operations

This chapter is the operator view: how to run the runtime, what to inspect, and how to recover.
Every command below was executed against the built binaries; the exact outputs are in
docs/VALIDATION.md.

## Running the coordinator

```sh
icfd --state-dir /var/lib/icf \
     --domain domain-north \
     --listen 127.0.0.1:7700 \
     --ready-file /run/icf-coordinator.ready \
     --log-level info
```

| Option | Meaning |
| --- | --- |
| `--state-dir` | Durable state directory (required). Created if missing. |
| `--domain` | The authority domain this coordinator speaks for (required). |
| `--listen` | `host:port`. Port 0 asks the operating system for an ephemeral port. |
| `--ready-file` | Written after the listener is bound, with `port`, `term`, `incarnation`, and `view_digest`. |
| `--durable` | `true` (default) fsyncs every durable write. |
| `--allow-agent-registration` | Accept cluster identities that were not pre-registered. |
| `--domain-key.<domain>` | Shared channel key for one authority domain. |
| `--log-level` | `trace`, `debug`, `info`, `warn`, `error`, `off`. |

Configuration keys are identical to the long options, in a `key = value` file passed with `--config`.
Unknown keys are an error: a typo never silently disables a check. Command-line options override the
file.

## Running a cluster agent

```sh
icfclusterd --cluster cluster-a --domain domain-north \
            --coordinator 127.0.0.1:7700 \
            --state-dir /var/lib/icf-cluster-a \
            --control 127.0.0.1:7801 \
            --generation 1 \
            --policy-generation 1 \
            --state active \
            --endpoint.a-scope.scope=/accelerator/a \
            --endpoint.a-scope.capacity=1000 \
            --endpoint.a-scope.degraded=false \
            --endpoint.a-scope.allow=true
```

Each endpoint scope is declared with dotted keys: `scope`, `capacity`, `degraded` (whether a
degraded path may be authorized for it), and `allow` (whether it accepts inter-cluster connectivity
at all). Restarting an agent without changing `--generation` bumps the generation automatically,
because a new incarnation must present a higher generation on the wire.

The agent also listens on its **local control channel** (`--control`), which accepts observer sessions
only: status, cluster, grant, contract, and audit queries, plus cluster-local administration
(`agent-state`, `agent-withdraw`, `agent-fence`, and endpoint updates). It refuses
coordinator-only administration with `UNSUPPORTED`.

## Inspection with icfctl

```sh
icfctl --connect 127.0.0.1:7700 status                 # coordinator status, term, digests, counters
icfctl --connect 127.0.0.1:7700 clusters list          # cluster records, endpoints, incarnations
icfctl --connect 127.0.0.1:7700 links list             # edge state and provenance
icfctl --connect 127.0.0.1:7700 paths list             # derived path state and bottleneck capacity
icfctl --connect 127.0.0.1:7700 policies list          # allow and refuse rules per domain
icfctl --connect 127.0.0.1:7700 contracts list         # terms digests and per-side consents
icfctl --connect 127.0.0.1:7700 grants list            # grant state, attempt, acknowledgements
icfctl --connect 127.0.0.1:7700 accounting             # reservations and whether they are closed
icfctl --connect 127.0.0.1:7700 audit --limit 50       # the audit trail

icfctl --connect 127.0.0.1:7700 decide --src a-scope --dst b-scope
icfctl --connect 127.0.0.1:7700 fence-plan --cluster cluster-b --trigger reincarnation

icfctl --agent 127.0.0.1:7801 agent-status             # what the agent itself enforces
icfctl --agent 127.0.0.1:7801 agent-grants
```

`decide` is the runtime core question rendered as a command. Its exit code is stable and safe to
script: `0` authorized, `3` authorized over a degraded path, `4` any typed negative outcome,
`2` transport failure, `1` usage error.

## Administrative actions

| Action | Command |
| --- | --- |
| Register or update a cluster | `icfctl --connect HOST:PORT admin` (see `icfctl --help`) |
| Allow or refuse a pair per domain | `icfctl --connect HOST:PORT policies allow|refuse <id> --owner <domain> --a <cluster> --b <cluster>` |
| Add or fail a link | `icfctl --connect HOST:PORT links add|fail|restore|degrade <edge> ...` |
| Add or delete a path | `icfctl --connect HOST:PORT paths add|delete <path> --a <endpoint> --b <endpoint> --hops a,b` |
| Propose a two-sided contract | `icfctl --connect HOST:PORT propose --a <cluster> --endpoint <e> --b <cluster> --endpoint-b <e>` |
| Issue a grant | `icfctl --connect HOST:PORT grant --contract <id> [--capacity N]` |
| Revalidate or fence a grant | `icfctl --connect HOST:PORT revalidate|fence --grant <id>` |
| Resolve a generation conflict | `icfctl --connect HOST:PORT resolve --cluster <id> --generation <n>` |
| Withdraw consent | `icfctl --connect HOST:PORT withdraw --cluster <id>` |

## Recovery procedures

**An agent restarted (planned or after a crash).** Its grants are fenced automatically during the
handshake, because the new incarnation cannot use them. Inspect with `grants list`, then
`propose` and `grant@ again to re-establish connectivity on the new incarnation.

**The coordinator restarted.** The authority term increments durably, every recovered grant is
fenced before the coordinator serves anything, and reservations are released. Re-issue grants once
both agents have reconnected (`status` reports `connected_agents`).

**A commit acknowledgement was lost.** The grant shows `INDETERMINATE` and is not usable. On the
next connection the coordinator asks for the agent durable state; if both sides hold the same
attempt, the grant is finalized, otherwise it is fenced and a fresh grant must be issued.

**Durable state was damaged.** A damaged file header, an unsupported format version, a sequence
regression, or an implausible length makes the store refuse to load: the daemon exits with a typed
error and does not serve. A torn tail (a partially written last record) is truncated at the last
verifiable record, reported as an incident, and every recovered dynamic record is fenced pending
revalidation.

**Generation conflict.** If two updates ever claim the same generation with different contents, the
cluster is marked `CONFLICTING`, dependent grants are fenced, and decisions for that cluster are
refused until an operator resolves it explicitly with `resolve --cluster <id> --generation <higher>`.

## What to watch

`status` reports `term`, `view_digest`, `connected_agents`, `commits`, `fences`, `refusals`,
`revalidations`, `rejected_replays`, and `rejected_frames`. A rising `rejected_frames` means peers are
sending input the framing layer refuses (a misconfigured key, a version mismatch, or a hostile peer).
A rising `rejected_replays` means messages are arriving with session tokens that were never issued.

## Logging

Logs go to stderr or to a file the operator names, one bounded line per event, with control
characters escaped. The runtime never transmits telemetry: it only talks to the peers an operator
configured, and it writes only inside the state directory and the paths given on the command line.
