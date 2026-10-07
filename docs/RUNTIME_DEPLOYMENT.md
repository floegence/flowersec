# Runtime deployment

`flowersec-runtime -config /absolute/path/deployment.json` installs the current
wire revision 4 deployment. Its roles are `relay`, `direct-server` and `direct-client`.
The process constructs SDK owners from independently supplied host inputs and
uses the public native carrier, admission, Noise and READY paths.

The configuration is a bounded JSON document. Unknown fields, duplicate object
keys and trailing JSON are rejected. Deployment field names use the explicit
snake case spellings in `deployment_config.go`. Embedded numeric SDK tuning
uses the exported Go field names of the corresponding configuration type;
`time.Duration` values are integer nanoseconds. Runtime limits have no inferred
machine-dependent defaults.

## Shared host inputs

Every role supplies `wire_revision: 4`, `role`, `resources`, `environment_id`,
`clock`, `namespaces`, `stores` and a finite `shutdown_ms`.

- `resources` supplies the qualified same-root engineering limits. The tenant
  and environment accounts derive from the original deployment inputs. Every
  accepted direct position receives its own session account.
- `clock` identifies an independently qualified monotonic incarnation and
  trusted initial lower/upper interval. Clock continuity and drift checks remain
  part of the running deployment.
- `namespaces` contains independent root pins, finite namespace geometry,
  fixed HTTPS bootstrap addresses and explicit native TLS trust. Each root is
  bootstrapped through its own fresh signed response before credential use.
- Each used store has an absolute canonical SQLite path, its stable original
  identity, finite store limits, an independent history public key and a
  signed history approval. An approval binds the path and database/WAL digests,
  generation, epoch, expiry and permission to provision a new store.

Private signing seeds, original credential maps and TLS private keys are read
from the configured bounded files. A credential does not install a namespace
root, choose a store or replace a missing history approval.

## Direct server

The `direct` object installs a finite original material inventory, stable
admission mappings, native listeners and a frozen raw stream registration set.
The direct roles use `stores[0]` for their original pool spend or admission
history. Materials with the `services` or `execution` profile require the
complete `services` aggregate. Durable business histories install additional
independent physical stores under their own logical service authorities.

The required `direct` inputs are:

| Field | Original input |
| --- | --- |
| `tenant` | Exact tenant of all stable admission mappings |
| `materials` | Original Artifact, source-specific activation proof, both identity certificate files, independent local signer and static DH seed files, source generation, activation signing key ID, three namespace selectors and candidate index |
| `admission` | Exact tenant, audience, crypto profile, source, issuer ID, server identity digest, spend authority and signing key for each accepted stable mapping |
| `listeners` | Material selector, exact numeric `address`, independent TLS certificate/key/trust files and qualified QUIC, WebTransport or WebSocket provider limits |
| `core` | Qualified immutable numeric session/stream/liveness/rekey/cleanup tuning |
| `executor` | Finite original ordinary/resident/Completion execution geometry |
| `streams` | Optional inbound raw stream registrations with exact application kind, handler slots, fixed TCP upstream address and finite timeout |
| `services` | Complete numeric RPC tuning, original service contracts, method bindings and independently owned execution histories |
| `client` | Present only for `direct-client`; fixed local ingress and independent native provider inputs |
| `establishment_limits` | Complete current credential and HELLO codec bounds |
| `local_capabilities` | Features actually implemented by the local deployment |
| `binding_mode` | `1`, the supported native observation binding |
| `handshake_ms` | Finite local establishment duration, up to 90 seconds |
| `max_admission_record_bytes` | Finite original admission record bound |

`core.Clock`, `core.Session` and a supplied handler plan are not configuration
inputs. The runtime installs its qualified clock, verified original session
parameters and newly constructed handler plan. Before opening the listeners,
it qualifies each complete admission graph and checks its same-root capacity.

A native listener's physical address, carrier and TLS policy must match its
complete signed candidate. Multiple original routes may share one listener
when their signed profile, source and Initial frame geometry are compatible.
TCP and UDP listeners are accounted for independently. A second listener of
the same network at the same numeric address is rejected.

HELLO is a bounded unauthenticated lookup hint. The resolver requires the exact
original artifact digest, route digest, candidate ID and attempt ID within the
listener's installed route set. A successful resolution transfers that
original material once. The public Acceptor then independently performs
credential checks, actual AdmissionLedger CAS, FSB binding, Noise and both
READY messages. Application authorization runs only after authentication and
matches the complete original application binding.

Each accepted position owns a fresh handler plan, application plan and session
account. Registered upstream streams preserve bidirectional half-close: peer
FIN closes the TCP write side, TCP EOF closes the Flowersec write side, and
cancellation closes both owners before returning their reservations. Shutdown
joins native listener/provider work, sessions and application callbacks before
retiring the store, namespace and root owners. Failed cleanup retains the
original owner for a later cleanup observer.

## Direct client

A `direct-client` deployment supplies `direct.client` and leaves
`direct.listeners` empty. Its `client.providers` array has one entry per
original material. Each entry supplies the fixed numeric native peer address,
independent TLS roots, qualified carrier options and an explicit `origin`
when required by the signed WebSocket or WebTransport route.

`client.ingress` binds an original material index to one unique numeric
loopback TCP `address`, exact stream `kind`, immutable `metadata`, finite
`slots` and `timeout_ms`. The runtime establishes that material through the
public source-based `Connect` path once, then opens each local connection on
that authenticated session. It reserves the native listener and connection
positions before exposure and each full bridge task vector before dispatch.
EOF propagates as half-close in both directions; cancellation joins both copy
tasks before returning their resources.

Pool materials supply their original `activation_file`. Live materials omit
that file, supply their original nonzero `attempt`, and use
`client.live_control` for the independent fixed HTTPS control address,
mutual TLS credentials and finite provider limits. The live source lease has
no activation proof; the original live control provider performs activation.
The client identity selects the original client certificate and private key.

## Service and execution applications

`services.rpc` contains only immutable numeric tuning. The runtime installs
its qualified root, clock, authenticated session parameters, service registry,
execution bindings and executor charges. Callers cannot supply SDK owners or
callback tables through deployment JSON.

Each `services.methods` entry supplies the exact canonical `contract_file`,
`namespace`, `type`, `work_class` and bounded fixed TCP `upstream`. Unary
requests are sent as bytes followed by TCP FIN; the bounded response ends at
upstream EOF. Notifications send request bytes and FIN and wait for upstream
EOF, which joins the actual application exchange. Observation notifications
use original per-session subscriptions; execution notifications use the
original unique execution handler.

A streaming contract additionally supplies `stream.kind` and
`stream.metadata` for its exact OPEN binding and uses the resident work class.
Its TCP application returns items framed by a four-byte big-endian unsigned
length followed by that many payload bytes. Each complete item is passed to
the original SDK response before reading the next frame. Signed item size,
count, total payload, duration and native backpressure remain enforced by the
original stream owner. EOF lets the SDK publish its terminal result.

Checkpoint and retained-content methods require separately installed
application recovery/content definitions and are rejected by this fixed TCP
application adapter. Application stream kind names, including supported
`*_v1` names, are used exactly as registered.

`services.histories` installs one history per method namespace. Its `service`
fixes the original tenant, audience and namespace; `caller_authorities`,
`Records`, `Active`, `RuntimeBytes`, `WorkRuntimeBytes` and
`ResultRuntimeBytes` bound volatile business execution. Volatile methods use
explicit `admission_offers` containing original `LowerMS` and `UpperMS`
bounds. Reading or reconnecting does not extend those windows.

A history with `durable` uses its own `store`, finite SQLite geometry and
separate `continuity_public_key` and `continuity_approval`. The physical store
approval binds the database and WAL digests. The separately signed execution
approval binds the original identity, logical service, epoch, database digest,
external authority, expiry and `previous_work_fenced: true`. The continuity
key differs from the physical history key. Both approvals must remain valid
at the original open boundary. Database files alone cannot establish that
previous actual or external work has stopped.

The execution approval signs the JSON serialization of this exact ordered
object, with exported field spellings:

```json
{
  "Domain": "flowersec-runtime-execution-continuity-1",
  "Identity": {},
  "Service": {},
  "Epoch": 0,
  "DatabaseDigest": "base64 of 32 bytes",
  "PreviousWorkFenced": true,
  "Authority": "independent settlement authority",
  "NotAfterMS": 0
}
```

`Identity` and `Service` use the exported field spellings of their original
SQLite configuration types. The domain-separated envelope contains no
signature field. Provisioning installs explicitly configured admission windows
through the original store CAS. Reopening requires `admission_offers` to be
omitted and reads the original canonical registrations and windows. Expired
windows remain in persisted history; they do not create new admission promises.
Shutdown joins the actual durable adapter and SQLite work before retiring the
physical connection and sealing its backing. Persistent files are retained.

## Relay

The `relay` role supplies its independent original `pool`, `relay` and
`control_tls` inputs and uses all three physical stores. Pool issuance, source
consumption and relay admission retain separate original ownership.

A tunnel keeps logical client `0`, server `1` and relay `2`. Grant records and
publication slots use the logical endpoint side. Each signed leg independently
chooses endpoint-to-relay or relay-to-endpoint physical direction; its numeric
address and native TLS inputs identify its actual listener. Every native
carrier remains its own connection. Original publication preserves the complete
paired endpoint material and both Grants, and server allow delivery reaches
the original recipient through the independently installed control service.

Each `relay.legs` entry can install an `origin` for outgoing WSS or WebTransport
connections. It must satisfy the signed leg policy and the endpoint's independent
Origin policy. Raw QUIC legs omit this field.

The shared native tunnel peer publishes both independent endpoint listener
manifests as `client_tls_certificate_pem`, `client_tls_private_key_pem`,
`server_tls_certificate_pem` and `server_tls_private_key_pem`. Its relay-only
`--client-listener endpoint|relay` and `--server-listener endpoint|relay`
flags select physical listener ownership before route signing. The independent
`--server-carrier` selector supports carrier combinations different from the
client leg. Endpoint identity roles remain unchanged by those selections.

The tunnel matrix driver supports separate
`FLOWERSEC_PARITY_CLIENT_CARRIERS` and `FLOWERSEC_PARITY_SERVER_CARRIERS`
filters. `FLOWERSEC_PARITY_CLIENT_LISTENER` and
`FLOWERSEC_PARITY_SERVER_LISTENER` each accept `endpoint` or `relay` and
forward that trusted topology choice to the issuing relay peer before signing.
