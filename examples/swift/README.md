# Swift Cookbook

The Swift example prints the opaque Flowersec v5 public contract marker and
optionally establishes a macOS WSS session from an artifact lease. A connected
client exercises typed RPC, notification send, reliable stream write/read/FIN,
liveness, and session close.

## Run

Requirements: macOS 15+ and Swift 6.1+.

```bash
swift run --package-path ./examples/swift
```

Output without an artifact is:

```text
transport=v5
session_api=opaque
```

To establish and close a session, provide a fresh artifact containing a
macOS-compatible WSS candidate and a new path for the durable spend receipt:

```bash
FSEC_ARTIFACT_V5_PATH=/secure/path/artifact-v5.json \
FSEC_SPEND_RECEIPT_V5_PATH=/durable/state/artifact.spent \
FSEC_ORIGIN=https://app.example \
FSEC_TRUST_ROOT_PEM_PATH=/secure/path/custom-root.pem \
  swift run --package-path ./examples/swift
```

The example creates the receipt with no overwrite, restricts it to the current
user, synchronizes it before connection credentials are sent, and fails closed
when the path already exists. The receipt contains no artifact or key material.
The endpoint leaves that receipt in place and writes `<receipt-path>.released`
after its connection closes. This local marker does not represent a relay release.
After connecting, the client makes typed RPC type `7001` with
`{ "value": "ping" }`, sends notification type `7002` with
`{ "value": "notify" }`, then writes `hello` on a `parity.echo` stream,
sends FIN, and reads `world` through peer FIN. The repository server-parity
fixtures implement this application contract; a deployed service must register
equivalent handlers. Connection and session failures expose only a structured
`RetryDisposition`.
Long-lived applications give `ConnectionController` a refreshable artifact
source; this one-shot example never reuses its spend receipt.

The Direct server example waits on `DirectWebSocketListener.waitClosed()` and
starts `close()` when its task is canceled. Waiting alone keeps the listener
serving. Closing cancels pending authorization and application callbacks without
waiting for clients to acknowledge TLS shutdown. Both methods return after those
callbacks finish and accepted connections close, including connections still
waiting for HTTP upgrade.

To check contracts in both directions, set `FSEC_EXAMPLE_BIDIRECTIONAL=1`,
`FSEC_EXAMPLE_QUERY=1` and `FSEC_PARITY_CONTRACTS_PATH` on both endpoints.
`FSEC_EXAMPLE_QUERY_OVERLAP` sets the number of concurrent queries per endpoint.
The ordinary endpoint can read the current application policy from
`FLOWERSEC_PARITY_POLICY_FILE`: a JSON object with `execute` and `disclose`
arrays of numeric method IDs. Publish updates by replacing the file atomically.
Execution and disclosure are checked independently on each dispatch. A missing
or invalid configured file denies the operation. Without a policy file, the
endpoint permits its installed parity methods for the admitted session.

For a 32 MiB binary echo over Tunnel, run one copy per endpoint, with each
copy's own artifact, receipt and `FSEC_TUNNEL_INGRESS`. On the caller set
`FSEC_EXAMPLE_LARGE_RPC=1`; on the serving endpoint set
`FSEC_EXAMPLE_LARGE_RPC=serve`. Either Tunnel leg can take either application
role. Both endpoints register method `7010` before connecting. Set
`FSEC_RPC_FRAME_BYTES=50331648` on both to allow the Base64 JSON envelope in
both directions. Alternatively set both `FSEC_RPC_SEND_BYTES` and
`FSEC_RPC_RECEIVE_BYTES` instead of the common limit. A configured policy
file must permit execution of `7010` on the serving endpoint.

The caller checks the entire reply and closes the session, then prints
`binary_echo=verified`. The serving endpoint validates and returns the canonical
Base64 value. It prints `binary_echo=accepted` after receiving a valid request
and observing session closure; an empty exchange, failure or timeout exits
with an error. Only the caller can verify delivery. This exchange needs no
additional application stream. Set `FSEC_EXAMPLE_QUERY=1` and supply the
contract manifest if both applications also support contract queries.

## Capacity product on macOS

Set `FLOWERSEC_CAPACITY_WORKER_COMMAND` to a JSON array containing the absolute
path of the Release executable, without arguments. The capacity launcher starts
the coordinator and the product on a private Unix socket. The coordinator only
forwards the original command and event stream; the launcher owns the workload
schedule and process sampling.

Set `FSEC_ORIGIN` (default `https://parity.example`) and `FSEC_PARITY_CONTRACTS_PATH` (the repository's
`examples/parity-contracts.json`). Direct requires the PEM files named by
`FSEC_LISTEN_CERT_PEM_PATH` and `FSEC_LISTEN_KEY_PEM_PATH`; it binds a loopback
listener on an OS-assigned port by default. Configure `FSEC_TRUST_ROOT_PEM_PATH`
when the issuer uses a private CA. For a tunnel, supply the independently
authorized `FSEC_CAPACITY_INGRESS_A` and `FSEC_CAPACITY_INGRESS_B` WSS
URLs for the deployed relay listeners. The relay processes and their authority
must be deployed and sampled separately. Configured addresses alone do not
establish relay readiness.

`initialize.options.materialPath` is the driver's path anchor. Its parent contains
`invitations`, `approvals` and `records`; `FSEC_CAPACITY_INVITATION_DIR`,
`FSEC_CAPACITY_APPROVAL_DIR` and `FSEC_CAPACITY_RECORD_DIR` can name these
private directories explicitly. For Direct, the client reads `invitations/pN.json`
and the listener reads the independently published `approvals/pN.json`.
For Tunnel the issuer publishes `invitations/pN/second.json` for B, then
`invitations/pN/first.json` for A. Each leg has its own signed entry selection.
`install_tunnel_server(index)` installs an independently published B; the
batched `prepare_server(count)` serves the original WW schedule. Both write an
exclusive digest receipt for each verified B. `prepare` opens no endpoints. A `connect` reads its own
position without waiting for another position's invitation. Replacements use
fresh IDs of the form `pN-gG` and fresh credentials. `replace_tunnel_server`
checks both old leg release receipts from the authorizer before installing the new B.

For overlapping generations, initialize with `overlapSuccessors: 4` and the
matching `directReplacement` or `tunnelReplacement` option. Keep all initial
pairs connected. Direct reads the new generation's issued invitation and
approval. WW uses one relay, with the issuer in `--allow-generations
--overlap-successors` mode. For each of four distinct positions:

1. For WW, ask the issuer to `install_b`, call `replace_tunnel_server` with
   `index`, `session: pN`, `generation: 2`, and `expectedSession: pN-g2`, then
   ask the issuer to `publish_a`. It checks the private B registration before
   releasing the matching A invitation. Direct needs no Tunnel command.
2. Call `connect_successor` with the same identity fields, then `probe` the
   successor ID. The old ID still addresses its own pair. `check_live` and
   `snapshot` include both generations. `business(session, operation, bytes)`
   performs an authorized RPC echo or duplex raw stream round trip (`echo` or
   `raw`, 256 or 1048576 bytes per direction).
3. After all four successors respond at both ends, retire each old ID with
   `close_session` and join its termination event. Direct checks both local
   release markers before acknowledging retirement. For WW, call
   `confirm_tunnel_releases` with the old identity to join both authority
   markers; the driver independently observes relay `watch` and `retired`.

`generation_state` accepts a session ID and, optionally, its index and
generation. It reports endpoint liveness, physical closure and how many of
the two durable reservations remain held or have been released. A closed WW
pair can still have releases pending. After retirement `check_live` rejects
the old ID. In overlap mode, capacity spend, admission and release markers
contain `flowersec/5` followed by a newline. Without `overlapSuccessors`,
`replace_direct` and `replace_tunnel` keep the close-first workflow.

`initialize.options.storeDirectory` must be a private writable directory on
durable storage. For Direct, the dialer's `spent-` and listener's `admitted-`
receipts remain in place. Their SDK release callbacks publish `released-client-`
and `released-` respectively, using the same credential digest. Each spend creates an exclusive receipt keyed by the credential
and the consuming role; an uncertain write is not retried. For the four parity
methods, the binding verifies the issuer's per-leg record at admission and
checks its current contents on each inbound call, query and notification. A
query for the notification method also requires a live subscription. This
example does not implement a transactional revocation service or protection
against restoration of an older storage snapshot.

The capacity commands use real SDK sessions, notification subscriptions and
stream counts. The product does not implement issuer or relay control-plane
commands. Host provisioning must publish v5 grants and obtain any relay
retirement observations directly from the deployed relay.

On Darwin arm64, `scripts/build-swift-ww-capacity.py` in the workload checkout
packages the Release Swift executable with its Go issuer, authorizer, relay and
original capacity driver. Pass `--output`, `--product-go`, `--driver-go` and
`--swift-executable`; use the Go versions pinned by the product and driver.
Set `FLOWERSEC_CAPACITY_SWIFT_WW_PRODUCT` to the resulting absolute product
directory to select the Swift deployment in `TestFocusedProductionCapacityCase`
with SDK `swift` and case `CAP-WW-1000`. The original capacity schedule installs
all initial B legs before publishing A. A configured churn plan waits for the
old Swift termination event, both authorization releases, and the old Relay
generation to finish before admitting a new generation at that position.

For a single-position correctness check, set `FLOWERSEC_TEST_SWIFT_WW_ONE_POSITION`
to that directory and run only `TestSwiftWWOnePositionReplacement`. This check
does not exercise the thousand-pair workload or measure its limits.

## Runtime Boundaries

Applications receive only opaque artifacts, sessions, RPC peers, byte streams, and redacted errors. Connection selection and cryptographic state remain internal.

## Troubleshooting

- Spent or expired artifact: acquire a fresh artifact and retry.
- TLS or subprotocol rejection: verify the artifact's CA or pin policy and the exact Flowersec v5 subprotocol.
- Dependency resolution failure: run `swift package resolve --package-path ./examples/swift` and retry.
