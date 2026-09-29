# Controlled operations components

The internal Go `controlv4.OperationsService` provides an explicitly constructed
`GET /operations` handler for a separately admitted management listener. It does
not start a listener, bind an interface, grant Session access, or enable itself
through the public SDK. `OperationsTLSConfig` requires verified client
certificates, TLS 1.3 and HTTP/1.1, and disables session tickets.

The service registers at most 16 exact client certificates from an independent
management CA. Certificate parsing is bounded at 16 KiB. An accepted CA alone
does not grant operations access: the exact leaf must be registered and its
original validity interval must still contain the trusted current time. Local
`RevokeReader` permanently revokes that registration, including requests on an
existing keepalive connection. Rotation requires explicit new registration.

The base authorization grants the fixed deployment's aggregate read only. It does
not grant authorization administration, sensitive authorization record reads,
audit record reads, audit export, or retention maintenance. There are no tenant
selectors, field projections or query expressions. Explicit diagnostic read,
deletion and incident correlation permissions apply only to the separately
configured exporter and its management table; see
[Diagnostic runtime components](DIAGNOSTICS_V4.md).
The default source network allowlist is exact IPv4/IPv6 loopback; an explicit
configuration can register at most eight canonical management prefixes. Forwarded
headers are not authentication or source-network evidence.

## Bounds and lifecycle

Each service owns one snapshot and output position. Concurrent requests cannot
queue for that position. The configured rate is at most 60 attempts per minute;
authorization denials and invalid request shapes share this rate. Busy refusals
use only a saturating aggregate counter and make no owner queries. The aggregate
route accepts only GET on `/operations` without a query, alternate encoded path,
body or transfer encoding. Explicit diagnostic routes have their own fixed
method/body shapes. JSON has a 64 KiB hard ceiling and fixed fields.

An admitted request has one original deadline, configured from 1 ms through
10 seconds. The native response writer must support a write deadline. Authentication
is checked again after that external call, before store queries and immediately
before output handoff. JSON has `no-store` and `nosniff` headers. The original
position is retained through Write, Flush and deadline-reset return; no response
helper task or independent retry is created.

`Close` stops admission and requests cancellation. `WaitCleanup` only completes
after the original request and optional incident worker actually return. An expired cleanup wait cannot refund
a blocked writer or storage call. All aggregate owners are borrowed from their
actual root: the Environment and stores must belong to the same Environment;
the application executor is the existing root service. Construction failure and
actual cleanup release those borrows and remove retained certificate digests,
authorization adapters and owner graphs.

The listener, native TLS/HTTP buffers, handshakes, connections, request goroutines
and pre-admission refusal responses require their own admitted host profile.
The handler's single position does not bound an arbitrary surrounding HTTP
server. Its response deadline does not prove that an uncooperative store returns;
a blocked store remains charged until its actual return.

## Snapshot fields

The fixed snapshot contains:

- Registered runtime, provider-family and feature-profile names, with one
  immutable value per service, at most 64 restricted ASCII characters each.
  These are deployment configuration labels, not qualification evidence.
- The original root's resource profile revision, dimension names, effective
  limits, current charges, reservation/reference counts and per-dimension peaks.
  The root's own backing is included. Failed unpublished atomic batches do not
  inflate the peak. Releases and Environment replacement do not reset it.
- Environment position, Serve group, material, material-pool, query and result
  capacities and occupied counts. Physical tails remain occupied. Configured
  capacities remain visible after Environment retirement.
- The complete unsampled diagnostic counter registry and fixed marginal
  histogram index names. There are no arbitrary labels or correlation labels.
- If registered, the original executor's ordinary, resident, Completion,
  diagnostic and fixed SDK query running/ready counts and caps. Logical closure
  does not report an executing callback as idle.
- If registered, aggregate verification-registry startup, current, expired,
  unavailable and closed counts, pending/running fetches and refreshes, and
  trust-configuration occupancy. `Current` means the original active Head and
  independent trust pass their current checks. It does not promise freshness
  for every credential's individual staleness policy. Reads do not advance
  pins, retire history, fetch content or mutate authorization gates.
- If registered, the original audit maintenance service's active export/source
  expiry/archive expiry calls, finite failures and persistence/ACK observations.
- Up to eight explicitly registered SQLite TopUp audit stores, identified only
  by fixed local slot. Their independently authorized operations reads report
  current audit caps, retained rows, pending export backlog, timestamp, finite
  failure counters and a bucketed duration of this read. Store state is
  `available`, `capacity` or `unavailable`. A permission denial suppresses the
  whole response; a successful read cannot survive actor or permission changes
  before publication.

Each owner supplies its own consistent observation. The combined document is not
a transaction across owners, and counter marginals can observe concurrent
increments at different points. Peaks are independent dimension maxima, not a
claim that all dimensions reached their maxima simultaneously. No aggregate
asserts quorum for a store that does not implement quorum.

There are no certificate, actor, tenant, namespace, URL, endpoint, credential,
Session/Stream ID, payload or arbitrary exception fields. Sensitive authorization
and audit queries use the separate permissions and transactions described in
[Control audit transaction component](CONTROL_AUDIT_V4.md).

## Operational interpretation

Compare current root charges with caps and historical peaks when resource
rejections rise. Compare original executor ready and running counts to identify
callback saturation; cleanup timeouts require checking actual callback/provider
exit. Compare verification startup, expiry and unavailable counts before assuming
an identity rejection is a certificate renewal problem. Rekey counters and phase
histograms distinguish local preparation, protocol preparation and confirmation.

An unavailable store or rising pending-audit count requires checking the original
store or exporter. Capacity rejection does not authorize expanding signed
limits, dropping receive promises, replaying business work or replacing a Session.
These operations observations never perform those actions.

Native provider send/receive queue telemetry, pre-auth and Stream deployment
aggregation, deployment export policy, management listener admission, other
control authorities and public/four-SDK composition remain separate integration
requirements. The component tests exercise actual TLS authentication and
keepalive revocation, original SQL reads and permission changes, bounded outputs
and rates, and blocked-response ownership. They do not establish full deployment
or provider qualification.
