# Diagnostic runtime components

The internal Go diagnostic runtime consists of `diagnosticv4`'s finite event
projection and aggregate counters, and `sessionv4.DiagnosticSink`'s bounded
delivery service. These components do not enable diagnostics through the public
SDK entry points or provide a management authentication/audit service.

Detailed events require explicit sink construction and the original root
`ApplicationExecutorConfig.Diagnostics` admission. The root has exactly two
diagnostic running positions and four ready positions. They are independent of
ordinary callbacks, Completion, and fixed SDK queries. Every sink uses that same
root service; another sink does not obtain another callback allowance.

## Events and correlation

An immutable event contains only `state`, `attempt_bucket`, `phase`, `code`,
`retry_disposition`, `duration_bucket`, and `correlation_id`. Inputs accept finite
numeric enums. Unknown values become `other`; no input field accepts a URL,
identity, carrier, payload, arbitrary string, error, or error cause. JSON and
formatted event output use the same whitelist. The encoded ceiling is 512 bytes.

`Begin` creates a separate observation for each connection attempt or application
operation. Callers cannot supply an ID or derive one from a Session. Each sink
generates independent random 16-byte IDs, with at most 1024 assigned IDs per UTC
15-minute bucket. Closing an operation does not replenish that bucket's ID
allowance. A bucket change, including a backwards wall-clock change, replaces
live operations' IDs and removes old SDK queue entries. Queued callbacks are
cancelled; already handed-off callback values belong to the application. No
cross-bucket mapping is exported.

Sampling defaults to 1%, using CSPRNG draws independent of correlation IDs. It
can be configured from zero through 100 basis points. The sampled event ceiling
is 4096 per bucket, including events subsequently dropped for callback capacity.
The queue has a 2 MiB encoded-byte ceiling. The default local bounds are 64 live
operations and 64 queued events; increasing them requires the complete original
reservation, up to 1024 operations and 4096 queued events.

Producers use try-now queue admission. A busy gate or exhausted bound drops the
event and increments a finite counter. Producers perform no application callback,
randomness acquisition, or I/O. A single admitted SDK pump samples events and
moves each original backing borrow into the root diagnostic lane. Callback
execution occurs outside SDK gates. Full callback capacity drops the event.

## Cleanup and accounting

The sink's original charge covers its tables, queue, pump, timer and qualified
runtime overhead. The root executor separately prepays its callback task/stack
and ready-slot backing. `TakeBorrow` moves an event's existing backing reference
at executor handoff without minting another reference or freeing the original
charge. Byte arithmetic refuses overflow. Runtime allowances are explicit host
qualification inputs; a constructor does not attest their accuracy.

`Close` stops admission, clears queued events and correlation IDs, and requests
callback cancellation. Its returned cleanup snapshot can be `cleanup_incomplete`.
`WaitCleanup` waits only for actual task retirement; cancelling that wait does not
refund callback resources. An application callback that ignores cancellation,
blocks in a defer, panics, or calls `Goexit` retains its original position until
its actual exit. Root shutdown also closes attached sinks, even under continuous
event production. Completed operation aliases retain no sink reference.

The SDK cannot delete copies retained by an application callback. Custom callback
storage needs its own retention policy. The explicit `MemoryExporter` destination stores only original immutable events
in a preadmitted finite table. It preserves each event's original bucket expiry,
including delayed callbacks; expiry uses the original monotonic deadline as
well as the UTC bucket check. Reads never renew retention. Its one original
worker clears expired events and IDs. `DeleteCorrelation` and `DeleteAll` erase
both stored values and deduplication identifiers without replenishing consumed
bucket quotas. Close clears values immediately and releases backing after the
worker actually exits. Busy/full admission refuses immediately and increments a
saturating aggregate drop count. Destination capacity is at most 4096 events,
1024 IDs and 2 MiB encoded bytes per bucket. These are implementation bounds;
actual storage expiry/deletion and host qualification need independent checks.

An explicitly configured management `OperationsService` can borrow this exact
exporter. Detailed reads and deletion require separate immutable certificate
permissions; aggregate operations read alone grants neither. GET on
`/operations/diagnostics` accepts only bounded offset/limit paging, at most 64
events, with no retained paging snapshot. Output retains the original seven
fields, no-store policy and a write deadline no later than event expiry. DELETE
on that path consumes a fixed 16-byte binary correlation ID; DELETE on its
`/all` child clears the destination. IDs are not query parameters. These routes
share the original independent mTLS, management-network, concurrency, rate and
byte limits. They cannot select another exporter, query across tenants, modify
protocol authority or read the audit store. A trusted deployment must bind a
single authorized diagnostic scope to that exporter. Revocation is rechecked
before publication and ordered with in-memory deletion.

Incident correlation requires both the deployment's `DiagnosticIncidents`
option and the original reader's `CorrelateDiagnostics` and `ReadDiagnostics`
permissions. It is disabled by default. An empty POST to
`/operations/diagnostics/incidents` creates a random 16-byte `parent_event_id`
in a separate management-only table. Each of its 64 positions has at most 32
links. PUT to its `/links` child takes exactly 32 binary bytes (parent ID followed
by correlation ID), and accepts only an ID still retained in that exporter.
POST to its `/lookup` child and DELETE on the parent route each take exactly
16 binary bytes. Binary bodies require `application/octet-stream`; IDs never
appear in URLs. Create/lookup return the parent ID, original absolute expiration
and bounded correlation IDs as JSON.

A parent belongs to one immutable reader registration. Other readers cannot
look it up, extend it or link to it. The parent lasts at most 15 minutes and
never beyond the original certificate deadline; each link retains its exporter's
earlier expiry. Lookup cannot renew either deadline. One preadmitted worker and
timer clear expired rows even without requests. Trusted time uncertainty clears
the affected rows, and reader revocation or service close clears them immediately.
Publication rechecks the original row, permissions, trusted deadline and retained
exporter IDs. Management deletions also erase matching links; direct exporter
deletions are rechecked on lookup/publication. Parent IDs never enter public
events, metrics, Session APIs or cross-tenant queries. These components still
require a separately admitted management listener and deployment qualification.

## Aggregate observations

`diagnosticv4.Counters` supplies unsampled, saturating counters and fixed marginal
histograms for the finite metric registry. Its containing owner must include the
whole bank in its original charge. There is no arbitrary-label map, tenant label,
correlation label, or unbounded Cartesian product. Concurrent snapshots are
observations, not transactional protocol facts.

The sink itself records `diagnostic_drop` and `cleanup_timeout`. The internal Go
Session Environment also owns one complete precharged bank. `DiagnosticCounts`
returns a detached snapshot; it does not enable a detailed event sink or provide
management authorization. Duration buckets are under 10 ms, 10–99 ms,
100–999 ms, 1–9 s, and at least 10 s. Attempt buckets are 1, 2–3, 4–7, and at
least 8. Original Environment attempts use bucket 1; source, ingress and intake
handoffs do not become additional attempts or imply a controller retry count.

The Environment counts installed connection attempts and their once-only
failure transition. Successful explicit Session closure is not a failure.
Exact local failures identify TLS rejection, identity binding rejection,
unknown spend, unavailable stores, reservation conflicts and resource
rejections. Only bounded native transport wrappers are inspected; arbitrary
error methods, strings and causes are neither invoked nor exported. Other
failures remain `other`. Full Environment position tables report resource
rejection before consuming the caller's inputs.

Each actual rekey exchange records start, authenticated phase completion and
successful completion. The local-prepare, protocol-prepare and confirmation
phases have separate finite dimensions. Durations use the original monotonic
phase samples. A watchdog and returning worker observing the same expired round
produce one timeout. These observations do not change deadline checks or create
another clock sample, timer, callback or protocol work item.

The record engine counts each rejected completely parsed datagram at its
original ingress epoch. Current, old and future epochs have separate counters;
pre-ACK staged input is future input. Malformed envelopes without a validated
record header cannot be attributed to one of these epoch classes. Counting
occurs before the original input work backing is released and does not change
AEAD usage, replay windows or receive protection.

`slow_consumer` counts original receive directions whose unread ring reaches
its admitted capacity while still open, once per direction. It reports local
backpressure rather than a transport failure or a claim about application
latency. It does not retract credit, drop data, reset a Stream or create work.
Session and Environment cleanup owners each record their first expired cleanup
wait; repeated waits and caller cancellation do not inflate that owner's count.
The original core, engine, receive pool and rekey owners relinquish their bank
references through physical cleanup before the Environment position retires.

These are the internal Go paths instrumented here. Other authorities, SDKs,
public Environment composition and native provider telemetry require
their own original-owner integration. The separately authenticated internal Go
aggregate read is described in [Controlled operations components](OPERATIONS_V4.md). A metric declaration alone does not
establish that coverage.

For rising `diagnostic_drop`, inspect the configured local queue/operation bounds
and whether the root's two diagnostic callbacks return. Dropped diagnostics do
not justify increasing transport admission or replaying business work. For
`cleanup_timeout`, inspect provider/callback cancellation and actual defer exit
before assuming resources are available again. `slow_consumer` identifies
receive saturation; inspect application read progress without changing signed
credit. Rekey timeout phase distinguishes local work, protocol preparation and
confirmation. TLS, identity, store and resource counts identify different
failure domains; an unknown-spend count requires preserving the original
consumption facts. Access-controlled deployment snapshots and durable
control-plane security auditing remain separate interfaces.
