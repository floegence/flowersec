# Control audit transaction component

The internal Go `SQLiteTopUpServer` maintains security audit records and a bounded
export outbox in the same SQLite transaction group as its authoritative source
state. This component supplies controlled local reads; it does not configure a
management network listener, authenticate remote administrators, or qualify a
deployment/exporter. Management gateway authentication, protected storage and
transport, other control authorities, and public SDK composition are separate
dependencies. The internal aggregate HTTP composition is described in
[Controlled operations components](OPERATIONS_V4.md); it does not grant sensitive
record or audit-read permissions.

## Authority changes and atomic recording

Preparing an allocation intent, publishing an issued material batch, changing an
owner binding, recording an explicit authorized denial, or permanently fencing
a source writes its state and audit record together. The authenticated source
invocation must implement `TopUpAuditAccess` as well as ordinary `TopUpAccess`.
The actor comes from the original authentication record, and its current binding
is checked again before commit. There is no anonymous actor or successful
mutation fallback when audit persistence is unavailable.

The original source authority's commit permit remains held through actual
SQLite commit/rollback return. An audit insert failure rolls back the authority
change. An ambiguous commit remains unknown; recovering the existing state does
not regenerate its audit event ID or reissue material. Idempotent state operations
append no duplicate record.

A private `state_revision` versions actual source-state changes with checked
increment and CAS. Audit `BeforeVersion`/`AfterVersion` refer to this authoritative
local record version. It is distinct from the audit sequence used for pagination,
the source binding generation, and the protocol's operation/artifact sequences.
It is not added to TopUp wire results or client terminal receipts. Read audit
events observe the same before/after source version.

ACK and automatic expiry/retirement converge the already admitted operation and
retain their original authoritative ledger facts. They do not need another
ordinary audit row. A permanent source fence uses separate safety audit capacity.
Even if safety audit persistence fails, the independently verified permanent
source fence continues to deny source use; waiting for logging cannot reopen it.
This source-level behavior does not claim to implement another authority's
namespace revocation or change the lifetime of already issued credentials.

## Bounds and retention

`SQLiteAuditPolicy` defaults to 30 days of retention, 128 ordinary records,
16 safety records, and 60 management read requests per minute. Local bounds are
fixed in the store's exact configuration. Retention can be reduced; record
ceilings are 4096 ordinary and 256 safety records. There is no zero-capacity
setting that disables mandatory audit.

The store reserves pages for both classes, including complete transaction
replacement overhead. Ordinary work cannot consume safety rows. At the ordinary
cap, operations requiring a new ordinary record fail closed. The original source
and other live Sessions are not closed merely because audit export is delayed.
An export acknowledgement changes delivery metadata but does not delete retained
audit facts or replenish retained-record capacity. Capacity must cover the
deployment's configured retention and activity rate.

Each record is at most 512 encoded bytes. Its fields are a server-generated random
event ID, UTC time, authenticated actor/role, the fixed tenant, a finite action,
an internal source-object reference, actual before/after source-state versions,
the original request correlation, and the allowed/committed decision. No URL,
endpoint hash, credential, payload, secret, or raw exception is copied. These are
access-controlled security records and are not anonymous public diagnostics.
Ordinary formatting and JSON output are opaque; controlled transports explicitly
use the bounded audit codecs.

Records retain their original trusted upper-bound timestamp plus the configured
retention. Expiry requires the trusted lower bound to reach that deadline.
`ExpireAudit` deletes only expired rows; callers cannot choose a cutoff or delete
an arbitrary event. `secure_delete=ON` and a successful WAL truncation are required
before physical cleanup is reported successful. The append sequence is never
reset after deletion. Pending records lost at retention expiry have a finite
aggregate counter. Filesystem snapshots and external copies require their own
protection and retention guarantees.

## Controlled local reads and export

`AuditAccess` performs independent, current deployment/tenant authorization. Its
trusted checks are bounded local work, with no application callback or I/O.
Source access does not imply management access. The five permissions are:

| Permission | Fixed operation |
| --- | --- |
| Operations read | `AuditStatus`: policy, counts, backlog, observed time and finite failure counters |
| Authorization read | `ReadAuthorization`: bounded source facts, with a mandatory read audit |
| Audit records read | `ReadAudit`: bounded audit page, with a mandatory read audit |
| Outbox export | `ExportAudit` and exact event-ID acknowledgement |
| Retention maintenance | Original-deadline expiry and deletion |

Authorization precedes database queries and is checked again before publishing
results. Revoked permissions or changed actors suppress output. Each transaction
group admits one synchronous storage operation, without a waiting queue or helper
task. Interactive operations/authorization/audit reads share a fixed rate bucket;
export and retention have independent fixed buckets, so an interactive read flood
cannot consume the export/retention allowance. Rejections are aggregated without
writing unbounded denial events.

Audit pages permit a window of at most one day, at most 16 returned records and
at most 8192 encoded bytes, including framing. Queries accept no SQL expressions,
custom projections, tenant switch or arbitrary object scope. The first page fixes
`ThroughSequence`; subsequent pages use it together with `NextSequence`. Auditing
a read therefore cannot extend the original pagination boundary. Final freshness
checks suppress rows that expire while a query is executing.

Interactive sensitive reads must persist their own audit before returning data;
they fail closed when that record cannot be admitted. `ExportAudit` is the
separately authorized deployment outbox transfer and does not recursively audit
each internal transfer. It remains usable at the ordinary record cap. Transfer
retries return the same event IDs; acknowledgements bind the exact sequence/ID
pair and are idempotent. Acknowledgement asserts the authenticated exporter's
external persistence result, not proof that a downstream retention implementation
has been qualified. The internal [durable audit export component](AUDIT_EXPORT_V4.md) implements
original-ID deduplication, interruption recovery and original-deadline deletion
in a separate bounded SQLite destination. Deployment authentication, protected
storage and public SDK composition require their own qualification. Explicit
local export/retention scheduling is provided by `controlv4.AuditMaintenance`.

The local component tests exercise transaction rollback and unknown commit,
ordinary/safety capacity, source fencing with failed audit, permission revocation,
cross-tenant rejection, bounded pagination/rate/output, exact duplicate ACK,
actual SQLite/WAL expiry deletion, and provider tails during close. Test-only
actors, source authorities and continuity checks are not production authority or
deployment qualification.
