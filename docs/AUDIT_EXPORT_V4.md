# Durable audit export component

The internal Go `SQLiteAuditArchive` transfers original SQLite TopUp security
audit outbox records into a separate bounded SQLite transaction group. It has
no API for caller-supplied records, record edits, arbitrary deletion or sensitive
record reads. Public SDK and deployment authorization are separate composition.

A destination fixes its own independent storage identity/continuity and the exact
source identity, generation, tenant, internal source object and retention policy.
These are protected audit configuration, never public diagnostic labels. The
source and destination independently authorize outbox export. The source's actual
retention must equal the archive's configured retention before any source query.
A management operations permission grants only aggregate counts; retention
maintenance has its own permission and rate allowance.

`TransferAuditPage` performs one original bounded query, destination transaction
and source acknowledgement. It borrows the original source owner until actual
return and occupies the archive's existing synchronous storage position. No
background retry, helper goroutine, new source cursor or extra ledger authority
is created. Query windows remain at most one day, pages at most 16 records and
8192 encoded bytes. Original permissions and actors are checked after the read,
before destination commit and before source acknowledgement.

The destination uses event ID as its primary key and also checks the exact
original sequence and encoded record. Exact retry is idempotent, including when
the archive is full. A reused ID with different bytes, or a reused sequence with
a different event, is rejected. A capacity failure rolls back the entire page.
The record ceiling is explicitly configured from 1 through 4096; full page cache,
transaction, wire scratch and disk backing are admitted before opening the store.

The result independently reports destination `Persistence` and source
`Acknowledgement` as `not_started`, `unknown` or `committed`. A lost COMMIT result
provides no success receipt and never acknowledges the source. Retry reads the
same source IDs and compares the archive's existing bytes. A confirmed archive
commit followed by an interrupted source ACK retains its confirmed persistence
fact. A failed transfer never advances `NextSequence`; retry uses the original
query. Successful acknowledgement changes only source delivery metadata, not its
retained audit facts.

## Retention and recovery

Every archive row expires at the original record's upper-bound UTC timestamp plus
the immutable configured retention, at most 30 days. Arrival, export retries,
reopen and ACK do not reset that deadline. A record timestamp must be covered by
the archive clock's independently trusted current upper bound before persistence;
a legitimate source whose interval is ahead can retry when covered. Expired
input cannot resurrect a deleted event.

`ExpireAuditArchive` uses the current trusted lower bound and accepts no caller
cutoff or event-ID selector. Deletion occurs transactionally with the retained-row
count using `secure_delete=ON`. Successful physical cleanup also requires a
completed WAL truncation. A failed storage operation or checkpoint does not
report cleanup success. External filesystem snapshots and copies require their
own protection and deletion guarantees.

Reopen checks the exact schema, source/configuration binding, row count,
sequence uniqueness, complete record encoding and original expiry for every
retained row. Independent continuity authenticates restoration and a new fenced
connection epoch prevents an old connection from resuming authority. SQLite
cannot prove that its own file was not rolled back. Host access controls,
encryption at rest where required and independent restore evidence remain
explicit deployment dependencies. Files use the existing private SQLite backing
and FULL synchronous/WAL storage discipline.

Close stops new transfers. Actual driver calls and their source borrow remain
charged until they return; an expired cleanup wait does not refund a blocked
COMMIT. Cleanup clears the archive's configuration and scratch only after the
store physically retires.

The component tests perform real SQLite writes, close/reopen, exact duplicate
replay, conflicting IDs/sequences, unknown commit recovery, ACK interruption,
page rollback at capacity, cross-tenant/source refusal, permission revocation,
original-deadline expiry and scanning the actual DB/WAL for deleted actor bytes.
The production transfer tests read the real source outbox before archive commit
and source ACK. Their control authority and restore providers are fixtures,
not deployment authentication or durability qualification.

Independently authenticated remote export,
archive access-audit workflows and other authority sources require their own
composition. An arbitrary application diagnostic callback is not this exporter;
its external copies have separate retention responsibilities.

## Automatic local maintenance

`controlv4.AuditMaintenance` explicitly enables bounded local export and expiry.
Construction retains both original stores in the same physical root and
Environment, checks their exact shared trusted clock and source/retention binding,
and requires independent export and retention permissions for each store. An
original binding permits only one live automatic maintenance service per source
and per archive. Logical Close retains that claim until every original worker
actually exits. It
never creates another store or private budget authority. Rejected construction
releases its original reservations before starting any task.

The service prepays three worker stacks/work positions and six timers: one
polling timer and one call deadline for each of export, source expiry and archive
expiry. There is exactly one synchronous operation per worker, with no queue or
replacement goroutine. Export polling is configured from 2 through 60 seconds;
retention polling from 1 through 60 seconds. The three initial turns are staggered
within the retention interval, so short expiry calls do not repeatedly collide
with every export tick. Calls have one original deadline of
at most 10 seconds. Existing store concurrency and permission-specific rate gates
still apply. A busy store refuses the current attempt; it cannot create a waiting
work item. Source and destination retention attempts have independent workers,
so a stalled exporter cannot take either worker's position. A stall in the native
store can still prevent that same store's physical deletion.

The exporter scans the current retained time range in fixed windows of at most
one day and bounded pages. A cycle fixes its upper time bound, retains original
page progress only after successful acknowledgement, and then starts a new cycle
for later records. Errors retry the same window/cursor; they do not skip records
or reset record deadlines. Export and source ACK share the source's configured
export rate bucket. This schedule bounds work; capacity, storage availability
and the record retention window determine whether all records can be exported
before expiry. Expired pending-source records retain the source's existing finite
loss counter.

A detached aggregate snapshot reports original call counts, currently running
operations, confirmed persistence/ACK observations, failures and finite last
states. Confirmations count successful observations, including an exact retry;
they are not a unique-event metric. The separately authenticated operations
handler can register this owner to include that snapshot. No actor, record,
source ID, endpoint, exception or callback is emitted.

Close cancels all three original workers and stops further polling. Actual native
calls remain occupied and charged until return; only the last worker's actual
exit completes cleanup and releases store/dependency borrows. An expired cleanup
wait leaves this original responsibility intact. Permission revocation yields a
finite refusal and does not authorize bypassing access controls for deletion.
Storage/permission failures are visible in the aggregate maintenance state and
require deployment remediation rather than an automatic privilege expansion.
