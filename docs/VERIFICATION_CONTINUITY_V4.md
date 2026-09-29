# Go v4 verification continuity

The internal Go namespace engine supports two fixed construction paths.
`NewNamespaceOnlineBootstrap` authenticates an independent authority's fresh
nonce response and installs its complete trust/Head/State pair in memory.
`NewNamespaceDurableBootstrap` obtains the same baseline and commits its complete
verification history before delivery. `RestoreNamespace` instead requires an
empty independently configured trust anchor and a store that proves its latest
complete snapshot under the deployment's supported recovery model.

All paths use the same canonical parsers, signature verification, immutable
capacity/publication mapping, State validation, issuer impact checks, observed
high-water and active/pinned algorithms. A durable owner cannot become an online
owner when storage fails. These are internal components; public Environment
assembly and cross-SDK provider qualification remain separate obligations.

## Environment namespace ownership

`NamespaceRegistry` fixes one continuity profile and a finite table of original
trust anchors for a physical Environment budget. The resource root rejects a
second registry for that same Environment while any original registry backing
remains. Distinct Environments on the root keep distinct tables and still share
the root's aggregate resource bounds.

Registration precedes bootstrap or recovery. The exact tenant/authority pair
selects one slot; another trust anchor, key, capacity digest, URL or failed owner
cannot create a second view of that namespace. Re-registering the same anchor
is idempotent. The configured profile is checked before provider/store work or
transferring recovery buffers, and is checked again under the startup gate.
Successful startup publishes the original verified incarnation only after the
required continuity commit. Registering an existing cache or an already started
owner cannot establish this fact.

An internal Session Environment configured with `Verification` borrows this
registry. It validates every material dependency before carrier preparation and
checks the complete consumer/acceptor subscription closure at admission, before
spend/admission work. Source acquisition, static material and accepted ingress
use that same gate. Lookup returns only an independently configured original
trust anchor; a name never starts bootstrap or confers authorization. Component
test compositions may omit the registry; this omission is not a qualified public
Environment configuration.

The table retains original trust pins and exact namespace history after ordinary
close or failure. `ReplaceFailed` reuses the same namespace slot for a fresh
independently authenticated bootstrap. It copies and revalidates every original
signed trust configuration, preserves immutable capacity/publication mappings,
and verifies coverage of every retained observed frontier and complete denial
State before opening the new incarnation. An unsuccessful bootstrap cannot
remove the previous evidence; subsequent replacement checks all retained owners.
A generation change additionally requires independent permanent signer retirement.
Old subscriptions never attach to the replacement and remain terminal. Registry close atomically fences all registered trust checks
before requesting individual owner cancellation. Provider tails, subscriptions
and backing remain charged. Destruction requires the original resource
Environment to be permanently closed and every registered owner physically
retired. Entries cannot be unbound or evicted to make capacity available.

The table has a configured entry ceiling (at most 4096); each trust, complete
State/candidate, continuity buffer and refresh service retains its separately
admitted root/tenant/Environment charge. Each slot preadmits metadata for at most
16 failed incarnations, whose original full owners remain charged until actual
Environment destruction. This component does not implement conversion to compact
history or coverage-based history eviction; exhausted retained capacity refuses
further replacements or subscriptions.

## Stored facts and recovery

The private versioned record retains every accepted original TrustConfig,
the complete active State, original active/observed/pinned Heads, each Head's
original trust revision, settled work sequence, original absolute pin deadline
and consumed attempts. It contains no Session key, live operation, activation
right or execution owner. The storage format is not a wire feature.

The independently installed namespace scope binds tenant, authority, capacity
digest, trust/state capacity and fixed fetch policy. Recovery revalidates every
historical configuration's signature, mapping and monotonic constraints. An
expired historical configuration can remain evidence; the latest independent
configuration must satisfy the current trusted clock. Each Head is reverified
against its recorded configuration, preserving its original trust interval.
The complete State must match its original Head and all retained issuer impact
evidence. A digest cannot replace the State's membership and omission evidence.

An expired active pair may retain denial history, while ordinary authorization
continues to reject it until a valid complete successor is installed. Recovery
keeps the original pin deadline and attempts. Exhausted or expired work becomes
settled; a remaining pin receives only a local projection bounded by the
remaining original absolute deadline. A failed restore does not reuse the
anchor's startup position or silently open from a cache.

## Publication and ownership

Each durable namespace admits one complete snapshot buffer and one serialized
commit position. Publishers capture immutable borrows under the namespace and
trust gates, then encode and perform store I/O outside those gates. Credential
authorization pauses during the required commit. A new ordinary mutation
refuses contention; an already admitted fetch joins the existing original
commit before publishing its result. Its download deadline keeps running.

The attempt counter is durable before the provider is invoked. Trust updates,
observations, complete pair installation and work settlement use the same
atomic record. The watchdog can cancel overdue work during a store call;
pending semantic changes are committed before authorization reopens. Required
commit failure or an invalid receipt permanently fences the affected namespace
and notifies its existing subscribers. There is no retry against an assumed
commit version. A fresh replacement reads the independently proven current
snapshot and accepts only the exact acknowledged or uncertain original commit
version/digest retained by the failed owner before its new continuity commit.
This read cannot reopen the old incarnation or switch continuity profiles. A successful commit does not extend any authorization deadline.

Close cancels and fences immediately while the original store/provider tail and
verification history remain charged. History and dependency references are
released only through the existing Environment destruction gate after actual
work and subscription cleanup. This adapter does not implement history retirement
or independent reconstruction of damaged history.

## SQLite adapter

`SQLiteNamespaceHistory` uses one explicit transaction group per namespace.
One manifest and fixed 64 KiB chunks change in a single FULL-synchronous WAL
transaction. The exact manifest, schema, configured identity and limits are
checked on open. Transactions compare the complete previous revision/digest;
chunks, manifest and obsolete chunk removal commit together. A lost commit
response remains unknown. Recovery never treats an incomplete initialized file
as empty valid history.

Loads read one transaction snapshot, validate every chunk and the full digest,
and invoke the independent restoration authority before and after the read.
SQLite continuity and connection epoch fences are also checked. A checksum or
SQLite file cannot attest against its own rollback: the trusted host must supply
`NamespaceRestoreAuthority` using an independent recovery anchor or a supported
authority reconstruction procedure. The interface has no permissive default.
Backend page/disk bounds include old and new trees through actual transaction
cleanup. Storage reservations and the namespace's snapshot allocation are
separate, and both remain in the same admitted Environment.
