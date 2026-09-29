# Go v4 native connection component

`internal/sessionv4.StreamOwnership.AsConn` claims both I/O directions of one
accepted v4 Stream and returns a `net.Conn`. It does not open a listener or add
framing, transport, crypto, credit, or publication queues. This is an internal
composition component; the normal public Go connector and `ServeHTTPStream`
entry point do not yet construct this component.

Construction requires an original same-Environment reservation and fixes the
overall lifetime, Finish timeout, cleanup timeout and trusted hard deadline.
The claim excludes raw I/O, reader cursors, prepared writes, typed messages,
recovery and another connection adapter. Construction failure preserves the
original Stream. The runtime profile must cover channel, context, stack and
allocator costs in addition to the component's explicit structural charge.

The adapter admits one read, one write, one completion observer and one cleanup
observer concurrently. Excess calls return a local capacity error. The original
read gate copies directly into the caller's borrowed buffer; there is no read
prefetch task or adapter payload queue. Writes preserve the original queue's
exact locally accepted prefix. Their buffers are borrowed only until return.

`SetReadDeadline` interrupts the current read wait. Clearing or replacing it
allows subsequent reads of the original queued bytes. It does not reset the
Stream. A write deadline failure preserves the accepted prefix and aborts the
Stream. Native deadlines use one original supervisor timer; updates do not
create timer callbacks or replacement I/O tasks. Neither native deadline can
extend the trusted Stream lifetime.

`CloseWrite` seals output and observes the one original FIN. `Finish(ctx)` waits
for authenticated `DRAINED(drained)` of that same sending direction. Canceling
the wait does not reopen output or replace the close operation. The reverse
reader stays usable. The first half-close fixes the finite Finish window;
repeated calls and a later `Close` do not restart it.

`Close` synchronously fences new reads, writes and deadline updates at the
original I/O gates. A read cannot modify caller memory after the close gate;
already transferred bytes remain reported. A write keeps its already accepted
prefix and stops its unaccepted suffix. A successful `Close` return means only
that local fencing and the preadmitted lifecycle are in place.

The lifecycle preserves accepted output through the same FIN and authenticated
Finish. Its private receive drain stays within the preexisting credit window
and never publishes bytes to another handler. Once sending is drained, an open
reverse direction uses only receive `STOP`; it does not reset the successfully
finished sending half. `Result` preserves sending drain and receiving
`eof`/`abandoned` separately. Explicit `Abort`, actual I/O failure, original
revocation, parent cancellation or an expired bound uses the original Reset.

`Result`, `CleanupStatus` and `WaitCleanup` observe physical cleanup separately.
Two preadmitted workers own supervision and lifecycle waiting. An uncooperative
provider can produce `cleanup_incomplete`; its original reservation and aliases
remain occupied until the actual native call and all admitted methods exit.
Late completion monotonically becomes complete. Detached results retain only
compact direction and completion facts, with no Stream, Session, carrier or
key graph. These component checks do not qualify provider memory bounds or
public four-SDK runtime composition.

The normal termination preset can be fixed in `SessionStreamConfig` for local
opens and in the immutable raw handler registration for accepted streams. A
native adapter verifies that both directions selected its Finish timeout before
termination began. It rejects an incompatible already started window instead
of extending it. Zero connection `TimeoutMS` adds no lifetime cap; a positive
value tightens the original hard deadline. Finish and cleanup timeouts govern
ending work, not healthy keep-alive or upgrade duration.

## Native HTTP and delegated services

The internal `StartHTTPStream` and `ServeHTTPStream` components run Go's native
HTTP/1 server over the same v4 connection. They retain the 15-second header,
60-second idle and 64-KiB header defaults. They use a private one-connection
listener and open no network port. The explicit `ExternalRuntime` declaration
covers native HTTP, handler, upgrade and associated external work. Its minimum
checks do not measure or constrain arbitrary handler allocation or qualify RSS.

Native server return alone does not complete the helper. Its original compound
close owner joins authenticated sending Finish, transport cleanup, actual
HTTP callback return and native worker exit. A blocked handler keeps its input,
external execution responsibility, registration and backing charged even after
transport retirement or `cleanup_incomplete`. Cancellation records the original
abort before calling `http.Server.Close`. Hijack retains the same cancellation
and resource owner. A late cancellation cannot overwrite physical compound
completion while its publication is waiting for the supervisor.

`RawStreamHandlerConfig.HTTP` freezes a `DelegatedHTTPService` in the original
kind registry. Authorization and its target/permission setup execute on the
original ordinary executor before accepted publication. The complete HTTP,
connection and lifecycle resources are protected in the original Session and
tenant accounts before READY. Each reusable position covers the componentwise
maximum of its registered descriptors, along with original receive storage,
credit and reference positions. Cancellation and handoff share one
gate. The setup callback must physically return, including its defers, before
its ordinary permit is released and the service starts. Its old invocation
context does not become the future service context.

After handoff, native HTTP, its declared handlers and upgrades occupy the
explicit external service responsibility without retaining an ordinary running
permit. The dispatcher keeps this original registration until real compound
cleanup. HTTP and raw delegated services share the same capacity, including pending
setup, active service and closing tails; `ServiceTarget` defaults to 64 and accepts explicit values through 128.
Per-kind positions, active Stream limits, shared credit and all original root
and account capacities still apply. These internal caps are not evidence that
a deployment meets the full 64/128-service workload and resource qualification.
An ordinary raw callback that calls and waits for `ServeHTTPStream` retains its
ordinary permit for its actual duration, with normal connection sealing
supervised by the connection owner.

The normal public connector and HTTP helper still require v4 facade assembly.
Four-SDK composition and deployment workload qualification are not provided by
these internal components.

`RawStreamHandlerConfig.ControlledHTTP` reserves native parsing and I/O as a
Session service. Every actual request callback uses an ordinary executor permit
of its registered class and a fixed request timeout. That permit remains held
through the handler's real return and defers; cancellation closes the endpoint
and retains noncooperative callback backing. Idle keep-alive holds no ordinary
permit. A request cannot obtain native Hijacker or unwrap the response to bypass
execution ownership. Native upgrades remain available through the explicitly
delegated full-HTTP descriptor. A controlled descriptor can instead preadmit
`ControlledHTTPUpgradeConfig`. Its handler writes the 101 response, calls
`HTTPStreamUpgrader.BridgeUpgrade` with an exclusively transferred authorized
half-close-capable native peer and its buffered head, and returns. The two SDK
copy loops begin only after actual callback exit. Each uses one fixed 64-KiB
buffer, handles partial writes without replay and preserves both parsers' heads
in order. Original HTTP deadlines are cleared without extending the Stream's
hard lifetime. EOF half-closes only the corresponding output; final closure
still joins authenticated sending Finish. Cancellation closes the transferred
endpoint through the original service worker, and blocked native reads, writes
or Close retain the full service reservation through real exit. The declared
external runtime envelope must cover the native peer and its queues.

`SessionCoreReferenceSlots` projects the core's primary references, Environment
borrows, original service aliases and receive-pool references. Root slab and
existing registration/Environment owners are separate inputs. The constructor
rejects insufficient task, byte, reference, receive or credit capacity before
claiming the handler plan. Closing does not release a reusable position while
an actual transport, native callback or I/O observer still retains it.

Once both terminal proofs and actual flow/callback/provider cleanup are complete,
the original admission slot retains only the compact terminal and late-credit
facts. It releases the full send queue and writer backing without waiting for
RETIRE_ACK. The proof slot and used ID remain occupied until authenticated
retirement; late STOP/STOPPED/DRAINED and credit are checked against the same
immutable terminal and monotonic credit knowledge. A shared carrier's logical
association closes at this original cleanup gate. A native association still
requires its provider's actual closure report. This lets a completed delegated
service reuse its prepaid position without taking new root reference slots.

`RawStreamHandlerConfig.Delegated` freezes a `DelegatedStreamService` for a
third-party raw protocol. Its ordinary setup returns one finite, explicitly
accounted external Serve function. That function receives the original narrow
`net.Conn` and a service cancellation context, and uses its unchanged protocol
bytes. Its nil return closes the connection through the original FIN/Finish
owner; actual failure or panic aborts that same owner. Neither return nor bare
Close proves business success. Panics are represented by a fixed local error
without formatting their values.

The external runtime declaration must cover Serve, its allocations and all
associated descendants; its return must join that work. Hidden goroutines are
not made bounded or stoppable by declaration. Original connection failures
cancel the external Serve context, but noncooperative work retains its charges
and original registration through physical exit. An explicit service age is
fixed before setup and acceptance, never restarted by delayed handoff.
