# Flowersec Error Model

Public failures use closed, bounded codes. Error text and generic serialization
must not expose Artifacts, credentials, URLs, certificate pins, session keys,
carrier handles, native TLS diagnostics or peer payloads. Applications inspect
structured codes and progress rather than parsing error messages.

## Connection and lifecycle

The material source, one-shot connection and ConnectionController retain their
own failure boundaries. An unavailable source differs from an established
Session failure. Progress records irreversible spend and READY separately from
application publication. Initialization can fail after READY without publishing
a current Session.

An uncertain live authorization is terminal for that attempt. Pool consumption
and admission are not undone by cancellation or failed writes. Retrying obtains
fresh material through the original source; it never reuses a spent credential.
The Controller owns the bounded recovery scheduler. Explicit replacement can
recover from a stopped lifecycle, including when no first Session was published.
It does not replay application calls or move accepted work to a new Session.

TLS policy, namespace trust and protocol authentication failures fail closed.
A native failure is classified only when its original provider supplies the
required evidence. Browser APIs can produce less specific failures. No public
failure grants permission to downgrade security or bypass an authorization gate.

## Application operations

Transport, application, execution and delivery outcomes remain separate.
An accepted write can have partial progress before cancellation or failure;
callers use its structured result rather than assuming zero bytes were sent.
A canceled observer does not cancel the underlying operation unless the
corresponding API explicitly owns cancellation. Finish, Drain, Abort and cleanup
report distinct ownership transitions.

Typed service errors carry their declared semantic code and bounded sanitized
message. Decoder failures, unavailable execution history, operation conflicts,
expired retained results and unknown execution outcomes are explicit results;
none is permission to repeat a business action automatically. A service
contract controls any idempotent join, retained-result read or resume behavior.

Raw stream and negotiated unreliable-message errors remain carrier-neutral.
Accepted or dropped unreliable sends are outcomes rather than transport errors.
Unsupported capabilities fail before consuming connection material whenever
requirements can be determined at that boundary.

The exact code sets and result shapes are in
`stability/transport_v4_schema.json` and `stability/api_contract_manifest.json`.
See [API_CONTRACT.md](API_CONTRACT.md) and the language-specific current
transport guides for concrete APIs.
