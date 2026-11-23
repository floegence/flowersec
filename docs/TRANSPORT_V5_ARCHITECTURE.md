# Flowersec transport architecture

Flowersec 7 endpoints speak `flowersec/5`. An application obtains an invitation,
opens a session, and uses its RPC or byte stream API. The invitation determines
whether the connection goes directly to a service or through a tunnel. See the
[SDK contracts](API_CONTRACT.md) for the public interfaces and the
[wire contract](TRANSPORT_V5_WIRE.md) for the exact encodings.

## Direct connections

The issuer binds the endpoint address and TLS policy into the invitation. The
connector selects an eligible carrier, verifies its peer according to that
policy, and durably commits the invitation lease before sending credentials.
The listener checks the admission against its authoritative record and the
listener that received it. After admission and the end-to-end handshake, the
accepting service and the connecting application each have a session.

## Tunnel connections

Each endpoint receives its own invitation and connects only to an ingress
authorized for its role. With the Go issuer, use `TunnelIssueOptions.Endpoints`
for a shared ingress configuration, or set both `FirstEndpoints` and
`SecondEndpoints` for separate configurations. Their addresses and TLS policies
can be completely disjoint. An endpoint does not need the other endpoint's
address or a list of intermediate relays.

A single relay can accept both connections. A deployment with multiple ingress
nodes can forward the two legs to one pairing service using distinct listener
bindings. The pairing service checks each leg against its own authorization
record and ingress. It pairs complementary roles only when their trusted
authority scope, logical audience, rendezvous group, channel and session
contract match and their endpoint identities name each other. The digest of
the candidate set authenticates one leg; it need not match the other leg's
digest.

The two endpoints authenticate each other and encrypt application traffic end
to end. Relays forward it without receiving the session keys or running RPC
handlers. Closing the session releases its leases. It does not make either
invitation reusable.

## Application traffic and storage

RPC streams open on first use. Applications can call a known authorized method
without first requesting a method list. Limits on concurrent work and buffered
bytes protect the session; registering methods or completing calls does not
consume a lifetime quota. Closing a connection does not migrate streams or
replay calls. A connection controller can acquire a fresh lease to reconnect.

The host supplies durable storage to the issuance and admission paths that
require it. It may use its own store or explicitly select a SQLite adapter.
Concurrent attempts to consume the same credential can succeed at most once.
An uncertain commit cannot authorize a retry with that credential. Applications
do not pass storage handles to `Call` or to individual stream operations.
