# Local browser bridge

The current transport supports explicitly signed `local_loopback` access for
an application-authenticated browser bridge on the same machine. It uses the
same Flowersec session authentication, single-use admission, encryption,
streams and service protocol as other access classes.

## Admission boundary

The signed route selects a WebSocket endpoint at `/flowersec/v4/local` with
subprotocol `flowersec.local.v4`. The endpoint uses a canonical numeric
loopback address and explicit port. The Origin must be the exact corresponding
HTTP origin. Host, remote address, route and Origin checks precede upgrade,
and the application must authorize the request before admission.

The application owns bridge tokens and user authentication. Flowersec neither
issues that application token nor treats a same-origin request as authenticated
by itself. Public network listeners must reject local-loopback authority.
Host-instance binding is available only when the configured host can provide
its actual guarantee; an ordinary application-origin deployment does not
implicitly claim it.

## Connection ownership

Independent namespace trust, original identity, activation, durable spend and
admission remain required. A loopback route cannot supply its own trust root
or bypass the signed candidate and lifetime limits. The connection reports
consumer TLS verification as not applicable; a requirement for consumer TLS
verification rejects this route before acquisition. It never claims that
plaintext WebSocket completed TLS.

Closing, Drain, session replacement, cancellation and cleanup retain the same
bounded ownership semantics. Applications register their current stream and
service handlers once through the Session or Serve plan. The bridge does not
introduce an alternate application protocol or a second retry scheduler.

This access class does not authorize remote addresses, DNS hosts, tunnels,
QUIC or WebTransport. Runtime availability is determined by the current SDK's
configured provider and tested deployment profile. See
[TRANSPORT_V4_BINDING.md](TRANSPORT_V4_BINDING.md) and the language-specific
current transport guides.
