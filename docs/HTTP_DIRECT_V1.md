# HTTP application integration

Flowersec can carry an application's HTTP byte stream inside a current
authenticated Session. This retains HTTP keep-alive, WebSocket upgrade,
backpressure, half-close and the application's authorization boundary without
opening a separate public listening port for that stream.

The application registers its raw stream kind and, when needed, a validated
metadata codec and descriptor. Authorization sees the bounded metadata view
before the original Stream is accepted. HTTP and WebSocket bytes then pass
through that same Stream; metadata projection does not replace request-target,
user-session or password authorization.

Network connection establishment still requires the signed TLS policy. A
failed secure connection cannot silently select plaintext HTTP. An explicitly
configured browser bridge on the same machine uses the current
`local_loopback` access class described in
[PRIVATE_LOOPBACK_V1.md](PRIVATE_LOOPBACK_V1.md). It is limited to numeric
loopback and does not authorize a plaintext LAN or public listener.

For a browser proxy, use the registered ProxyServer HTTP and WebSocket kinds
and their current Session ownership. The final upstream request target is
checked by application policy; controlled Cookie sessions require explicit
scope and lifecycle configuration. For direct native HTTP embedding, use the
language's stream integration described in [API_CONTRACT.md](API_CONTRACT.md).
