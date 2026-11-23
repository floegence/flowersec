# Static WebSocket Tunnel Ingress

Two ingress nodes can forward the two legs to one Flowersec pairing process.
The client dials A and the server dials B. Each node forwards TCP unchanged;
TLS, `flowersec/5` admission and pairing run at M. Only the business endpoints establish
the end-to-end Flowersec session. Neither ingress needs invitation material,
TLS keys or a route to the other ingress.

On Linux with `systemd-socket-activate` and `systemd-socket-proxyd`, start one
foreground process per ingress. For example, with A, M and B on three hosts:

```sh
# On A (10.10.1.1):
sh run-wss-ingress.sh 10.10.1.1:8443 10.10.1.2:9443

# On B (10.10.1.3):
sh run-wss-ingress.sh 10.10.1.3:8443 10.10.1.2:9444
```

At M, bind the listener on port 9443 to A's public WSS candidate and the
listener on port 9444 to B's. Both use the same trusted pairing scope and
logical audience. Configure each TLS listener with a certificate satisfying
its public candidate's CA or pin policy. Restrict each backend port to its
corresponding ingress. Admission checks the candidate in the authoritative
record against the binding of the listener that accepted the socket. A request
field, HTTP Host header or TLS SNI cannot establish this binding.

Issue one pair with `IssueTunnelPair`: authorize only A's public URL for the
client and only B's public URL for the server. Keep M's private addresses out
of both credentials. A single-node deployment may use the same authorized
endpoint on both legs.

To verify the topology, observe the independent A, M and B processes while
both endpoints exchange RPC and stream data in both directions. Stop M, then
attempt a fresh round trip on the same session: it must not succeed. Check
separately that the wrong listener, a mismatched peer identity and reuse of a
consumed credential deny admission or pairing. Count all live product PIDs
for A, M and B in the same RSS sample as the endpoints. This TCP configuration
does not forward QUIC or WebTransport datagrams.
