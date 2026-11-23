# Direct parity issuer

`parity-direct-issuer` issues production `flowersec/5` Direct artifacts for cross-language parity runs. Start the compiled binary once, keep its stdin open, and send one NDJSON request per channel. The same PID handles each request and stays idle between requests, so the harness can sample its RSS. EOF ends the process.

Build from `flowersec-go` with `go build -o parity-direct-issuer ./cmd/parity-direct-issuer`. Create a trusted parent directory for the output roles, then start the issuer:

```sh
mkdir -m 700 run
./parity-direct-issuer -url wss://listener.example/flowersec/v5/direct -tls ca \
  -audience server-parity -group cross-language-direct-parity \
  -upstream 127.0.0.1:8080 -ttl 2m -max-inbound 16 -idle 5m \
  -record-dir run/records -approval-dir run/approvals -invitation-dir run/invitations
```

Use `/flowersec/v5/direct` for WSS, `/flowersec/webtransport/v5/direct` for HTTPS WebTransport, or `quic://host:port` for raw QUIC. TLS policy is required. For a pinned leaf, pass `-tls pin -pin-sha256 <unpadded-base64url-SHA256-of-leaf-DER> -pin-not-after <Unix-seconds>` instead of `-tls ca`. The pin must be active at issuance. `-help` lists all settings.

Input example: `{"channel_id":"p123"}`. IDs accept ASCII letters, digits, `.`, `_`, `~`, and `-`, up to 128 characters. A successful response has this shape (the key shown is a placeholder):

```json
{"channel_id":"p123","lookup_key":"<lookup-key>","record_ref":"<lookup-key>.json","approval_ref":"p123.json","invitation_ref":"p123.json"}
```

Resolve each reference against its corresponding directory. The optional record is the encoded `AuthorizationRecord`, keyed by its lookup key. Approval and invitation contain identical raw artifact bytes. Only the client invitation belongs with the client. Omit `-record-dir` to skip record storage and the `record_ref` field.

Use distinct, non-nested role directories under trusted parents. Missing role directories are created `0700`; existing ones must be real directories with that mode. Use a local filesystem supporting exclusive creation, atomic hard links, and file and directory sync. Each final `0600` file appears complete and is never overwritten. The issuer syncs the optional record, then the server approval, then the invitation before writing a receipt.

Keep `approval-dir/.issuer-claims` for the full run, including across restarts and after consumers remove artifacts. The issuer reserves a channel there before generating credentials. A malformed request, duplicate, or failure ends the process with nonzero status and a diagnostic on stderr. A failed publication can leave private material or, after a crash, a staging file; consumers should open only exact final filenames. An absent receipt does not prove that no file was published. Do not resubmit that channel or delete its claim. Inspect the role directories and use a new channel for a new attempt.
The capacity driver may pass a connected Unix socket on descriptor 3 and set `FLOWERSEC_V5_ISSUER_METRICS_FD=3`. A `goroutines` line on this socket returns the current Go goroutine count. Closing the metrics socket does not issue an invitation or close the issuance input.
