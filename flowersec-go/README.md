# flowersec-go

This module contains the Go implementation of the Flowersec data-plane protocol stack:

- Tunnel attach (pair endpoints and forward bytes)
- End-to-end encryption (E2EE record layer)
- Yamux multiplexing
- RPC routing by `type_id`

Status: experimental; not audited.

Prerequisite: Go 1.25.x.

## Install (Go library)

```bash
go get github.com/floegence/flowersec/flowersec-go@latest
# Or pin a version:
go get github.com/floegence/flowersec/flowersec-go@v0.2.0
```

Versioning note: repository tags for this submodule are prefixed with `flowersec-go/` (for example, `flowersec-go/v0.2.0`).

## Install (tunnel binary)

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-tunnel@latest
# Or pin a version:
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-tunnel@v0.2.0
```

## Install (controlplane helper tools, optional)

These tools are intended for local development and demos (keep private keys secret):

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-issuer-keygen@latest
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-channelinit@latest
```

No-Go option: download `flowersec-tools_X.Y.Z_<os>_<arch>.tar.gz` (or `.zip`) from the GitHub Release and run the binaries from `bin/`.

## Recommended entrypoints

- Client (role=client): `github.com/floegence/flowersec/flowersec-go/client`
- Server endpoint (role=server): `github.com/floegence/flowersec/flowersec-go/endpoint`
- Server stream runtime: `github.com/floegence/flowersec/flowersec-go/endpoint/serve`
- RPC (router/server/client): `github.com/floegence/flowersec/flowersec-go/rpc`
- JSON framing helpers (advanced): `github.com/floegence/flowersec/flowersec-go/framing/jsonframe`
- Input JSON helpers: `github.com/floegence/flowersec/flowersec-go/protocolio`

For a full integration walkthrough, see `docs/INTEGRATION_GUIDE.md` in the repository root.

For tunnel deployment details (Docker examples, operational notes), see `docs/TUNNEL_DEPLOYMENT.md` in the repository root.
