# API Change Policy

Flowersec exposes one current transport and application contract through four
SDKs. Public names describe application ownership rather than wire revisions.

## Contract sources

The current wire allocation is `stability/transport_v4_schema.json`; its source
binding, review status and provider qualification are described in
[TRANSPORT_V4_BINDING.md](TRANSPORT_V4_BINDING.md). The shared vectors under
`testdata/transport_v4/` and Unicode 15.1 data under `testdata/unicode15_1/`
exercise that allocation. `stability/api_contract_manifest.json` records the
public language surfaces. [API_CONTRACT.md](API_CONTRACT.md) describes the
application-facing behavior.

A machine declaration, source test or generated vector does not establish
runtime support. Carrier, deployment and interoperability claims require the
original native provider, authenticated material and applicable runtime checks.
Changing a declaration alone cannot promote an unsupported deployment.

## Review requirements

- Keep public errors bounded and free of credential, carrier and native details.
- Preserve independently configured trust, immutable authorization and original
  resource ownership at every admission and publication boundary.
- Preserve the once-only spend and admission transitions. Cancellation,
  uncertain authorization and session replacement never authorize credential
  reuse or automatic replay of business operations.
- Preserve typed unary, streaming, notifications, raw streams, HTTP integration,
  proxy and service lifecycle behavior when changing shared abstractions.
- Keep current Unicode, encoding, signature, cipher, framing and resource
  vectors synchronized across the SDKs.
- Separate source availability, provider qualification and verified support in
  documentation and capability declarations.

A feature commit runs `make precommit`. The complete main tip is pushed with
`scripts/push-main.sh`, which runs `make test` once. `make check`, browser
compatibility, nightly, privileged diagnostics and performance are separate
engineering workflows. Release performs publication and registry readback and
runs no tests.
