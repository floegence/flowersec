# Migrating to Flowersec 0.27

Flowersec 0.27 removes the legacy automatic-connect compatibility surface. Upgrade callers directly to the supported artifact or explicit transport contracts. Do not add forwarding aliases, runtime fallback branches, or input-shape detection in downstream applications.

## Automatic Connections

Construct or request a `ConnectArtifact` before using an automatic connection entrypoint:

- Go `client.Connect(...)`
- TypeScript `connect(...)`
- TypeScript `connectBrowser(...)`
- TypeScript `connectNode(...)`

These entrypoints no longer accept raw tunnel grants, `{ grant_client: ... }` wrappers, direct connection info, readers, byte slices, or serialized JSON. Go callers pass `*protocolio.ConnectArtifact`; TypeScript callers pass `ConnectArtifact`.

When the transport is already known and the application intentionally holds a raw transport credential, call the corresponding explicit tunnel or direct entrypoint. Do not wrap that credential in an artificial artifact solely to select a known transport.

## Control-plane Requests

Browser applications must replace `requestChannelGrant(...)` and `requestEntryChannelGrant(...)` with `requestConnectArtifact(...)` and `requestEntryConnectArtifact(...)`. They are available from `@floegence/flowersec-core/browser` for browser-only integrations and from the canonical `@floegence/flowersec-core/controlplane` subpath.

Replace the removed browser-only `ControlplaneConfig`, `EntryControlplaneConfig`, `ConnectArtifactRequestConfig`, and `EntryConnectArtifactRequestConfig` aliases with `RequestConnectArtifactInput` or `RequestEntryConnectArtifactInput` as appropriate.

The package no longer exports `@floegence/flowersec-core/internal`. Import a documented public subpath instead. If an application depended on an internal module, migrate to the public owner of that contract rather than copying or forwarding the internal export.

## Scoped Metadata

The artifact-first change does not alter scoped metadata validation. The relaxed optional-scope validation option remains available in all four SDKs under the existing contract. Critical scopes and default optional-scope validation still fail closed.

## Verification

After migrating, search application source, tests, examples, and package metadata for removed raw automatic-connect inputs, grant helper imports, and the `./internal` subpath. Type checking must reject raw or serialized inputs passed to automatic connection entrypoints.
