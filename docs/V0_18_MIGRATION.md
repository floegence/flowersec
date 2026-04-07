# Flowersec v0.18 Migration

This guide summarizes the compatibility changes and the preferred migration path for Flowersec v0.18.x.

## Recommended migration path

Move new integrations to:

1. canonical `ConnectArtifact`
2. artifact-aware browser/controlplane helpers
3. preset manifests instead of named proxy profiles

## Intentional breaking changes

### Connect input tightening

These now fail fast:

- hybrid direct+tunnel inputs
- legacy raw/wrapper inputs mixed with artifact-only fields
- client-facing `grant_server` / server-role raw inputs
- `token` / `role` auto-detect shortcuts

### Observer semantics

Observer callbacks no longer control connect success.

If user callbacks throw, panic, or block:

- connect success/failure semantics stay unchanged
- diagnostics remain best-effort

### Strict API cleanup

New strict APIs no longer accept `0 == default`.

This applies to:

- `ConnectArtifact`
- scoped metadata
- preset manifests
- new artifact/reconnect helper options

Legacy proxy wire compatibility stays unchanged:

- `timeout_ms`: `omit == 0 == server default`

### Profile to preset migration

Stable replacement:

- preset manifests
- gateway `proxy.preset_file`
- TS/Go preset helpers

Deprecated compatibility:

- named proxy profile helpers
- gateway `proxy.profile`

## CLI migration

New artifact-aware flows:

- `flowersec-channelinit --format artifact`
- `flowersec-channelinit --server-grant-out ...`
- `flowersec-directinit --format artifact`

Legacy stdout behavior remains available during the migration window.

## Frontend migration

Before:

- `requestChannelGrant(...)`
- `connectBrowser(grant)`

Preferred now:

- `requestConnectArtifact(...)`
- `connectBrowser(artifact)`
- `createBrowserReconnectConfig({ artifactControlplane: ... })`

## Controlplane migration

Preferred controlplane output:

- return `connect_artifact`

Still supported compatibility edges:

- raw `grant_client`
- wrapper-based legacy consumers

## What did not change

- `ChannelInitGrant`
- raw grant path
- wrapper path
- raw direct path
- `requestChannelGrant(...)`
- `requestEntryChannelGrant(...)`
- direct server APIs
