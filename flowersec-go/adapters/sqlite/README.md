# SQLite credential and lease store

Import `github.com/floegence/flowersec/flowersec-go/adapters/sqlite/v7` only
in a host that chooses SQLite. `Create(ctx, path)` provisions a new private
database in a host-owned directory. `Open(ctx, path)` requires the existing
database. Never recreate a missing database to recover from an open error.
Use separate databases for distinct trust domains; a relay does not need the
authorizer's database or any session secrets.

| Role | Host operation |
| --- | --- |
| Client | Pass `store.Lease(artifact)` to the connector. Each copy of the same credential shares a persistent spend key. |
| Issuer | Call `store.Publish(ctx, issued.AuthorizationRecord())` before publishing `issued.ArtifactJSON()`. Publish the legs of a pair independently. |
| Direct authorizer | Set `AcceptorOptions.Authorize` to `store.AuthorizeDirect`. |
| Tunnel authorizer | Return `store.AuthorizeTunnel`'s response through the existing authorization callback or HTTP endpoint. |
| Lease owner | Call `store.ReleaseLease(ctx, id)` in `Release` or the HTTP release handler. Handle errors at this boundary; retries are idempotent. |
| Revocation | `store.Revoke(ctx, key)` invalidates an unconsumed record without touching another credential. |

Retain spent records across restarts and release. Concurrent redemption of
one credential updates at most one row; errors never form an allow response.
Use a filesystem with durable SQLite locking and synchronization. Protect the
database and its backups as secrets. This database alone cannot detect a
rollback to an earlier snapshot, fence a stale writer after restore, supply
trusted time, or revoke a running session. Deployments that require those
guarantees must enforce them through their own policy and storage before
allowing the corresponding operation.
