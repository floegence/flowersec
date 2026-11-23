package sqlite

import (
	"context"
	"crypto/rand"
	"errors"

	flowersec "github.com/floegence/flowersec/flowersec-go/v7"
	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

// Lease binds an outbound artifact to its permanent spend marker.
func (store *Store) Lease(artifact flowersec.Artifact) (flowersec.ArtifactLease, error) {
	key := artifact.LookupKey()
	if store == nil || store.db == nil || key == "" {
		return flowersec.ArtifactLease{}, errors.New("sqlite: missing store or credential")
	}
	return flowersec.NewArtifactLease(artifact, func(ctx context.Context) error {
		return store.writeOne(ctx, "INSERT INTO client_spends (credential) VALUES (?)", key)
	})
}

// Publish persists the issuer's authorization record before the host distributes
// that credential. A previously published, consumed or revoked key is never reset.
func (store *Store) Publish(ctx context.Context, record controlplane.AuthorizationRecord) error {
	data, err := record.Encode()
	if err != nil {
		return err
	}
	return store.writeOne(ctx, "INSERT INTO admissions (credential,record) VALUES (?,?)", record.LookupKey(), data)
}

// Revoke prevents a previously published credential from being admitted. It
// does not revoke an active session or affect the peer's separately issued leg.
func (store *Store) Revoke(ctx context.Context, credential string) error {
	return store.writeOne(ctx, "UPDATE admissions SET record=NULL WHERE credential=? AND lease IS NULL", credential)
}

// AuthorizeDirect verifies the exact request and commits the admission before allow.
func (store *Store) AuthorizeDirect(ctx context.Context, req controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
	return authorize(ctx, store, req, controlplane.AuthorizeRuntime)
}

// AuthorizeTunnel performs the same admission for a single leg; only the public
// pairing and lease decision is delivered to the relay.
func (store *Store) AuthorizeTunnel(ctx context.Context, req controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error) {
	return authorize(ctx, store, req, controlplane.AuthorizeTunnelRuntime)
}

func authorize[Decision interface{ Allowed() bool }](ctx context.Context, store *Store, req controlplane.RuntimeAuthorizationRequest, verify func(controlplane.RuntimeAuthorizationRequest, controlplane.AuthorizationRecord, string) (Decision, error)) (Decision, error) {
	var zero Decision
	if store == nil || store.db == nil || ctx == nil || req.LookupKey() == "" {
		return zero, errors.New("sqlite: missing store, context or credential")
	}
	var data []byte
	key := req.LookupKey()
	if err := store.db.QueryRowContext(ctx, "SELECT record FROM admissions WHERE credential=? AND record IS NOT NULL AND lease IS NULL", key).Scan(&data); err != nil {
		return zero, err
	}
	record, err := controlplane.ParseAuthorizationRecord(data)
	if err != nil {
		return zero, err
	}
	leaseID := rand.Text()
	decision, err := verify(req, record, leaseID)
	if err != nil || !decision.Allowed() {
		return decision, err
	}
	if err := store.writeOne(ctx, "UPDATE admissions SET lease=?, record=NULL WHERE credential=? AND record=? AND lease IS NULL", leaseID, key, data); err != nil {
		return zero, err
	}
	return decision, nil
}

// ReleaseLease is idempotent for a known lease. Its credential stays consumed.
func (store *Store) ReleaseLease(ctx context.Context, leaseID string) error {
	return store.writeOne(ctx, "UPDATE admissions SET released=1 WHERE lease=?", leaseID)
}

func (store *Store) writeOne(ctx context.Context, query string, args ...any) error {
	if store == nil || store.db == nil || ctx == nil {
		return errors.New("sqlite: missing store or context")
	}
	result, err := store.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("sqlite: credential or lease unavailable")
	}
	return nil
}
