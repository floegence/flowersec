package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// The physical database approval and the external settlement approval are
// separately signed inputs. A database digest cannot prove that old work has
// stopped, and opening a history never renews its admission windows.
type directExecutionContinuity struct {
	physical  *runtimeHistory
	service   ledgerv4.SQLiteExecutionService
	authority string
	notAfter  uint64
	clock     *timev4.Clock
}

func (p *directExecutionContinuity) CheckExecutionHistory(identity ledgerv4.SQLiteIdentity, service ledgerv4.SQLiteExecutionService, epoch uint64, create bool) error {
	if p == nil || service != p.service || p.authority == "" {
		return ledgerv4.ErrOwner
	}
	if err := p.physical.Check(identity, epoch, create); err != nil {
		return err
	}
	now, err := p.clock.Sample()
	if err != nil {
		return err
	}
	if !now.ValidBefore(p.notAfter) {
		return ledgerv4.ErrFenced
	}
	return nil
}

type directDurableHistory struct {
	backing  *ledgerv4.SQLiteBacking
	store    *ledgerv4.SQLiteExecutions
	original *rpcv4.DurableExecutions
	retired  bool
}

func (h *directDurableHistory) cleanup(ctx context.Context) error {
	if h.original != nil {
		h.original.Close()
		if !h.original.CleanupComplete() {
			return cryptov4.ErrTransition
		}
	}
	if h.store != nil && !h.retired {
		h.store.Close()
		if err := h.store.WaitCleanup(ctx); err != nil {
			return err
		}
		if err := h.store.Retire(); err != nil {
			return err
		}
		h.retired = true
	}
	// Persistent files retain their original storage charge until an explicit
	// host removal. Shutdown seals the backing and does not erase history.
	if h.backing != nil {
		h.backing.Close()
	}
	return nil
}
func (r *directRuntime) installDurableHistory(spec directExecutionSpec) (rpcv4.ServiceBinding, error) {
	var binding rpcv4.ServiceBinding
	installation := spec.Durable
	service := ledgerv4.SQLiteExecutionService{Tenant: spec.Service.Tenant, Audience: spec.Service.Audience, Namespace: spec.Service.Namespace}
	physical, err := r.host.verifyHistory(installation.Store)
	if err != nil {
		return binding, err
	}
	approval := installation.Continuity
	if approval.Identity != installation.Store.Identity || approval.Service != service || approval.Epoch != installation.Store.History.Epoch || len(approval.DatabaseDigest) != 32 || !bytesEqualRuntime(approval.DatabaseDigest, installation.Store.History.DatabaseDigest) || !approval.WorkFenced || approval.Authority == "" || len(approval.Authority) > 128 || len(installation.ContinuityKey) != ed25519.PublicKeySize || len(approval.Signature) != ed25519.SignatureSize {
		return binding, ledgerv4.ErrOwner
	}
	signing := struct {
		Domain             string
		Identity           ledgerv4.SQLiteIdentity
		Service            ledgerv4.SQLiteExecutionService
		Epoch              uint64
		DatabaseDigest     []byte
		PreviousWorkFenced bool
		Authority          string
		NotAfterMS         uint64
	}{"flowersec-runtime-execution-continuity-1", approval.Identity, approval.Service, approval.Epoch, approval.DatabaseDigest, approval.WorkFenced, approval.Authority, approval.NotAfterMS}
	message, err := json.Marshal(signing)
	if err != nil {
		return binding, err
	}
	if !ed25519.Verify(ed25519.PublicKey(installation.ContinuityKey), message, approval.Signature) {
		return binding, ledgerv4.ErrOwner
	}
	proof := &directExecutionContinuity{physical: physical, service: service, authority: approval.Authority, notAfter: approval.NotAfterMS, clock: r.host.clock}
	if err = proof.CheckExecutionHistory(approval.Identity, service, approval.Epoch, installation.Store.History.Provision); err != nil {
		return binding, err
	}
	methods := make([]ledgerv4.SQLiteExecutionMethod, 0, len(r.methods))
	for _, method := range r.methods {
		if method.policy.Namespace == service.Namespace && method.policy.Semantics == 1 && method.policy.ExecutionMode == 1 {
			methods = append(methods, ledgerv4.SQLiteExecutionMethod{Type: method.policy.Type, Shape: method.shape})
		}
	}
	if len(methods) == 0 {
		return binding, errors.New("durable history requires an original method in its exact namespace")
	}
	sort.Slice(methods, func(i, j int) bool { return methods[i].Type < methods[j].Type })
	for i := 1; i < len(methods); i++ {
		if methods[i-1].Type == methods[i].Type {
			return binding, ledgerv4.ErrConfiguration
		}
	}
	history := &directDurableHistory{}
	r.durableHistories = append(r.durableHistories, history)
	cost, err := ledgerv4.SQLiteBackingCharge(installation.Store.Limits)
	if err != nil {
		return binding, err
	}
	ref, _, err := r.host.reserve(cost)
	if err != nil {
		return binding, err
	}
	history.backing, err = ledgerv4.NewSQLiteBacking(installation.Store.Path, installation.Store.Limits, ref, r.host.environment)
	ref.Release()
	if err != nil {
		return binding, err
	}
	config := ledgerv4.SQLiteExecutionConfig{Root: r.host.root, Owner: r.host.owner, Accounts: r.host.accounts, Clock: r.host.clock, Service: service, CallerAuthorities: spec.CallerAuthorities, Methods: methods, Active: spec.Active, ContractNodes: r.config.Services.RPC.Routes.ContractNodes, WorkRuntimeBytes: spec.WorkRuntimeBytes}
	cost, err = ledgerv4.SQLiteExecutionsCharge(installation.Store.Limits, config)
	if err != nil {
		return binding, err
	}
	ref, owner, err := r.host.reserve(cost)
	if err != nil {
		return binding, err
	}
	config.Owner = owner
	if installation.Store.History.Provision {
		history.store, err = ledgerv4.CreateSQLiteExecutions(r.context, history.backing, installation.Store.Identity, proof, config, ref, r.host.environment)
	} else {
		history.store, err = ledgerv4.OpenSQLiteExecutions(r.context, history.backing, installation.Store.Identity, proof, config, ref, r.host.environment)
	}
	ref.Release()
	if err != nil {
		return binding, err
	}
	guard := func() error { return r.context.Err() }
	revision := uint64(0)
	for index := range r.methods {
		method := &r.methods[index]
		policy := method.policy
		if policy.Namespace != service.Namespace || policy.Semantics != 1 || policy.ExecutionMode != 1 {
			continue
		}
		if installation.Store.History.Provision {
			if len(method.spec.AdmissionOffers) == 0 {
				return binding, errors.New("new durable history requires explicitly configured original admission windows")
			}
			revision, err = history.store.InstallContract(r.context, revision, method.wire, method.spec.AdmissionOffers, true, guard)
			if err != nil {
				return binding, err
			}
		} else if len(method.spec.AdmissionOffers) != 0 {
			return binding, errors.New("reopened durable history reads original windows; new admission windows require an explicit registration workflow")
		}
		var wire [8192]byte
		registration, err := history.store.ReadRegistration(r.context, policy.Digest, wire[:], guard)
		if err != nil {
			return binding, err
		}
		if !registration.Enabled || !bytesEqualRuntime(wire[:registration.ContractBytes], method.wire) {
			return binding, ledgerv4.ErrExecutionContract
		}
		method.offers = append(method.offers, registration.Offers[:registration.OfferCount]...)
	}
	adapter := rpcv4.DurableExecutionConfig{Root: r.host.root, Owner: r.host.owner, Accounts: r.host.accounts, Clock: r.host.clock, Service: spec.Service, Store: history.store, Active: spec.Active, TaskCharge: r.executor.TaskCharge(), RuntimeBytes: spec.RuntimeBytes, WorkRuntimeBytes: spec.WorkRuntimeBytes}
	cost, err = rpcv4.DurableExecutionsCharge(adapter)
	if err != nil {
		return binding, err
	}
	ref, owner, err = r.host.reserve(cost)
	if err != nil {
		return binding, err
	}
	adapter.Owner = owner
	history.original, err = rpcv4.NewDurableExecutions(adapter, ref)
	ref.Release()
	if err != nil {
		return binding, err
	}
	return rpcv4.ServiceBinding{Authority: rpcv4.ServiceAuthority(spec.Service), DurableHistory: history.original}, nil
}
