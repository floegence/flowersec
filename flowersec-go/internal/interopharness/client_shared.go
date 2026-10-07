package interopharness

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PrepareMaterial creates untouched local attempt inputs in the same original
// root, clock, installed namespaces and Environment. It never acquires from a
// source, spends a SQLite record, dials or issues material. The caller has
// independently installed this complete signed material before preparation.
func (c *Client) PrepareMaterial(ctx context.Context, material Material, origin string, handlers HandlerConfig) (*Client, error) {
	if c == nil || c.Runtime == nil || ctx == nil {
		return nil, errors.New("original client Environment is required")
	}
	reporter, err := c.Runtime.Reporter.ForkAuthority()
	if err != nil {
		return nil, err
	}
	result, err := construct(reporter, func() *Client {
		if err := ctx.Err(); err != nil {
			reporter.Fatal(err)
		}
		h := *c.Runtime.Authority
		h.Reserve = func(v resourcev4.Vector, accounts ...resourcev4.Account) resourcev4.Reference {
			reference, err := h.Root.Reserve(h.Owner(), v, accounts...)
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Cleanup(reference.Release)
			return reference
		}
		if h.Pool == nil {
			reporter.Fatal("current shared pool inputs are required")
		}
		pool := *h.Pool
		h.Pool = &pool
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			reporter.Fatal(err)
		}
		limit := h.Root.Snapshot().Limit
		limit[resourcev4.Sessions] = 1
		scope, err := h.Root.Account(resourcev4.AccountKey{Kind: resourcev4.SessionAccount, ID: id}, limit)
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Cleanup(scope.Close)
		h.Scope[0].Session = scope
		spendCharge, err := ledgerv4.SQLitePoolSpendCharge(4096)
		if err != nil {
			reporter.Fatal(err)
		}
		// The durable store is shared; its per-attempt consume workspace is
		// exclusively owned and moves once into the original admission.
		h.Pool.Consume = h.Reserve(spendCharge, h.Scope[0].Tenant, h.Scope[0].Session)
		config := fs.ArtifactLeaseBytesConfig{Artifact: material.Artifact, Proof: material.Activation, ClientCertificate: material.ClientCertificate, ServerCertificate: material.ServerCertificate, Source: material.Source, ActivationSigningKeyID: material.ActivationSigningKeyID, MapBytes: 65536, MapNodes: 4096, RuntimeBytes: 65536}
		h.UseEngineeringPeerMaterial(reporter, config, [32]byte(material.IdentitySeed), [32]byte(material.DHSeed), protocolv4.ClientToServer)
		deadline, err := timev4.NewAge(h.Clock, reporter.operationMS(10000), h.Admission[0].Core.Session.SessionNotAfterMS)
		if err != nil {
			reporter.Fatal(err)
		}
		h.Admission[0].Initial.Deadline = deadline
		h.Generation = fs.MaterialGeneration{Source: [16]byte(material.Generation.Source), Generation: material.Generation.Generation}
		runtime := &Runtime{Reporter: reporter, Authority: &h, Executor: c.Runtime.Executor, PoolSpend: &ledgerv4.PoolSpendObservation{}}
		h.Pool.Observation = runtime.PoolSpend
		if err = runtime.initialize(ctx, []uint8{0}, handlers, c.Runtime.Environment); err != nil {
			reporter.Fatal(err)
		}
		address, kind, _, err := directRoute(material.Route)
		if err != nil {
			reporter.Fatal(err)
		}
		prepared := &Client{Runtime: runtime, Material: material, Kind: kind}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(c.TrustPEM)) {
			reporter.Fatal("original deployment trust roots are missing")
		}
		if err = prepared.prepareCarrier(ctx, address, roots, origin); err != nil {
			reporter.Fatal(err)
		}
		prepared.TrustPEM = c.TrustPEM
		return prepared
	})
	if err != nil {
		err = errors.Join(err, reporter.Close())
	}
	return result, err
}
