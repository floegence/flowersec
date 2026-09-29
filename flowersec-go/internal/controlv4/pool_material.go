package controlv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// PoolMaterialBundle is the reference application's pool-material-1 format:
// a canonical CBOR array of four byte strings and an optional ordered tunnel
// material set. A single Grant/relay pair may be supplied directly. Each string is
// the complete original signed map. The entire array must fit in 65536 bytes.
// This is an explicit control-application binding, not an L0 wire map, key
// locator, lease wrapper, or authority to trust the enclosed signing keys.
type PoolMaterialBundle struct {
	Tunnels                                                    []PoolTunnelMaterial
	Artifact, Activation, ClientCertificate, ServerCertificate []byte
	Grant, RelayCertificate                                    []byte
}

func EncodePoolMaterial(dst []byte, b PoolMaterialBundle) (int, error) {
	return encodePoolMaterialSet(dst, b)
}

type PoolMaterialDecoderConfig struct {
	// New set bundles verify only this endpoint role. Remote-only trust is not required.
	Role                            protocolv4.Direction
	MaxTunnelMaterials              uint8
	TunnelTrust                     []PoolTunnelTrust
	Root                            *resourcev4.Root
	Owner                           resourcev4.OwnerKey
	Accounts                        []resourcev4.Account
	Trust                           [3]*protocolv4.NamespaceTrustStore
	GrantTrust, RelayTrust          *protocolv4.NamespaceTrustStore
	ActivationSigningKeyID          string
	MapBytes, MapNodes              int
	RuntimeBytes, LeaseRuntimeBytes uint64
}

// PoolMaterialDecoder verifies each complete lease against independently
// installed namespace trust, including the original activation authority.
// Every returned lease has its own full reservation and dependency borrow;
// closing the decoder cannot destroy leases already transferred to the pool.
type PoolMaterialDecoder struct {
	mu                                sync.Mutex
	config                            PoolMaterialDecoderConfig
	tunnelTrust                       [sessionv4.MaxLeaseTunnelMaterials]PoolTunnelTrust
	accounts                          [8]resourcev4.Account
	reservation, shared, dependencies resourcev4.Reference
	decoder                           *protocolv4.Decoder
	leaseCharge                       resourcev4.Vector
	serial                            uint64
	done                              chan struct{}
	busy, closed, cleaned             bool
}

func PoolMaterialDecoderCharge(c PoolMaterialDecoderConfig) (resourcev4.Vector, error) {
	if c.Root == nil || len(c.Accounts) > 8 || len(c.ActivationSigningKeyID) == 0 || len(c.ActivationSigningKeyID) > 128 || c.RuntimeBytes == 0 || c.Role > protocolv4.ServerToClient || c.MaxTunnelMaterials > 16 || len(c.TunnelTrust) > sessionv4.MaxLeaseTunnelMaterials {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if err := validatePoolTunnelTrust(c.TunnelTrust); err != nil {
		return resourcev4.Vector{}, err
	}
	for _, trust := range c.Trust {
		if trust == nil {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	if _, err := sessionv4.ArtifactLeaseCharge(c.MapBytes, c.MapNodes, c.LeaseRuntimeBytes, max(1, int(c.MaxTunnelMaterials))); err != nil {
		return resourcev4.Vector{}, err
	}
	backing, err := protocolv4.DecoderBackingBytes(65536, poolMaterialNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolMaterialDecoder{})) + backing + 128 + 16*uint64(unsafe.Sizeof(sessionv4.ArtifactLeaseTunnelBytes{})), resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewPoolMaterialDecoder(c PoolMaterialDecoderConfig, reservation, dependencies resourcev4.Reference) (*PoolMaterialDecoder, error) {
	cost, err := PoolMaterialDecoderCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		shared.Release()
		return nil, err
	}
	c.ActivationSigningKeyID = strings.Clone(c.ActivationSigningKeyID)
	d := &PoolMaterialDecoder{config: c, reservation: owned, shared: shared, dependencies: dependencies, done: make(chan struct{})}
	copy(d.tunnelTrust[:], c.TunnelTrust)
	d.config.TunnelTrust = d.tunnelTrust[:len(c.TunnelTrust):len(c.TunnelTrust)]
	n := copy(d.accounts[:], c.Accounts)
	d.config.Accounts = d.accounts[:n:n]
	d.decoder, err = protocolv4.NewDecoder(65536, poolMaterialNodes)
	if err != nil {
		d.Close()
		return nil, err
	}
	d.leaseCharge, err = sessionv4.ArtifactLeaseCharge(c.MapBytes, c.MapNodes, c.LeaseRuntimeBytes, max(1, int(c.MaxTunnelMaterials)))
	if err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func (d *PoolMaterialDecoder) DecodePoolLease(ctx context.Context, wire []byte) (lease *sessionv4.ArtifactLease, err error) {
	if d == nil || ctx == nil || len(wire) == 0 || len(wire) > 65536 {
		return nil, resourcev4.ErrConfiguration
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, resourcev4.ErrClosed
	}
	if d.busy {
		d.mu.Unlock()
		return nil, ErrBusy
	}
	if err = d.reservation.Check(); err == nil {
		err = d.shared.Check()
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		d.mu.Unlock()
		return nil, err
	}
	if d.serial == math.MaxUint64 {
		d.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	d.serial++
	var seed [56]byte
	copy(seed[:16], "pool-material-1")
	copy(seed[16:32], d.config.Owner.Instance[:])
	copy(seed[32:48], d.config.Owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], d.serial)
	digest := sha256.Sum256(seed[:])
	owner := d.config.Owner
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	ref, err := d.config.Root.Reserve(owner, d.leaseCharge, d.config.Accounts...)
	if err != nil {
		d.mu.Unlock()
		return nil, err
	}
	d.busy = true
	c, decoder, dependencies := d.config, d.decoder, d.dependencies
	d.mu.Unlock()
	defer func() {
		ref.Release()
		d.mu.Lock()
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = d.reservation.Check()
		}
		if err == nil {
			err = d.shared.Check()
		}
		if err == nil && d.closed {
			err = resourcev4.ErrClosed
		}
		if err != nil {
			lease.Close()
			lease = nil
		}
		d.busy = false
		d.cleanupLocked()
		d.mu.Unlock()
	}()
	doc, err := decoder.DecodeShape(wire, "", protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer doc.Release()
	bundle, tunnels, err := decodePoolMaterialSet(doc, c)
	if err != nil {
		return nil, err
	}
	return sessionv4.NewArtifactLeaseFromBytes(sessionv4.ArtifactLeaseBytesConfig{Artifact: bundle.Artifact, Proof: bundle.Activation,
		ClientCertificate: bundle.ClientCertificate, ServerCertificate: bundle.ServerCertificate,
		Grant: bundle.Grant, RelayCertificate: bundle.RelayCertificate, GrantTrust: c.GrantTrust, RelayTrust: c.RelayTrust, Tunnels: tunnels,
		Source: "preauthorized_pool", ActivationSigningKeyID: c.ActivationSigningKeyID, Trust: c.Trust,
		MapBytes: c.MapBytes, MapNodes: c.MapNodes, RuntimeBytes: c.LeaseRuntimeBytes}, ref, dependencies)
}

func (d *PoolMaterialDecoder) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	d.cleanupLocked()
}
func (d *PoolMaterialDecoder) cleanupLocked() {
	if !d.closed || d.busy || d.cleaned {
		return
	}
	d.config = PoolMaterialDecoderConfig{}
	d.decoder = nil
	d.accounts = [8]resourcev4.Account{}
	clear(d.tunnelTrust[:])
	d.dependencies = resourcev4.Reference{}
	d.shared.Release()
	d.reservation.Release()
	d.shared, d.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	d.cleaned = true
	close(d.done)
}
func (d *PoolMaterialDecoder) WaitCleanup(ctx context.Context) error {
	if d == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-d.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ sessionv4.PoolLeaseDecoder = (*PoolMaterialDecoder)(nil)
