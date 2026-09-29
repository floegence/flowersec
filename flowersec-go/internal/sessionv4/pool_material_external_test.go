package sessionv4_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func TestPoolMaterialDecoderAuthenticatesCompleteOriginalBundle(t *testing.T) {
	f := sessionv4.NewPoolMaterialTestHarness(t)
	c := controlv4.PoolMaterialDecoderConfig{Root: f.Root, Owner: f.Owner, Trust: f.Lease.Trust, ActivationSigningKeyID: f.Lease.ActivationSigningKeyID, MapBytes: f.Lease.MapBytes, MapNodes: f.Lease.MapNodes, RuntimeBytes: 65536, LeaseRuntimeBytes: f.Lease.RuntimeBytes}
	charge, err := controlv4.PoolMaterialDecoderCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	d, err := controlv4.NewPoolMaterialDecoder(c, f.Reserve(charge), f.Dependencies)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	bundle := controlv4.PoolMaterialBundle{Artifact: f.Lease.Artifact, Activation: f.Lease.Proof, ClientCertificate: f.Lease.ClientCertificate, ServerCertificate: f.Lease.ServerCertificate}
	buf := make([]byte, 65536)
	n, err := controlv4.EncodePoolMaterial(buf, bundle)
	if err != nil {
		t.Fatal(err)
	}
	wire := bytes.Clone(buf[:n])
	before := f.Root.Snapshot()
	for _, variant := range []string{"bad-activation-signature", "wrong-certificate-role", "missing-activation", "trailing-data"} {
		t.Run(variant, func(t *testing.T) {
			bad := bundle
			switch variant {
			case "bad-activation-signature":
				bad.Activation = bytes.Clone(bundle.Activation)
				bad.Activation[len(bad.Activation)-1] ^= 1
			case "wrong-certificate-role":
				bad.ClientCertificate, bad.ServerCertificate = bad.ServerCertificate, bad.ClientCertificate
			case "missing-activation":
				bad.Activation = []byte{0xa0}
			}
			n, err := controlv4.EncodePoolMaterial(buf, bad)
			if err != nil {
				t.Fatal(err)
			}
			if variant == "trailing-data" {
				buf[n] = 0
				n++
			}
			lease, err := d.DecodePoolLease(context.Background(), buf[:n])
			if lease != nil {
				lease.Close()
			}
			if err == nil || lease != nil {
				t.Fatal("unverified complete material accepted")
			}
			if after := f.Root.Snapshot(); after != before {
				t.Fatal("rejected bundle leaked resources", before, after)
			}
		})
	}
	lease, err := d.DecodePoolLease(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	clear(wire)
	d.Close()
	if err := d.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	sessionv4.CheckPoolMaterialTestLease(t, lease)
}
