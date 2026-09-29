package rawquic

import (
	"bytes"
	"testing"
)

func TestOwnedQUICExporterBindsOriginalTLSAndArtifact(t *testing.T) {
	client, server := ownedTestPair(t)
	artifact := [32]byte{1, 9}
	left, err := client.ExportBinding(artifact)
	if err != nil {
		t.Fatal(err)
	}
	right, err := server.ExportBinding(artifact)
	if err != nil || left != right || left == ([32]byte{}) {
		t.Fatal("original peer exporters differ", err)
	}
	state, err := client.TLSState()
	if err != nil {
		t.Fatal(err)
	}
	exact, err := state.ExportKeyingMaterial("EXPORTER-flowersec-v4", artifact[:], 32)
	if err != nil || !bytes.Equal(exact, left[:]) {
		t.Fatal("raw TLS inputs changed", err)
	}
	wrong, err := state.ExportKeyingMaterial("EXPORTER-EXPORTER-flowersec-v4", artifact[:], 32)
	if err != nil || bytes.Equal(wrong, left[:]) {
		t.Fatal("double prefix not separated", err)
	}
	other, err := client.ExportBinding([32]byte{2, 9})
	if err != nil || other == left {
		t.Fatal("artifact context not bound", err)
	}
	another, _ := ownedTestPair(t)
	other, err = another.ExportBinding(artifact)
	if err != nil || other == left {
		t.Fatal("separate TLS connections reused exporter", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ExportBinding(artifact); err == nil {
		t.Fatal("closed connection retained exporter authority")
	}
}
