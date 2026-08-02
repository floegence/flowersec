package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// flowersec:race-cost=critical
func TestSignCLIProducesVerifierCompatibleImmutableReport(t *testing.T) {
	manifestPath := fixturePath(t, "performance_manifest.json")
	registryPath := fixturePath(t, "case_registry.json")
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	repositoryPath, baseSHA, finalSHA := newCleanTestRepository(t)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6d}, ed25519.SeedSize))
	trustStorePath, trustPolicyPath := writeSigningTrustFixture(t, privateKey)
	keyPath := writePKCS8PrivateKey(t, privateKey, 0o600)

	report := completeReport(t, manifest, registry)
	report.Source.BaseSHA = baseSHA
	report.Source.FinalSHA = finalSHA
	bindReportRunnerToRepository(t, report, repositoryPath, manifest, registry)
	report.Attestation = EvidenceAttestation{}
	unsignedPath := filepath.Join(report.baseDir, "report.unsigned.json")
	signedPath := filepath.Join(report.baseDir, "report.json")
	if err := os.Remove(signedPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	writeJSON(t, unsignedPath, report)

	var output bytes.Buffer
	err := run([]string{
		"sign", "-manifest", manifestPath, "-registry", registryPath,
		"-report", unsignedPath, "-output", signedPath,
		"-repo", repositoryPath, "-base-sha", baseSHA,
		"-trust-store", trustStorePath, "-trust-policy", trustPolicyPath,
		"-key-file", keyPath,
	}, &output)
	if err != nil || output.String() != "evidence signed\n" {
		t.Fatalf("sign error = %v output = %q", err, output.String())
	}
	info, err := os.Stat(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("signed report mode = %o, want 600", info.Mode().Perm())
	}

	output.Reset()
	err = run([]string{
		"evidence", "-manifest", manifestPath, "-registry", registryPath,
		"-report", signedPath, "-repo", repositoryPath, "-base-sha", baseSHA,
		"-trust-store", trustStorePath, "-trust-policy", trustPolicyPath,
	}, &output)
	if err != nil || output.String() != "evidence pass\n" {
		t.Fatalf("verify error = %v output = %q", err, output.String())
	}

	before, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	err = run([]string{
		"sign", "-manifest", manifestPath, "-registry", registryPath,
		"-report", unsignedPath, "-output", signedPath,
		"-repo", repositoryPath, "-base-sha", baseSHA,
		"-trust-store", trustStorePath, "-trust-policy", trustPolicyPath,
		"-key-file", keyPath,
	}, &output)
	if err == nil || !strings.Contains(err.Error(), "file exists") {
		t.Fatalf("second sign error = %v, want immutable output rejection", err)
	}
	after, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing signed report changed after overwrite attempt")
	}
}

func TestEvidencePrivateKeyLoaderRejectsUnsafeFiles(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4f}, ed25519.SeedSize))

	t.Run("group readable", func(t *testing.T) {
		path := writePKCS8PrivateKey(t, privateKey, 0o640)
		if _, err := loadEd25519PKCS8PrivateKey(path); err == nil || !strings.Contains(err.Error(), "group") {
			t.Fatalf("error = %v, want permissions rejection", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		target := writePKCS8PrivateKey(t, privateKey, 0o600)
		path := filepath.Join(t.TempDir(), "key.pem")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := loadEd25519PKCS8PrivateKey(path); err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("error = %v, want symlink rejection", err)
		}
	})
	t.Run("trailing data", func(t *testing.T) {
		path := writePKCS8PrivateKey(t, privateKey, 0o600)
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString("unexpected\n"); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := loadEd25519PKCS8PrivateKey(path); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("error = %v, want trailing data rejection", err)
		}
	})
}

func TestSigningPathsKeepReportWithItsArtifactTree(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "report.unsigned.json")
	if err := os.WriteFile(input, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSigningPaths(
		input,
		filepath.Join(directory, "report.json"),
	); err != nil {
		t.Fatal(err)
	}
	if err := validateSigningPaths(
		input,
		filepath.Join(t.TempDir(), "report.json"),
	); err == nil || !strings.Contains(err.Error(), "artifact directory") {
		t.Fatalf("error = %v, want cross-directory rejection", err)
	}
}

func writePKCS8PrivateKey(t *testing.T, privateKey ed25519.PrivateKey, mode os.FileMode) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeSigningTrustFixture(t *testing.T, privateKey ed25519.PrivateKey) (string, string) {
	t.Helper()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	trustStorePath := filepath.Join(t.TempDir(), "trust-store.json")
	writeJSON(t, trustStorePath, EvidenceTrustStore{
		SchemaVersion: 1,
		Keys: []TrustedEvidenceKey{{
			KeyID: "release-sign-test", PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		}},
	})
	trustStoreData, err := os.ReadFile(trustStorePath)
	if err != nil {
		t.Fatal(err)
	}
	trustStoreDigest := sha256.Sum256(trustStoreData)
	publicKeyDigest := sha256.Sum256(publicKey)
	trustPolicyDir := t.TempDir()
	trustPolicyPath := filepath.Join(trustPolicyDir, "trust-policy.json")
	runnerConfig, err := os.ReadFile(fixturePath(t, signedRunnerConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trustPolicyDir, signedRunnerConfigPath), runnerConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, trustPolicyPath, EvidenceTrustPolicy{
		SchemaVersion:    1,
		TrustStoreSHA256: hex.EncodeToString(trustStoreDigest[:]),
		KeyID:            "release-sign-test", PublicKeySHA256: hex.EncodeToString(publicKeyDigest[:]),
		Runner: EvidenceRunnerPolicy{
			ID: "flowersec-linux-release-v1", OS: "linux", Architectures: []string{"amd64", "arm64"},
			Namespace: "isolated", TrafficControl: "tc-netem-v1", PacketCounters: "ebpf-v1",
			EffectiveConfigSHA256: signedRunnerConfigDigest, EffectiveConfigPath: signedRunnerConfigPath,
		},
	})
	return trustStorePath, trustPolicyPath
}
