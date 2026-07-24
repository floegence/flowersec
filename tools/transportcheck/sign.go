package main

import (
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func loadEd25519PKCS8PrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect evidence signing key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("evidence signing key must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("evidence signing key must not be accessible by group or other users")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read evidence signing key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, errors.New("evidence signing key must contain exactly one unadorned PKCS#8 PRIVATE KEY block")
	}
	decoded, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("evidence signing key is not valid PKCS#8")
	}
	privateKey, ok := decoded.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("evidence signing key is not an Ed25519 private key")
	}
	return privateKey, nil
}

func requirePrivateKeyMatchesTrustStore(privateKey ed25519.PrivateKey, trustStore *EvidenceTrustStore, keyID string) error {
	if err := validateEvidenceTrustStore(trustStore); err != nil {
		return err
	}
	var trusted []byte
	for _, key := range trustStore.Keys {
		if key.KeyID == keyID {
			trusted, _ = base64.StdEncoding.DecodeString(key.PublicKey)
			break
		}
	}
	actual := privateKey.Public().(ed25519.PublicKey)
	if len(trusted) != ed25519.PublicKeySize || subtle.ConstantTimeCompare(actual, trusted) != 1 {
		return errors.New("evidence signing key does not match the repository trust store")
	}
	return nil
}

func writeNewEvidenceReport(path string, report *EvidenceReport) (err error) {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create signed evidence report: %w", err)
	}
	defer func() {
		_ = file.Close()
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return nil
}

func validateSigningPaths(input, output string) error {
	info, err := os.Lstat(input)
	if err != nil {
		return fmt.Errorf("inspect unsigned evidence report: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsigned evidence report must be a regular non-symlink file")
	}
	inputAbs, err := filepath.Abs(input)
	if err != nil {
		return err
	}
	outputAbs, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if filepath.Base(inputAbs) != "report.unsigned.json" || filepath.Base(outputAbs) != "report.json" {
		return errors.New("evidence signer requires report.unsigned.json and report.json filenames")
	}
	if filepath.Dir(inputAbs) != filepath.Dir(outputAbs) {
		return errors.New("unsigned and signed evidence reports must share one artifact directory")
	}
	if inputAbs == outputAbs {
		return errors.New("unsigned and signed evidence report paths must differ")
	}
	return nil
}
