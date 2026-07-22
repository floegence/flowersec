package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
)

func loadEvidenceTrustStore(path string) (*EvidenceTrustStore, error) {
	var trustStore EvidenceTrustStore
	if err := decodeStrictFile(path, &trustStore); err != nil {
		return nil, err
	}
	if err := validateEvidenceTrustStore(&trustStore); err != nil {
		return nil, err
	}
	return &trustStore, nil
}

func validateEvidenceTrustStore(trustStore *EvidenceTrustStore) error {
	if trustStore == nil {
		return errors.New("evidence trust store is missing")
	}
	if trustStore.SchemaVersion != 1 {
		return fmt.Errorf("evidence trust store schema_version = %d, want 1", trustStore.SchemaVersion)
	}
	if len(trustStore.Keys) == 0 {
		return errors.New("evidence trust store has no trusted keys")
	}
	seen := make(map[string]struct{}, len(trustStore.Keys))
	for _, key := range trustStore.Keys {
		if strings.TrimSpace(key.KeyID) == "" {
			return errors.New("evidence trust store contains an empty key_id")
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			return fmt.Errorf("evidence trust store contains duplicate key_id %q", key.KeyID)
		}
		seen[key.KeyID] = struct{}{}
		decoded, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return fmt.Errorf("trusted evidence key %q has an invalid Ed25519 public key", key.KeyID)
		}
		if err := validateTrustedEd25519PublicKey(decoded); err != nil {
			return fmt.Errorf("trusted evidence key %q has a weak Ed25519 public key: %w", key.KeyID, err)
		}
	}
	return nil
}

func validateTrustedEd25519PublicKey(publicKey []byte) error {
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return errors.New("invalid point encoding")
	}
	if !bytes.Equal(point.Bytes(), publicKey) {
		return errors.New("non-canonical point encoding")
	}
	cofactored := new(edwards25519.Point).MultByCofactor(point)
	if cofactored.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("low-order point")
	}
	eightBytes := make([]byte, 32)
	eightBytes[0] = 8
	eight, err := new(edwards25519.Scalar).SetCanonicalBytes(eightBytes)
	if err != nil {
		return errors.New("invalid subgroup scalar")
	}
	projected := new(edwards25519.Point).ScalarMult(new(edwards25519.Scalar).Invert(eight), cofactored)
	if projected.Equal(point) != 1 {
		return errors.New("point has a non-prime-order component")
	}
	return nil
}

func verifyEvidenceAttestation(report *EvidenceReport, trustStore *EvidenceTrustStore) error {
	if report == nil {
		return errors.New("evidence report is missing")
	}
	if err := validateEvidenceTrustStore(trustStore); err != nil {
		return err
	}
	if report.Attestation.Scheme != "ed25519" || strings.TrimSpace(report.Attestation.KeyID) == "" || strings.TrimSpace(report.Attestation.Signature) == "" {
		return errors.New("evidence attestation must contain scheme=ed25519, key_id, and signature")
	}
	var publicKey ed25519.PublicKey
	for _, key := range trustStore.Keys {
		if key.KeyID != report.Attestation.KeyID {
			continue
		}
		decoded, _ := base64.StdEncoding.DecodeString(key.PublicKey)
		publicKey = ed25519.PublicKey(decoded)
		break
	}
	if publicKey == nil {
		return fmt.Errorf("evidence attestation key_id %q is not trusted", report.Attestation.KeyID)
	}
	signature, err := base64.StdEncoding.DecodeString(report.Attestation.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("evidence attestation has an invalid Ed25519 signature encoding")
	}
	message, err := evidenceSigningBytes(report)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return errors.New("evidence attestation signature verification failed")
	}
	return nil
}

func evidenceSigningBytes(report *EvidenceReport) ([]byte, error) {
	if report == nil {
		return nil, errors.New("evidence report is missing")
	}
	canonical := *report
	canonical.baseDir = ""
	canonical.Attestation.Signature = ""
	return json.Marshal(canonical)
}
