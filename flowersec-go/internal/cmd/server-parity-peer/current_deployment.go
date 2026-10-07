package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
)

// Deployment files are independently installed inputs, never reconstructed
// from relay-ready. Bound the original read and reject trailing JSON values.
func readCurrentPeerDeployment(path string, dst any) error {
	if path == "" || len(path) > 4096 {
		return errors.New("current peer requires its independently installed deployment path")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 4194305))
	if err != nil {
		return err
	}
	defer clear(body)
	if len(body) == 0 || len(body) > 4194304 {
		return errors.New("current peer deployment exceeds its bounded input")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("current peer deployment has trailing JSON")
	}
	return nil
}
func readCurrentLiveClientInstallation(path string) (*interopharness.RegisteredLiveClientInstallation, error) {
	var installation interopharness.RegisteredLiveClientInstallation
	if err := readCurrentPeerDeployment(path, &installation); err != nil {
		return nil, err
	}
	return &installation, nil
}

func readCurrentLiveServerDeployment(path string) (*interopharness.RegisteredLiveServerDeployment, error) {
	var deployment interopharness.RegisteredLiveServerDeployment
	if err := readCurrentPeerDeployment(path, &deployment); err != nil {
		return nil, err
	}
	if _, _, err := deployment.ServerMaterial("", deployment.TrustPEM, deployment.Origin); err != nil {
		return nil, err
	}
	return &deployment, nil
}

func readCurrentPoolClientInstallation(path string) (*interopharness.RegisteredPoolClientInstallation, error) {
	var installation interopharness.RegisteredPoolClientInstallation
	if err := readCurrentPeerDeployment(path, &installation); err != nil {
		return nil, err
	}
	return &installation, nil
}
