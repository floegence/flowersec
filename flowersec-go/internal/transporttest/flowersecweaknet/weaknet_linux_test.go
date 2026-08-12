//go:build linux

package flowersecweaknet

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestPrivilegedFlowersecWeaknet(t *testing.T) {
	required := os.Getenv("FLOWERSEC_REQUIRED_DIAGNOSTIC") == "1"
	if err := validateWeaknetEnvironment(required, os.Getenv("FLOWERSEC_LINUX_NETLAB_INTEGRATION")); err != nil {
		t.Fatal(err)
	}
	if !required && os.Getenv("FLOWERSEC_LINUX_NETLAB_INTEGRATION") != "1" {
		t.Skip("run through the privileged diagnostic suite")
	}
	if os.Getenv("FLOWERSEC_WEAKNET_DIRECT_WORKER") == "1" {
		kind, err := parseCarrier(os.Getenv("FLOWERSEC_WEAKNET_CARRIER"))
		if err != nil {
			t.Fatal(err)
		}
		scenario, err := scenarioFor(os.Getenv("FLOWERSEC_WEAKNET_SCENARIO"))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		if err := runDirectWorker(ctx, kind,
			os.Getenv("FLOWERSEC_WEAKNET_CLIENT_NAMESPACE"),
			os.Getenv("FLOWERSEC_WEAKNET_SERVER_NAMESPACE"),
			os.Getenv("FLOWERSEC_WEAKNET_SERVER_ADDRESS"), scenario); err != nil {
			t.Fatal(err)
		}
		return
	}
	carrierName := os.Getenv("FLOWERSEC_WEAKNET_CARRIER")
	path := os.Getenv("FLOWERSEC_WEAKNET_PATH")
	scenario := os.Getenv("FLOWERSEC_WEAKNET_SCENARIO")
	if carrierName == "" || path == "" || scenario == "" {
		t.Fatal("Flowersec weak-network test identity is incomplete")
	}
	if err := runPrivilegedFlowersecWeaknet(t, carrierName, path, scenario); err != nil {
		t.Fatal(err)
	}
}

func validateWeaknetEnvironment(required bool, integration string) error {
	if required && integration != "1" {
		return errors.New("required Flowersec weak-network diagnostic environment is incomplete")
	}
	return nil
}
