package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func verifyPublicAPIDesign(repoRoot string) error {
	read := func(path string) (string, error) {
		data, err := os.ReadFile(filepath.Join(repoRoot, path))
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		return string(data), nil
	}

	leaseChecks := map[string]string{
		"flowersec-swift/Sources/Flowersec/Artifact.swift": "  public func commitSpend()",
		"flowersec-rust/src/artifact_v2.rs":                "    pub async fn commit_spend(",
	}
	for path, forbidden := range leaseChecks {
		source, err := read(path)
		if err != nil {
			return err
		}
		if strings.Contains(source, forbidden) {
			return fmt.Errorf("%s publicly exposes connector-owned artifact spending", path)
		}
	}
	tsLease, err := read("flowersec-ts/src/v2/artifactLease.ts")
	if err != nil {
		return err
	}
	tsLeaseBody, err := declarationBody(tsLease, "class ArtifactLeaseV2Value")
	if err != nil {
		return err
	}
	if strings.Contains(tsLeaseBody, "commitSpend(") {
		return fmt.Errorf("TypeScript ArtifactLeaseV2 publicly exposes connector-owned artifact spending")
	}

	terminationChecks := []struct {
		path      string
		required  []string
		forbidden []string
	}{
		{
			path:      "flowersec-go/connector.go",
			required:  []string{"WaitTermination(context.Context) (SessionTermination, error)"},
			forbidden: []string{"Termination() <-chan struct{}", "WaitClosed(context.Context) error"},
		},
		{
			path:      "flowersec-ts/src/v2/contract.ts",
			required:  []string{"waitTermination(): Promise<SessionTerminationV2>;"},
			forbidden: []string{"waitClosed(): Promise<SessionTerminationV2>;"},
		},
		{
			path:      "flowersec-swift/Sources/Flowersec/TransportV2.swift",
			required:  []string{"public struct SessionTermination", "func waitTermination() async -> SessionTermination"},
			forbidden: []string{"func waitClosed() async -> SessionError"},
		},
		{
			path:      "flowersec-rust/src/transport_v2.rs",
			required:  []string{"pub struct SessionTermination", "async fn wait_termination(&self) -> SessionTermination;"},
			forbidden: []string{"async fn wait_closed(&self) -> Result<(), SessionError>;"},
		},
	}
	for _, check := range terminationChecks {
		source, err := read(check.path)
		if err != nil {
			return err
		}
		for _, required := range check.required {
			if !strings.Contains(source, required) {
				return fmt.Errorf("%s is missing %q", check.path, required)
			}
		}
		for _, forbidden := range check.forbidden {
			if strings.Contains(source, forbidden) {
				return fmt.Errorf("%s retains duplicate termination API %q", check.path, forbidden)
			}
		}
	}

	tsContract, err := read("flowersec-ts/src/v2/contract.ts")
	if err != nil {
		return err
	}
	if !strings.Contains(tsContract, "decodeResponse: (payload: JsonValueV2) => Response") {
		return fmt.Errorf("TypeScript RpcPeer.call must require a successful-response decoder")
	}
	tsProjection, err := read("flowersec-ts/src/v2/publicSession.ts")
	if err != nil {
		return err
	}
	if strings.Contains(tsProjection, "as Response") {
		return fmt.Errorf("TypeScript public RPC projection must not assert an unchecked response type")
	}

	goConnector, err := read("flowersec-go/connector.go")
	if err != nil {
		return err
	}
	for _, forbidden := range []string{
		"ConnectInvalid = ConnectInvalidInput",
		"ConnectFailed  = ConnectConnectionFailed",
	} {
		if strings.Contains(goConnector, forbidden) {
			return fmt.Errorf("Go public errors retain compatibility alias %q", forbidden)
		}
	}

	rustTransport, err := read("flowersec-rust/src/transport_v2.rs")
	if err != nil {
		return err
	}
	body, err := declarationBody(rustTransport, "pub enum SessionError")
	if err != nil {
		return err
	}
	for _, forbidden := range []string{"InvalidInput", "Rejected", "Reset", "TimedOut", "Failed"} {
		if strings.Contains(body, "\n    "+forbidden+",") {
			return fmt.Errorf("Rust SessionError retains overlapping variant %s", forbidden)
		}
	}
	for _, required := range []string{"Timeout", "OperationFailed"} {
		if !strings.Contains(body, "\n    "+required+",") {
			return fmt.Errorf("Rust SessionError is missing portable variant %s", required)
		}
	}

	fmt.Println("public API design OK: portable lease, termination, RPC, and error contracts verified")
	return nil
}

func declarationBody(source, marker string) (string, error) {
	start := strings.Index(source, marker)
	if start < 0 {
		return "", fmt.Errorf("missing declaration %q", marker)
	}
	openOffset := strings.IndexByte(source[start:], '{')
	if openOffset < 0 {
		return "", fmt.Errorf("declaration %q has no body", marker)
	}
	open := start + openOffset
	depth := 0
	for index := open; index < len(source); index++ {
		switch source[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[open : index+1], nil
			}
		}
	}
	return "", fmt.Errorf("declaration %q has an unterminated body", marker)
}
