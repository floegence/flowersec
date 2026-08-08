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
	tsLease, err := read("flowersec-ts/src/public/artifactLease.ts")
	if err != nil {
		return err
	}
	tsLeaseBody, err := declarationBody(tsLease, "class ArtifactLease {")
	if err != nil {
		return err
	}
	if strings.Contains(tsLeaseBody, "commitSpend(") {
		return fmt.Errorf("TypeScript ArtifactLease publicly exposes connector-owned artifact spending")
	}
	if !strings.Contains(tsLeaseBody, "private constructor") || !strings.Contains(tsLeaseBody, "#artifactLeaseBrand") {
		return fmt.Errorf("TypeScript ArtifactLease must have a private constructor and opaque brand")
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
			path:      "flowersec-ts/src/public/contract.ts",
			required:  []string{"waitTermination(): Promise<SessionTermination>;"},
			forbidden: []string{"waitClosed(): Promise<SessionTermination>;", "SessionV2", "ByteStreamV2"},
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

	tsContract, err := read("flowersec-ts/src/public/contract.ts")
	if err != nil {
		return err
	}
	if !strings.Contains(tsContract, "decodeResponse: (payload: JsonValue) => Response") {
		return fmt.Errorf("TypeScript RpcPeer.call must require a successful-response decoder")
	}
	tsProjection, err := read("flowersec-ts/src/v2/publicSession.ts")
	if err != nil {
		return err
	}
	if strings.Contains(tsProjection, "as Response") {
		return fmt.Errorf("TypeScript public RPC projection must not assert an unchecked response type")
	}
	for path, required := range map[string][]string{
		"flowersec-go/connection_controller.go": {
			"type ConnectionControllerOptions struct", "MaximumAttempts uint64", "type ConnectionSnapshot struct", "func (controller *ConnectionController) Snapshot() ConnectionSnapshot",
		},
		"flowersec-rust/src/connection_controller.rs": {
			"pub struct ConnectionControllerOptions", "with_maximum_attempts", "pub struct ConnectionSnapshot", "pub fn snapshot(&self) -> ConnectionSnapshot",
		},
		"flowersec-swift/Sources/Flowersec/ConnectionController.swift": {
			"maximumAttempts: UInt64? = nil", "func retryNow() async -> Bool", "private var closeTask",
		},
	} {
		source, err := read(path)
		if err != nil {
			return err
		}
		for _, token := range required {
			if !strings.Contains(source, token) {
				return fmt.Errorf("%s is missing final controller contract %q", path, token)
			}
		}
	}
	for path, forbidden := range map[string][]string{
		"flowersec-go/connection_controller.go":                        {"RetryPolicy", "ConnectionStatus", "ErrConnectionControllerStarted"},
		"flowersec-rust/src/connection_controller.rs":                  {"pub struct RetryPolicy", "pub enum RetryPolicyError", "ConnectionControllerStartError", "pub struct ConnectionStatus"},
		"flowersec-swift/Sources/Flowersec/ConnectionController.swift": {"ConnectionRetryPolicy", "nextRetryAt", "retryPolicy:"},
		"flowersec-ts/src/facade.ts":                                   {"SessionV2", "ArtifactLeaseV2", "ConnectorArtifactLeaseV2"},
		"flowersec-ts/src/browser/connectSession.ts":                   {"connectBrowserSession"},
		"flowersec-ts/src/node/connectSession.ts":                      {"connectNodeSession"},
	} {
		source, err := read(path)
		if err != nil {
			return err
		}
		for _, token := range forbidden {
			if strings.Contains(source, token) {
				return fmt.Errorf("%s retains removed public API %q", path, token)
			}
		}
	}
	for path := range map[string]struct{}{
		"flowersec-go/connection_controller_test.go":                                   {},
		"flowersec-ts/src/connectionController.vectors.test.ts":                        {},
		"flowersec-rust/src/connection_controller.rs":                                  {},
		"flowersec-swift/Tests/FlowersecTests/ConnectionControllerVectorSupport.swift": {},
	} {
		source, err := read(path)
		if err != nil {
			return err
		}
		if !strings.Contains(source, "connection_controller_vectors.json") {
			return fmt.Errorf("%s does not consume shared connection controller vectors", path)
		}
	}
	if source, err := read("flowersec-ts/scripts/sanitize-public-declarations.mjs"); err == nil || source != "" {
		return fmt.Errorf("removed TypeScript declaration sanitizer remains")
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
