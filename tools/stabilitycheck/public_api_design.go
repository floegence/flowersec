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

	checks := []struct {
		path      string
		required  []string
		forbidden []string
	}{
		{"flowersec-swift/Sources/Flowersec/TransportV4API.swift", []string{"public final class ConnectionMaterial", "init(owner: any ConnectionMaterialOwner)", "public func waitCleanup()"}, []string{"public func commitSpend("}},
		{"flowersec-rust/src/material_source_v4.rs", []string{"pub struct ConnectionMaterial", "pub async fn connect(\n    environment: &TransportEnvironment"}, []string{"pub async fn commit_spend("}},
		{"flowersec-ts/src/v4/public.ts", []string{"const materialOwners = new WeakMap", "const wrappedMaterials = new WeakSet", "materialOwners.delete(material)", "waitTermination(options?: OperationOptions): Promise<void>", "waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus>"}, []string{}},
		{"flowersec-go/current_transport.go", []string{"Environment *TransportEnvironment", "func Connect(ctx context.Context, source ConnectionMaterialSource", "func ConnectMaterial(ctx context.Context, material *ConnectionMaterial"}, []string{}},
		{"flowersec-go/v4_session_lifecycle.go", []string{"func (s *Session) WaitTermination(ctx context.Context) error"}, []string{}},
		{"flowersec-go/v4_api.go", []string{"func (s *Session) WaitCleanup(ctx context.Context) error", "type Stream interface"}, []string{}},
		{"flowersec-swift/Sources/Flowersec/Transport.swift", []string{"public struct SessionTermination", "func waitTermination() async -> SessionTermination"}, []string{"func waitClosed() async -> SessionError"}},
		{"flowersec-ts/src/v4/messageDefinition.ts", []string{"decode(context: V4ApplicationContext, bytes: Uint8Array): T", "typeof decode !== \"function\""}, []string{}},
		{"flowersec-go/v4_controller.go", []string{"type ControllerOptions struct", "MaximumAttempts", "func (c *ConnectionController) Snapshot() ControllerSnapshot", "func (c *ConnectionController) WaitCleanup(ctx context.Context) error"}, []string{}},
		{"flowersec-rust/src/connection_controller_v4.rs", []string{"pub struct MaterialControllerOptions", "pub fn progress(&self) -> MaterialControllerProgress", "pub async fn wait_cleanup(&self) -> CleanupStatus"}, []string{}},
		{"flowersec-swift/Sources/Flowersec/ConnectionController.swift", []string{"maximumAttempts: UInt64? = nil", "func retryNow() async -> Bool", "private var closeTask"}, []string{}},
	}
	for _, check := range checks {
		source, err := read(check.path)
		if err != nil {
			return err
		}
		for _, token := range check.required {
			if !strings.Contains(source, token) {
				return fmt.Errorf("%s is missing current API ownership contract %q", check.path, token)
			}
		}
		for _, token := range check.forbidden {
			if strings.Contains(source, token) {
				return fmt.Errorf("%s exposes forbidden ownership operation %q", check.path, token)
			}
		}
	}
	tsSource, err := read("flowersec-ts/src/v4/public.ts")
	if err != nil {
		return err
	}
	material, err := declarationBody(tsSource, "export class V4ConnectionMaterial {")
	if err != nil {
		return err
	}
	if strings.Contains(material, "commitSpend(") {
		return fmt.Errorf("TypeScript material exposes runtime-owned spending")
	}
	if _, err := os.Stat(filepath.Join(repoRoot, "flowersec-ts/scripts/sanitize-public-declarations.mjs")); err == nil || !os.IsNotExist(err) {
		return fmt.Errorf("removed TypeScript declaration sanitizer remains or cannot be inspected")
	}

	fmt.Println("public API design OK: current material, termination, cleanup, typed codec and controller source contracts verified")
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
