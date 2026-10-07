package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const transportV4ContractPath = "stability/transport_v4_contract.json"
const transportV4SchemaPath = "stability/transport_v4_schema.json"
const transportV4ManifestPath = "testdata/transport_v4/manifest.json"
const transportV4TraceabilityPath = "stability/transport_v4_traceability.json"
const transportV4GeneratorPath = "scripts/generate-transport-v4-vectors.mjs"

type transportV4Registry struct {
	Version int    `json:"version"`
	Status  string `json:"status"`
	Design  struct {
		ProductVersion       string  `json:"product_version"`
		WireProfile          string  `json:"wire_profile"`
		SHA256               string  `json:"sha256"`
		SourcePath           string  `json:"source_path"`
		ReviewEvidencePath   string  `json:"review_evidence_path"`
		ReviewEvidenceStatus string  `json:"review_evidence_status"`
		ReviewEvidenceSHA256 *string `json:"review_evidence_sha256"`
	} `json:"design"`
	Schema struct {
		Status   string `json:"status"`
		Revision string `json:"revision"`
		SHA256   string `json:"sha256"`
		Path     string `json:"path"`
	} `json:"schema"`
	Vectors struct {
		Status         string `json:"status"`
		ManifestSHA256 string `json:"manifest_sha256"`
		Path           string `json:"path"`
	} `json:"vectors"`
	Traceability struct {
		Status string `json:"status"`
		Path   string `json:"path"`
	} `json:"traceability"`
	Qualification struct {
		ProviderInteroperability string `json:"provider_interoperability"`
		IndependentCryptography  string `json:"independent_cryptography"`
	} `json:"qualification"`
	Files []transportV4File  `json:"-"`
	Trace []transportV4Trace `json:"-"`
}

type transportV4File struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

type transportV4Trace struct {
	ID              string   `json:"id"`
	DesignSections  []string `json:"design_sections"`
	Artifact        string   `json:"artifact"`
	Tests           []string `json:"tests"`
	RegistryRefs    []string `json:"registry_refs"`
	VectorIDs       []string `json:"vector_ids"`
	SourceTargets   []string `json:"source_targets"`
	SDKEntries      []string `json:"sdk_entries"`
	RequiredTestIDs []string `json:"required_test_ids"`
	Status          string   `json:"status"`
	Qualification   string   `json:"qualification"`
}

// These are source obligations. Finding an assertion never establishes that it
// passed, or qualifies a codec, provider, cryptographic primitive or deployment.
var transportV4CorpusConsumers = map[string]struct {
	Path   string
	Tokens []string
}{
	"go":         {"flowersec-go/internal/protocolv4/cbor_reference_test.go", []string{"corpus.json", "transport_v4", "expected_error", "t.Fatalf"}},
	"rust":       {"flowersec-rust/src/codec_v4.rs", []string{"corpus.json", "transport_v4", "expected_error", "assert_eq!", "decode("}},
	"swift":      {"flowersec-swift/Tests/FlowersecTests/TransportV4CBORTests.swift", []string{"corpus.json", "transport_v4", "expected_error", "XCTAssertEqual", "Self.reference.decode"}},
	"typescript": {"flowersec-ts/src/v4/cborReference.test.ts", []string{"corpus.json", "transport_v4", "expected_error", "expect(", "reference.decode"}},
}

var transportV4Digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var transportV4Reference = regexp.MustCompile(`^(?:/[a-zA-Z0-9_]+)+$`)
var transportV4Identifier = regexp.MustCompile(`^[a-z][A-Za-z0-9_]*$`)
var transportV4TestID = regexp.MustCompile(`^v4\.[a-z0-9_]+\.[a-z0-9_]+$`)
var transportV4ForbiddenDomain = regexp.MustCompile(`(?i)(?:\bFS[ABCHSRD][23]\b|flowersec/[23](?:\b|/)|flowersec(?:[-.]direct|[-.]tunnel)/[23]|flowersec(?:/v[23]|/webtransport/v[23])(?:/|\b)|flowersec\.(?:direct|tunnel)\.v[23]|flowersec[-.]v[23]|flowersec v[23] (?:server finished|client finished|epoch zero|control root|stream root|setup root|rekey root|next epoch|stream|control|record key|nonce|unreliable))`)

func loadTransportV4Registry(repoRoot string) (*transportV4Registry, error) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, transportV4ContractPath))
	if err != nil {
		return nil, err
	}
	var registry transportV4Registry
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return nil, fmt.Errorf("parse %s: %w", transportV4ContractPath, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%s must contain one JSON value", transportV4ContractPath)
	}
	if registry.Version != 4 || registry.Status != "draft" || registry.Design.ProductVersion != "6.0.0" || registry.Design.WireProfile != "flowersec/4" || !transportV4Digest.MatchString(registry.Design.SHA256) {
		return nil, fmt.Errorf("%s must describe the current draft wire v4 binding", transportV4ContractPath)
	}
	if registry.Schema.Path != transportV4SchemaPath || registry.Vectors.Path != "testdata/transport_v4" || registry.Traceability.Path != transportV4TraceabilityPath {
		return nil, fmt.Errorf("transport v4 binding paths drifted")
	}
	if registry.Schema.Status != "not_frozen" || registry.Vectors.Status != "draft_cbor_fields_only" || registry.Traceability.Status != "implementation_in_progress" || registry.Qualification.ProviderInteroperability != "not_started" || registry.Qualification.IndependentCryptography != "not_started" {
		return nil, fmt.Errorf("transport v4 source checks cannot promote unfinished qualification")
	}
	if registry.Design.ReviewEvidenceSHA256 == nil {
		if registry.Design.ReviewEvidenceStatus != "pending_independent_review" {
			return nil, fmt.Errorf("unbound architecture evidence must remain pending")
		}
	} else if registry.Design.ReviewEvidenceStatus != "pinned" || !transportV4Digest.MatchString(*registry.Design.ReviewEvidenceSHA256) {
		return nil, fmt.Errorf("invalid architecture review evidence binding")
	}
	schemaRaw, err := readTransportV4Hash(repoRoot, registry.Schema.Path, registry.Schema.SHA256)
	if err != nil {
		return nil, err
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaRaw, &schema); err != nil {
		return nil, err
	}
	unresolved, ok := schema["unresolved"].([]any)
	if schema["status"] != "draft" || schema["wire_profile"] != "flowersec/4" || schema["protocol_id"] != "flowersec/4" || schema["artifact_version"] != "4" || schema["design_sha256"] != registry.Design.SHA256 || schema["schema_revision"] != registry.Schema.Revision || !ok || len(unresolved) == 0 {
		return nil, fmt.Errorf("transport v4 schema binding or draft boundary drifted")
	}
	manifestRaw, err := readTransportV4Hash(repoRoot, transportV4ManifestPath, registry.Vectors.ManifestSHA256)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Status         string            `json:"status"`
		DesignSHA256   string            `json:"design_sha256"`
		SchemaRevision string            `json:"schema_revision"`
		SchemaSHA256   string            `json:"schema_sha256"`
		Coverage       string            `json:"coverage"`
		Files          []transportV4File `json:"files"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, err
	}
	if manifest.Status != "draft" || manifest.DesignSHA256 != registry.Design.SHA256 || manifest.SchemaRevision != registry.Schema.Revision || manifest.SchemaSHA256 != registry.Schema.SHA256 || manifest.Coverage != registry.Vectors.Status || len(manifest.Files) == 0 {
		return nil, fmt.Errorf("transport v4 vector manifest binding drifted")
	}
	registry.Files = manifest.Files
	if err := validateTransportV4FixtureOwnership(repoRoot, manifest.Files); err != nil {
		return nil, err
	}
	vectorIDs, err := transportV4VectorIDs(manifestRaw)
	if err != nil {
		return nil, err
	}
	traceRaw, err := os.ReadFile(filepath.Join(repoRoot, registry.Traceability.Path))
	if err != nil {
		return nil, err
	}
	var trace struct {
		Status           string             `json:"status"`
		DesignSHA256     string             `json:"design_sha256"`
		SchemaRevision   string             `json:"schema_revision"`
		TrackingBoundary string             `json:"tracking_boundary"`
		Entries          []transportV4Trace `json:"entries"`
	}
	if err := json.Unmarshal(traceRaw, &trace); err != nil {
		return nil, err
	}
	if trace.Status != registry.Traceability.Status || trace.DesignSHA256 != registry.Design.SHA256 || trace.SchemaRevision != registry.Schema.Revision || !strings.Contains(trace.TrackingBoundary, "obligations") {
		return nil, fmt.Errorf("transport v4 traceability must preserve implementation obligations")
	}
	registry.Trace = trace.Entries
	if err := validateTransportV4Traceability(repoRoot, trace.Entries, schema, vectorIDs); err != nil {
		return nil, err
	}
	for language, consumer := range transportV4CorpusConsumers {
		body, err := os.ReadFile(filepath.Join(repoRoot, consumer.Path))
		if err != nil {
			return nil, err
		}
		if err := validateTransportV4ConsumerEvidence(language, string(body)); err != nil {
			return nil, err
		}
	}
	if err := scanTransportV4Domains(repoRoot, &registry); err != nil {
		return nil, err
	}
	return &registry, nil
}

func readTransportV4Hash(repoRoot, relative, expected string) ([]byte, error) {
	if !transportV4Digest.MatchString(expected) {
		return nil, fmt.Errorf("%s has invalid SHA-256", relative)
	}
	if err := validateTransportV4Path(relative); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, relative))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected {
		return nil, fmt.Errorf("%s SHA-256 drifted", relative)
	}
	return data, nil
}

func validateTransportV4Path(relative string) error {
	if relative == "" || strings.Contains(relative, "\\") || !filepath.IsLocal(relative) || filepath.ToSlash(filepath.Clean(relative)) != relative {
		return fmt.Errorf("invalid repository path %q", relative)
	}
	return nil
}

func validateTransportV4FixtureOwnership(repoRoot string, files []transportV4File) error {
	producer, err := os.ReadFile(filepath.Join(repoRoot, transportV4GeneratorPath))
	if err != nil {
		return err
	}
	owned := make(map[string]bool, len(files))
	for _, file := range files {
		if err := validateTransportV4Path(file.File); err != nil {
			return err
		}
		if owned[file.File] {
			return fmt.Errorf("duplicate transport v4 fixture owner for %s", file.File)
		}
		owned[file.File] = true
		if !strings.HasPrefix(file.File, "testdata/transport_v4/") && !strings.Contains(filepath.Base(file.File), "generated") && !strings.Contains(filepath.Base(file.File), "transportV4") {
			return fmt.Errorf("unexpected generated transport v4 output %s", file.File)
		}
		if _, err := readTransportV4Hash(repoRoot, file.File, file.SHA256); err != nil {
			return err
		}
		// Fixture names are declared by the common generator. Generated SDK
		// registries and result projections are listed in the same owned manifest.
		if strings.HasPrefix(file.File, "testdata/transport_v4/") && !strings.Contains(string(producer), filepath.Base(file.File)) {
			return fmt.Errorf("%s has no registered producer in %s", file.File, transportV4GeneratorPath)
		}
	}
	entries, err := os.ReadDir(filepath.Join(repoRoot, "testdata/transport_v4"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") && entry.Name() != "manifest.json" && !owned["testdata/transport_v4/"+entry.Name()] {
			return fmt.Errorf("transport v4 fixture %s has no manifest owner", entry.Name())
		}
	}
	if !owned["testdata/transport_v4/corpus.json"] || !owned["testdata/transport_v4/domains.json"] {
		return fmt.Errorf("transport v4 corpus or domain fixture owner is missing")
	}
	return nil
}

func transportV4VectorIDs(raw []byte) (map[string]bool, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	ids := make(map[string]bool)
	for key, value := range document {
		if key != "vectors" && !strings.HasSuffix(key, "_vectors") {
			continue
		}
		var vectors []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(value, &vectors); err != nil {
			return nil, fmt.Errorf("vector index %s: %w", key, err)
		}
		local := make(map[string]bool, len(vectors))
		for _, vector := range vectors {
			if !transportV4Identifier.MatchString(vector.ID) || local[vector.ID] {
				return nil, fmt.Errorf("invalid or duplicate transport v4 vector %q", vector.ID)
			}
			local[vector.ID] = true
			ids[vector.ID] = true
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("transport v4 vector index is empty")
	}
	return ids, nil
}

func resolveTransportV4RegistryReference(document any, reference string) (any, error) {
	if !transportV4Reference.MatchString(reference) {
		return nil, fmt.Errorf("invalid schema reference %q", reference)
	}
	current := document
	for _, segment := range strings.Split(reference[1:], "/") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("schema reference %q traverses a non-object", reference)
		}
		current, ok = object[segment]
		if !ok {
			return nil, fmt.Errorf("schema reference %q has no field %q", reference, segment)
		}
	}
	return current, nil
}

func validateTransportV4Traceability(repoRoot string, entries []transportV4Trace, schema map[string]any, vectors map[string]bool) error {
	ids, testIDs := make(map[string]bool), make(map[string]bool)
	qualification := false
	for _, entry := range entries {
		if !transportV4Identifier.MatchString(entry.ID) || ids[entry.ID] || entry.Status == "" || len(entry.DesignSections) == 0 || len(entry.SourceTargets) == 0 || len(entry.SDKEntries) == 0 || len(entry.RequiredTestIDs) == 0 {
			return fmt.Errorf("invalid or incomplete transport v4 trace %q", entry.ID)
		}
		ids[entry.ID] = true
		for _, id := range entry.RequiredTestIDs {
			if !transportV4TestID.MatchString(id) || testIDs[id] {
				return fmt.Errorf("invalid or duplicate transport v4 test obligation %q", id)
			}
			testIDs[id] = true
		}
		// Source targets are planned obligations; only artifacts and tests claim
		// existing files. Do not convert an implementation plan to passing proof.
		for _, target := range entry.SourceTargets {
			if err := validateTransportV4Path(target); err != nil {
				return err
			}
		}
		paths := append([]string{}, entry.Tests...)
		if entry.Artifact != "" {
			paths = append(paths, entry.Artifact)
		}
		for _, path := range paths {
			if err := validateTransportV4Path(path); err != nil {
				return err
			}
			if _, err := os.Stat(filepath.Join(repoRoot, path)); err != nil {
				return fmt.Errorf("trace %s artifact %s: %w", entry.ID, path, err)
			}
		}
		for _, ref := range entry.RegistryRefs {
			if _, err := resolveTransportV4RegistryReference(schema, ref); err != nil {
				return fmt.Errorf("trace %s: %w", entry.ID, err)
			}
		}
		for _, id := range entry.VectorIDs {
			if !vectors[id] {
				return fmt.Errorf("trace %s references missing vector %s", entry.ID, id)
			}
		}
		if entry.ID == "qualification" {
			qualification = true
			if entry.Status != "not_started" || entry.Artifact != "" || len(entry.Tests) != 0 {
				return fmt.Errorf("provider qualification cannot be inferred from source checks")
			}
			for _, id := range []string{"v4.qualification.required_pairs", "v4.qualification.browser", "v4.qualification.resource", "v4.qualification.non_regression"} {
				if !slices.Contains(entry.RequiredTestIDs, id) {
					return fmt.Errorf("provider qualification omits %s", id)
				}
			}
		}
	}
	if !qualification {
		return fmt.Errorf("transport v4 provider qualification obligations are missing")
	}
	return nil
}

func validateTransportV4ConsumerEvidence(language, body string) error {
	consumer, ok := transportV4CorpusConsumers[language]
	if !ok {
		return fmt.Errorf("unregistered transport v4 consumer %q", language)
	}
	for _, token := range consumer.Tokens {
		if !strings.Contains(body, token) {
			return fmt.Errorf("transport v4 %s corpus consumer omits %q", language, token)
		}
	}
	return nil
}

func scanTransportV4Domains(repoRoot string, registry *transportV4Registry) error {
	owned := make(map[string]bool)
	for _, trace := range registry.Trace {
		if trace.Artifact != "" {
			owned[trace.Artifact] = true
		}
		for _, path := range trace.SourceTargets {
			owned[path] = true
		}
	}
	for _, root := range []string{"flowersec-go", "flowersec-ts/src", "flowersec-rust/src", "flowersec-swift/Sources/Flowersec"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, root), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			name := filepath.ToSlash(relative)
			if !isTransportV4SourcePath(name, owned[name]) || isTransportV4TestPath(name) {
				return nil
			}
			if !slices.Contains([]string{".go", ".ts", ".rs", ".swift"}, filepath.Ext(name)) {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if filepath.Ext(name) == ".rs" {
				if index := bytes.Index(body, []byte("#[cfg(test)]")); index >= 0 {
					body = body[:index]
				}
			}
			if transportV4ForbiddenDomain.Match(body) {
				return fmt.Errorf("transport v4 source %s contains an obsolete transport domain", name)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func isTransportV4SourcePath(name string, registryOwned bool) bool {
	if registryOwned {
		return true
	}
	lower := strings.ToLower(filepath.ToSlash(name))
	return strings.Contains(lower, "v4") || strings.HasPrefix(lower, "flowersec-go/controlplane/") || strings.HasPrefix(lower, "flowersec-go/current_") || strings.HasSuffix(lower, "current.ts")
}

func isTransportV4TestPath(name string) bool {
	lower := strings.ToLower(filepath.ToSlash(name))
	return strings.HasSuffix(lower, "_test.go") || strings.Contains(lower, ".test.") || strings.Contains(lower, ".spec.") || strings.Contains(lower, "/tests/") || strings.Contains(lower, "/test/") || strings.Contains(lower, "/testsupport/") || strings.HasSuffix(lower, "_tests.rs")
}
