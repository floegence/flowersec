package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransportV4BindingAndDraftBoundary(t *testing.T) {
	root, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := loadTransportV4Registry(root)
	if err != nil {
		t.Fatal(err)
	}
	if registry.Version != 4 || registry.Schema.Status != "not_frozen" || len(registry.Files) == 0 || len(registry.Trace) == 0 {
		t.Fatal("unexpected transport v4 binding summary")
	}
}

func TestTransportV4SchemaReferencesResolveEveryPathSegment(t *testing.T) {
	document := map[string]any{"encoding": map[string]any{"max_depth": 8}, "outer": map[string]any{"inner": true}}
	for _, reference := range []string{"/encoding/max_depth", "/outer/inner"} {
		if _, err := resolveTransportV4RegistryReference(document, reference); err != nil {
			t.Fatalf("resolve %s: %v", reference, err)
		}
	}
	for _, reference := range []string{"encoding.max_depth", "/missing", "/outer/missing", "/outer/inner/leaf"} {
		if _, err := resolveTransportV4RegistryReference(document, reference); err == nil {
			t.Fatalf("invalid reference %s was accepted", reference)
		}
	}
}

func TestTransportV4ConsumerEvidenceRejectsUnregisteredRules(t *testing.T) {
	if err := validateTransportV4ConsumerEvidence("invented", "corpus.json"); err == nil {
		t.Fatal("unregistered consumer evidence rule was accepted")
	}
}

func TestTransportV4ForbiddenDomainRecognizesLegacyIsolationFamilies(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		for _, value := range []string{"FSB" + version, "flowersec/" + version, "flowersec-direct/" + version, "/flowersec/v" + version + "/direct", "/flowersec/webtransport/v" + version + "/tunnel", "flowersec.direct.v" + version, "flowersec v" + version + " server finished", "flowersec-v" + version + "-handshake"} {
			if !transportV4ForbiddenDomain.MatchString(value) {
				t.Fatalf("legacy isolation family was not recognized: %q", value)
			}
		}
	}
	for _, value := range []string{"flowersec/4", "x509v3", "IdnaTestV2"} {
		if transportV4ForbiddenDomain.MatchString(value) {
			t.Fatalf("nonlegacy domain was rejected: %s", value)
		}
	}
}

func TestTransportV4ContractRejectsUnknownTopLevelField(t *testing.T) {
	root, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, transportV4ContractPath))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["invented"] = true
	mutated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	if err := os.MkdirAll(filepath.Join(temporary, "stability"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(temporary, transportV4ContractPath), mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTransportV4Registry(temporary); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field rejection, got %v", err)
	}
}

func TestTransportV4ConsumerEvidenceRejectsSourceMutation(t *testing.T) {
	root, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	for language, consumer := range transportV4CorpusConsumers {
		body, err := os.ReadFile(filepath.Join(root, consumer.Path))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateTransportV4ConsumerEvidence(language, string(body)); err != nil {
			t.Fatalf("%s consumer failed: %v", language, err)
		}
		for _, token := range consumer.Tokens {
			mutated := strings.ReplaceAll(string(body), token, "")
			if err := validateTransportV4ConsumerEvidence(language, mutated); err == nil {
				t.Fatalf("%s consumer accepted removal of %s", language, token)
			}
		}
	}
}

func TestTransportV4BindingRejectsHashDriftAndUnsafePaths(t *testing.T) {
	root := t.TempDir()
	data := []byte("draft source")
	digest := sha256.Sum256(data)
	if err := os.WriteFile(filepath.Join(root, "schema.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTransportV4Hash(root, "schema.json", hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := readTransportV4Hash(root, "schema.json", strings.Repeat("0", 64)); err == nil {
		t.Fatal("hash drift was accepted")
	}
	for _, path := range []string{"", "../schema.json", "/schema.json", "a/../schema.json", "a\\schema.json"} {
		if err := validateTransportV4Path(path); err == nil {
			t.Fatalf("unsafe path was accepted: %q", path)
		}
	}
}

func TestTransportV4QualificationCannotBePromotedBySourceChecks(t *testing.T) {
	entry := transportV4Trace{ID: "qualification", DesignSections: []string{"7.1"}, SourceTargets: []string{"flowersec-go/internal/transporttest"}, SDKEntries: []string{"Provider tuples"}, Status: "verified", RequiredTestIDs: []string{"v4.qualification.required_pairs", "v4.qualification.browser", "v4.qualification.resource", "v4.qualification.non_regression"}}
	if err := validateTransportV4Traceability(t.TempDir(), []transportV4Trace{entry}, nil, nil); err == nil || !strings.Contains(err.Error(), "qualification") {
		t.Fatalf("qualification promotion was accepted: %v", err)
	}
}
