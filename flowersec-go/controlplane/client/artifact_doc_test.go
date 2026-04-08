package client

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestArtifactFetchDoc_CoversStablePathsAndRequestFields(t *testing.T) {
	doc := readArtifactFetchDoc(t)

	body, err := buildRequestBody(ConnectArtifactRequestConfig{
		EndpointID: "env_demo",
		Payload:    map[string]any{"floe_app": "com.example.demo"},
		TraceID:    "trace-0001",
	})
	if err != nil {
		t.Fatalf("buildRequestBody: %v", err)
	}

	wantRaw := []string{
		defaultPath("", false),
		defaultPath("", true),
		"connect_artifact",
		"endpoint_id",
		"payload",
		"trace_id",
	}
	if _, ok := body["correlation"]; ok {
		wantRaw = append(wantRaw, "correlation")
	}

	var missing []string
	for _, token := range wantRaw {
		if !strings.Contains(doc, token) {
			missing = append(missing, token)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("docs/CONTROLPLANE_ARTIFACT_FETCH.md missing stable request tokens: %v", missing)
	}
}

func TestArtifactFetchDoc_CoversStableGoRequestErrorFields(t *testing.T) {
	doc := readArtifactFetchDoc(t)
	typ := reflect.TypeOf(RequestError{})

	var missing []string
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !strings.Contains(doc, "`"+name+"`") {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("docs/CONTROLPLANE_ARTIFACT_FETCH.md missing stable RequestError fields: %v", missing)
	}
}

func readArtifactFetchDoc(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "docs", "CONTROLPLANE_ARTIFACT_FETCH.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CONTROLPLANE_ARTIFACT_FETCH.md: %v", err)
	}
	return string(b)
}
