package fserrors_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"testing"
)

func TestClientAndEndpoint_ReexportAllFSErrorsCodes(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	base := filepath.Clean(filepath.Join(dir, ".."))
	fserrorsCodes, err := extractFSErrorsCodeNames(filepath.Join(dir, "fserrors.go"))
	if err != nil {
		t.Fatalf("extract fserrors codes: %v", err)
	}
	clientCodes, err := extractReexportCodeNames(filepath.Join(base, "client", "types.go"))
	if err != nil {
		t.Fatalf("extract client codes: %v", err)
	}
	endpointCodes, err := extractReexportCodeNames(filepath.Join(base, "endpoint", "types.go"))
	if err != nil {
		t.Fatalf("extract endpoint codes: %v", err)
	}

	sort.Strings(fserrorsCodes)
	sort.Strings(clientCodes)
	sort.Strings(endpointCodes)

	if !equalStrings(fserrorsCodes, clientCodes) {
		t.Fatalf("client code re-export mismatch\nfserrors=%v\nclient=%v", fserrorsCodes, clientCodes)
	}
	if !equalStrings(fserrorsCodes, endpointCodes) {
		t.Fatalf("endpoint code re-export mismatch\nfserrors=%v\nendpoint=%v", fserrorsCodes, endpointCodes)
	}
}

func extractFSErrorsCodeNames(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`(?m)^\s*(Code[A-Z][A-Za-z0-9_]*)\s+Code\s+=\s+"`)
	matches := re.FindAllSubmatch(b, -1)
	out := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		s := string(m[1])
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, nil
}

func extractReexportCodeNames(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`(?m)^\s*(Code[A-Z][A-Za-z0-9_]*)\s*=`)
	matches := re.FindAllSubmatch(b, -1)
	out := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		s := string(m[1])
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
