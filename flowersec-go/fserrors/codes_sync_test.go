package fserrors

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"testing"
)

func TestErrorCodes_AlignWithTypeScript(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	goCodes, err := extractGoCodes(filepath.Join(dir, "fserrors.go"))
	if err != nil {
		t.Fatalf("extract Go codes: %v", err)
	}
	tsCodes, err := extractTSCodes(filepath.Join(dir, "..", "..", "flowersec-ts", "src", "utils", "errors.ts"))
	if err != nil {
		t.Fatalf("extract TS codes: %v", err)
	}

	sort.Strings(goCodes)
	sort.Strings(tsCodes)

	if len(goCodes) != len(tsCodes) {
		t.Fatalf("code count mismatch: go=%d ts=%d\ngo=%v\nts=%v", len(goCodes), len(tsCodes), goCodes, tsCodes)
	}
	for i := range goCodes {
		if goCodes[i] != tsCodes[i] {
			t.Fatalf("code mismatch at %d: go=%q ts=%q\ngo=%v\nts=%v", i, goCodes[i], tsCodes[i], goCodes, tsCodes)
		}
	}
}

func extractGoCodes(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`(?m)^\s*Code[A-Za-z0-9_]+\s+Code\s+=\s+"([^"]+)"`)
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
	sort.Strings(out)
	return out, nil
}

func extractTSCodes(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	start := regexp.MustCompile(`export type FlowersecErrorCode\s*=`).FindIndex(b)
	if start == nil {
		return nil, fmt.Errorf("FlowersecErrorCode block not found in %s", path)
	}
	rest := b[start[1]:]
	end := regexp.MustCompile(`;\s*\n`).FindIndex(rest)
	if end == nil {
		return nil, fmt.Errorf("FlowersecErrorCode block terminator not found in %s", path)
	}
	block := rest[:end[0]]

	re := regexp.MustCompile(`\|\s+"([^"]+)"`)
	matches := re.FindAllSubmatch(block, -1)
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
	sort.Strings(out)
	return out, nil
}
