package fserrors

import (
	"bytes"
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

func TestPathsAndStages_AlignWithTypeScript(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	goPaths, err := extractGoPaths(filepath.Join(dir, "fserrors.go"))
	if err != nil {
		t.Fatalf("extract Go paths: %v", err)
	}
	goStages, err := extractGoStages(filepath.Join(dir, "fserrors.go"))
	if err != nil {
		t.Fatalf("extract Go stages: %v", err)
	}

	tsFile := filepath.Join(dir, "..", "..", "flowersec-ts", "src", "utils", "errors.ts")
	tsPaths, err := extractTSUnionStrings(tsFile, "FlowersecPath")
	if err != nil {
		t.Fatalf("extract TS paths: %v", err)
	}
	tsStages, err := extractTSUnionStrings(tsFile, "FlowersecStage")
	if err != nil {
		t.Fatalf("extract TS stages: %v", err)
	}

	sort.Strings(goPaths)
	sort.Strings(tsPaths)
	if len(goPaths) != len(tsPaths) {
		t.Fatalf("path count mismatch: go=%d ts=%d\ngo=%v\nts=%v", len(goPaths), len(tsPaths), goPaths, tsPaths)
	}
	for i := range goPaths {
		if goPaths[i] != tsPaths[i] {
			t.Fatalf("path mismatch at %d: go=%q ts=%q\ngo=%v\nts=%v", i, goPaths[i], tsPaths[i], goPaths, tsPaths)
		}
	}

	sort.Strings(goStages)
	sort.Strings(tsStages)
	if len(goStages) != len(tsStages) {
		t.Fatalf("stage count mismatch: go=%d ts=%d\ngo=%v\nts=%v", len(goStages), len(tsStages), goStages, tsStages)
	}
	for i := range goStages {
		if goStages[i] != tsStages[i] {
			t.Fatalf("stage mismatch at %d: go=%q ts=%q\ngo=%v\nts=%v", i, goStages[i], tsStages[i], goStages, tsStages)
		}
	}
}

func TestErrorModelDoc_CoversAllStableValues(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	docPath := filepath.Join(dir, "..", "..", "docs", "ERROR_MODEL.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read ERROR_MODEL.md: %v", err)
	}

	goCodes, err := extractGoCodes(filepath.Join(dir, "fserrors.go"))
	if err != nil {
		t.Fatalf("extract Go codes: %v", err)
	}
	goPaths, err := extractGoPaths(filepath.Join(dir, "fserrors.go"))
	if err != nil {
		t.Fatalf("extract Go paths: %v", err)
	}
	goStages, err := extractGoStages(filepath.Join(dir, "fserrors.go"))
	if err != nil {
		t.Fatalf("extract Go stages: %v", err)
	}

	var missing []string
	for _, v := range goCodes {
		if !bytes.Contains(doc, []byte("`"+v+"`")) {
			missing = append(missing, v)
		}
	}
	for _, v := range goPaths {
		if !bytes.Contains(doc, []byte("`"+v+"`")) {
			missing = append(missing, v)
		}
	}
	for _, v := range goStages {
		if !bytes.Contains(doc, []byte("`"+v+"`")) {
			missing = append(missing, v)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("docs/ERROR_MODEL.md missing stable values: %v", missing)
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

func extractGoPaths(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`(?m)^\s*Path[A-Za-z0-9_]+\s+Path\s+=\s+"([^"]+)"`)
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

func extractGoStages(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`(?m)^\s*Stage[A-Za-z0-9_]+\s+Stage\s+=\s+"([^"]+)"`)
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

func extractTSUnionStrings(path string, typeName string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	start := regexp.MustCompile(`export type ` + regexp.QuoteMeta(typeName) + `\s*=`).FindIndex(b)
	if start == nil {
		return nil, fmt.Errorf("%s block not found in %s", typeName, path)
	}
	rest := b[start[1]:]
	end := regexp.MustCompile(`;\s*\n`).FindIndex(rest)
	if end == nil {
		return nil, fmt.Errorf("%s block terminator not found in %s", typeName, path)
	}
	block := rest[:end[0]]

	re := regexp.MustCompile(`"([^"]+)"`)
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
