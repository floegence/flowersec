package main

import (
	"fmt"
	"strings"
	"unicode"
)

type category int

const (
	categoryFeature category = iota
	categoryFix
	categoryDocs
	categoryTest
	categoryEngineering
)

type section struct {
	Title string
	Items []string
}

type releaseNotes struct {
	CurrentTag  string
	PreviousTag string
	Version     string
	Kind        releaseKind
	Sections    []section
}

type releaseKind string

const (
	releaseKindGo    releaseKind = "go"
	releaseKindSwift releaseKind = "swift"
)

func buildReleaseNotes(currentTag, previousTag string, kind releaseKind, commits []commit) *releaseNotes {
	features := make([]string, 0)
	fixes := make([]string, 0)
	auxiliary := make([]string, 0)
	seen := map[string]struct{}{}

	for _, item := range commits {
		kind, summary, keep := classifyCommit(item.Subject)
		if !keep {
			continue
		}
		if _, ok := seen[summary]; ok {
			continue
		}
		seen[summary] = struct{}{}
		switch kind {
		case categoryFix:
			fixes = append(fixes, summary)
		case categoryDocs, categoryTest, categoryEngineering:
			auxiliary = append(auxiliary, summary)
		default:
			features = append(features, summary)
		}
	}

	sections := make([]section, 0, 3)
	if len(features) > 0 {
		sections = append(sections, section{Title: "Features and Improvements", Items: features})
	}
	if len(fixes) > 0 {
		sections = append(sections, section{Title: "Fixes", Items: fixes})
	}
	if len(auxiliary) > 0 {
		sections = append(sections, section{Title: "Docs, Tests, and Release Engineering", Items: auxiliary})
	}
	if len(sections) == 0 {
		sections = append(sections, section{
			Title: "Included Changes",
			Items: []string{"No user-facing changes were detected beyond release preparation."},
		})
	}

	return &releaseNotes{
		CurrentTag:  currentTag,
		PreviousTag: previousTag,
		Version:     versionFromTag(currentTag, kind),
		Kind:        kind,
		Sections:    sections,
	}
}

func versionFromTag(tag string, kind releaseKind) string {
	if kind == releaseKindGo {
		return strings.TrimPrefix(tag, "flowersec-go/v")
	}
	return strings.TrimPrefix(tag, "v")
}

func renderMarkdown(notes *releaseNotes) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Flowersec %s\n\n", notes.Version)
	if notes.PreviousTag != "" {
		fmt.Fprintf(&b, "Changes since `%s`.\n\n", notes.PreviousTag)
	} else {
		b.WriteString("Initial published release snapshot.\n\n")
	}

	for _, sec := range notes.Sections {
		fmt.Fprintf(&b, "## %s\n\n", sec.Title)
		for _, item := range sec.Items {
			fmt.Fprintf(&b, "- %s\n", item)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Release Assets\n\n")
	if notes.Kind == releaseKindSwift {
		fmt.Fprintf(&b, "- SwiftPM package tag `%s` for the `Flowersec` library product.\n", notes.CurrentTag)
	} else {
		fmt.Fprintf(&b, "- `flowersec-runtime_%s_linux_<arch>` bundles for Linux amd64 and arm64 runtime deployments.\n", notes.Version)
		fmt.Fprintf(&b, "- `floegence-flowersec-core-%s.tgz` for no-clone TypeScript installs.\n", notes.Version)
		b.WriteString("- The multi-platform `ghcr.io/floegence/flowersec-runtime` image is also published for this version.\n")
	}
	return b.String()
}

func classifyCommit(subject string) (category, string, bool) {
	raw := strings.TrimSpace(subject)
	if raw == "" {
		return categoryEngineering, "", false
	}

	kind, scope, stripped := splitConventionalPrefix(raw)
	normalized := cleanSubject(stripped)
	lowerNormalized := strings.ToLower(normalized)

	if kind == "chore" && scope == "release" {
		if strings.HasPrefix(lowerNormalized, "prepare ") || strings.HasPrefix(lowerNormalized, "bump ") {
			return categoryEngineering, "", false
		}
	}

	switch {
	case kind == "fix" || strings.HasPrefix(lowerNormalized, "fix "):
		return categoryFix, normalized, true
	case kind == "docs" || strings.Contains(lowerNormalized, "readme") || strings.Contains(lowerNormalized, " docs ") || strings.HasPrefix(lowerNormalized, "docs "):
		return categoryDocs, normalized, true
	case kind == "test" || strings.Contains(lowerNormalized, "coverage") || strings.Contains(lowerNormalized, " e2e ") || strings.HasSuffix(lowerNormalized, " test") || strings.HasPrefix(lowerNormalized, "test "):
		return categoryTest, normalized, true
	case kind == "ci" || kind == "build" || kind == "refactor":
		return categoryEngineering, normalized, true
	case kind == "chore":
		return categoryEngineering, normalized, true
	default:
		return categoryFeature, normalized, true
	}
}

func splitConventionalPrefix(subject string) (kind, scope, rest string) {
	rest = strings.TrimSpace(subject)
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return "", "", rest
	}
	head := strings.TrimSpace(rest[:colon])
	body := strings.TrimSpace(rest[colon+1:])
	if head == "" || body == "" {
		return "", "", rest
	}
	kind = head
	scope = ""
	if open := strings.Index(head, "("); open >= 0 && strings.HasSuffix(head, ")") {
		kind = head[:open]
		scope = head[open+1 : len(head)-1]
	}
	if bang := strings.Index(kind, "!"); bang >= 0 {
		kind = kind[:bang]
	}
	for _, r := range kind {
		if !unicode.IsLower(r) && !unicode.IsDigit(r) && r != '-' {
			return "", "", rest
		}
	}
	return kind, scope, body
}

func cleanSubject(subject string) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return subject
	}
	runes := []rune(subject)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
