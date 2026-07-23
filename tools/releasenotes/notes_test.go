package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildReleaseNotesSkipsReleaseHousekeeping(t *testing.T) {
	notes := buildReleaseNotes("flowersec-go/v0.18.0", "flowersec-go/v0.17.1", releaseKindGo, []commit{
		{Hash: "1", Subject: "feat: add browser orchestration helpers"},
		{Hash: "2", Subject: "fix: preserve browser controlplane error details"},
		{Hash: "3", Subject: "docs: refresh README for product storytelling"},
		{Hash: "4", Subject: "chore(release): prepare v0.18.0"},
		{Hash: "5", Subject: "chore(release): bump flowersec-core to v0.18.0"},
	})

	md := renderMarkdown(notes)
	if !strings.Contains(md, "## Features and Improvements") {
		t.Fatalf("expected features section, got:\n%s", md)
	}
	if !strings.Contains(md, "- Add browser orchestration helpers") {
		t.Fatalf("expected feature summary, got:\n%s", md)
	}
	if !strings.Contains(md, "## Fixes") {
		t.Fatalf("expected fixes section, got:\n%s", md)
	}
	if strings.Contains(md, "prepare v0.18.0") || strings.Contains(md, "bump flowersec-core") {
		t.Fatalf("release housekeeping should be omitted, got:\n%s", md)
	}
	if !strings.Contains(md, "## Release Assets") {
		t.Fatalf("expected assets section, got:\n%s", md)
	}
}

func TestBuildSwiftReleaseNotesUsesRootTagAndSwiftPMAssets(t *testing.T) {
	notes := buildReleaseNotes("0.19.11", "", releaseKindSwift, []commit{
		{Hash: "1", Subject: "feat(swift): publish flowersec swift client"},
	})

	md := renderMarkdown(notes)
	if !strings.Contains(md, "# Flowersec 0.19.11") {
		t.Fatalf("expected Swift release heading, got:\n%s", md)
	}
	if !strings.Contains(md, "SwiftPM package tag `0.19.11`") {
		t.Fatalf("expected SwiftPM asset note, got:\n%s", md)
	}
	if strings.Contains(md, "flowersec-runtime_0.19.11") || strings.Contains(md, "flowersec-runtime` image") {
		t.Fatalf("Swift release notes must not list Go release assets, got:\n%s", md)
	}
}

func TestGoReleaseNotesAreGeneratedFromCommitTitles(t *testing.T) {
	repo := newReleaseNotesRepo(t)
	commitFile(t, repo, "feature.txt", "feature\n", "feat: add secure transport contracts")
	runGit(t, repo, "tag", "flowersec-go/v0.26.0")

	notes, err := loadReleaseNotes(repo, "flowersec-go/v0.26.0", "flowersec-go/v0.26.0")
	if err != nil {
		t.Fatal(err)
	}
	md := renderMarkdown(notes)
	if !strings.Contains(md, "Add secure transport contracts") {
		t.Fatalf("expected changelog generated from commit titles, got:\n%s", md)
	}
}

func TestGoReleaseNotesRenderBeforeCurrentTagExists(t *testing.T) {
	repo := newReleaseNotesRepo(t)
	commitFile(t, repo, "baseline.txt", "baseline\n", "feat: publish baseline")
	runGit(t, repo, "tag", "flowersec-go/v0.25.0")
	commitFile(t, repo, "feature.txt", "feature\n", "feat: prepare secure transport release")

	notes, err := loadReleaseNotes(repo, "flowersec-go/v0.26.0", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if notes.PreviousTag != "flowersec-go/v0.25.0" {
		t.Fatalf("previous tag = %q, want flowersec-go/v0.25.0", notes.PreviousTag)
	}
	if !strings.Contains(renderMarkdown(notes), "Prepare secure transport release") {
		t.Fatal("preflight release notes must include commits from HEAD")
	}
}

func TestFindPreviousTagRejectsCurrentTagOutsideReleaseCommit(t *testing.T) {
	repo := newReleaseNotesRepo(t)
	commitFile(t, repo, "main.txt", "main\n", "feat: publish baseline")
	runGit(t, repo, "tag", "flowersec-go/v0.25.0")
	runGit(t, repo, "switch", "-c", "other")
	commitFile(t, repo, "other.txt", "other\n", "feat: unrelated release commit")
	runGit(t, repo, "tag", "flowersec-go/v0.26.0")
	runGit(t, repo, "switch", "-")

	_, err := findPreviousTag(repo, "HEAD", "flowersec-go/v0.26.0", releaseKindGo)
	if err == nil || !strings.Contains(err.Error(), "not found among tags merged") {
		t.Fatalf("expected an unmerged current tag error, got %v", err)
	}
}

func TestFindPreviousTagAndCollectCommits(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.name", "Codex")
	runGit(t, repo, "config", "user.email", "codex@example.com")

	writeFile(t, filepath.Join(repo, "README.md"), "first\n")
	runGit(t, repo, "add", "README.md")
	runGit(t, repo, "commit", "-m", "docs: initial release docs")
	runGit(t, repo, "tag", "flowersec-go/v0.17.0")

	writeFile(t, filepath.Join(repo, "feature.txt"), "feature\n")
	runGit(t, repo, "add", "feature.txt")
	runGit(t, repo, "commit", "-m", "feat: add release notes generator")

	writeFile(t, filepath.Join(repo, "fix.txt"), "fix\n")
	runGit(t, repo, "add", "fix.txt")
	runGit(t, repo, "commit", "-m", "fix: include feature summaries in releases")
	runGit(t, repo, "tag", "flowersec-go/v0.18.0")

	prev, err := findPreviousTag(repo, "HEAD", "flowersec-go/v0.18.0", releaseKindGo)
	if err != nil {
		t.Fatal(err)
	}
	if prev != "flowersec-go/v0.17.0" {
		t.Fatalf("expected previous tag flowersec-go/v0.17.0, got %q", prev)
	}

	commits, err := collectCommits(repo, "HEAD", prev)
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 2 {
		t.Fatalf("expected 2 commits, got %d", len(commits))
	}
	if commits[0].Subject != "feat: add release notes generator" {
		t.Fatalf("unexpected first commit: %#v", commits[0])
	}
	if commits[1].Subject != "fix: include feature summaries in releases" {
		t.Fatalf("unexpected second commit: %#v", commits[1])
	}
}

func TestFindPreviousSwiftRootTagAndCollectCommits(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.name", "Codex")
	runGit(t, repo, "config", "user.email", "codex@example.com")

	writeFile(t, filepath.Join(repo, "Package.swift"), "package\n")
	runGit(t, repo, "add", "Package.swift")
	runGit(t, repo, "commit", "-m", "feat(swift): add package manifest")
	runGit(t, repo, "tag", "0.19.10")

	writeFile(t, filepath.Join(repo, "Swift.swift"), "sdk\n")
	runGit(t, repo, "add", "Swift.swift")
	runGit(t, repo, "commit", "-m", "feat(swift): expose rpc client")
	runGit(t, repo, "tag", "0.19.11")

	prev, err := findPreviousTag(repo, "HEAD", "0.19.11", releaseKindSwift)
	if err != nil {
		t.Fatal(err)
	}
	if prev != "0.19.10" {
		t.Fatalf("expected previous tag 0.19.10, got %q", prev)
	}

	commits, err := collectCommits(repo, "HEAD", prev)
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(commits))
	}
	if commits[0].Subject != "feat(swift): expose rpc client" {
		t.Fatalf("unexpected commit: %#v", commits[0])
	}
}

func TestFirstSwiftRootTagFallsBackToLatestGoTag(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.name", "Codex")
	runGit(t, repo, "config", "user.email", "codex@example.com")

	writeFile(t, filepath.Join(repo, "README.md"), "go release\n")
	runGit(t, repo, "add", "README.md")
	runGit(t, repo, "commit", "-m", "fix: publish go baseline")
	runGit(t, repo, "tag", "flowersec-go/v0.19.10")

	writeFile(t, filepath.Join(repo, "Package.swift"), "swift package\n")
	runGit(t, repo, "add", "Package.swift")
	runGit(t, repo, "commit", "-m", "feat(swift): publish swift package")

	notes, err := loadReleaseNotes(repo, "0.19.11", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if notes.PreviousTag != "flowersec-go/v0.19.10" {
		t.Fatalf("expected previous Go baseline, got %q", notes.PreviousTag)
	}
	md := renderMarkdown(notes)
	if !strings.Contains(md, "Publish swift package") {
		t.Fatalf("expected Swift commit in notes, got:\n%s", md)
	}
	if strings.Contains(md, "Publish go baseline") {
		t.Fatalf("first Swift notes must not include prior Go history, got:\n%s", md)
	}
}

func TestSwiftReleaseNotesDereferenceAnnotatedTag(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.name", "Codex")
	runGit(t, repo, "config", "user.email", "codex@example.com")

	writeFile(t, filepath.Join(repo, "README.md"), "go release\n")
	runGit(t, repo, "add", "README.md")
	runGit(t, repo, "commit", "-m", "fix: publish go baseline")
	runGit(t, repo, "tag", "flowersec-go/v0.19.10")

	writeFile(t, filepath.Join(repo, "Package.swift"), "swift package\n")
	runGit(t, repo, "add", "Package.swift")
	runGit(t, repo, "commit", "-m", "feat(swift): publish swift package")
	runGit(t, repo, "tag", "-a", "0.19.11", "-m", "Flowersec Swift 0.19.11")

	notes, err := loadReleaseNotes(repo, "0.19.11", "0.19.11")
	if err != nil {
		t.Fatal(err)
	}
	if notes.PreviousTag != "flowersec-go/v0.19.10" {
		t.Fatalf("expected previous Go baseline, got %q", notes.PreviousTag)
	}
	if notes.Sections[0].Items[0] != "Publish swift package" {
		t.Fatalf("unexpected notes: %#v", notes.Sections)
	}
}

func TestReleaseKindForTag(t *testing.T) {
	tests := []struct {
		tag  string
		kind releaseKind
	}{
		{tag: "flowersec-go/v0.19.10", kind: releaseKindGo},
		{tag: "0.19.11", kind: releaseKindSwift},
	}
	for _, tt := range tests {
		got, err := releaseKindForTag(tt.tag)
		if err != nil {
			t.Fatalf("releaseKindForTag(%q): %v", tt.tag, err)
		}
		if got != tt.kind {
			t.Fatalf("releaseKindForTag(%q) = %q, want %q", tt.tag, got, tt.kind)
		}
	}
	if _, err := releaseKindForTag("release-1"); err == nil {
		t.Fatal("expected unsupported tag error")
	}
	if _, err := releaseKindForTag("v0.19.11"); err == nil {
		t.Fatal("expected prefixed Swift tag error")
	}
}

func newReleaseNotesRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.name", "Codex")
	runGit(t, repo, "config", "user.email", "codex@example.com")
	return repo
}

func commitFile(t *testing.T, repo, name, body, subject string) {
	t.Helper()
	writeFile(t, filepath.Join(repo, name), body)
	runGit(t, repo, "add", name)
	runGit(t, repo, "commit", "-m", subject)
}

func runGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	cmd.Env = cleanGitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
