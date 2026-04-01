package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildReleaseNotesSkipsReleaseHousekeeping(t *testing.T) {
	notes := buildReleaseNotes("flowersec-go/v0.18.0", "flowersec-go/v0.17.1", []commit{
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

	prev, err := findPreviousTag(repo, "HEAD", "flowersec-go/v0.18.0")
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
