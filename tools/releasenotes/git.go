package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type commit struct {
	Hash    string
	Subject string
}

func loadReleaseNotes(repoPath, currentTag, currentRef string) (*releaseNotes, error) {
	previousTag, err := findPreviousTag(repoPath, currentRef, currentTag)
	if err != nil {
		return nil, err
	}
	commits, err := collectCommits(repoPath, currentRef, previousTag)
	if err != nil {
		return nil, err
	}
	return buildReleaseNotes(currentTag, previousTag, commits), nil
}

func findPreviousTag(repoPath, currentRef, currentTag string) (string, error) {
	lines, err := gitLines(repoPath, "tag", "--merged", currentRef, "--list", "flowersec-go/v*", "--sort=version:refname")
	if err != nil {
		return "", err
	}
	if len(lines) == 0 {
		return "", nil
	}
	for i, tag := range lines {
		if tag != currentTag {
			continue
		}
		if i == 0 {
			return "", nil
		}
		return lines[i-1], nil
	}
	return "", fmt.Errorf("current tag %q not found among tags merged into %s", currentTag, currentRef)
}

func collectCommits(repoPath, currentRef, previousTag string) ([]commit, error) {
	rangeSpec := currentRef
	if previousTag != "" {
		rangeSpec = previousTag + ".." + currentRef
	}
	out, err := gitOutput(repoPath, "log", "--no-merges", "--reverse", "--format=%H%x1f%s%x1e", rangeSpec)
	if err != nil {
		return nil, err
	}

	rawEntries := strings.Split(string(out), "\x1e")
	commits := make([]commit, 0, len(rawEntries))
	for _, entry := range rawEntries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		fields := strings.Split(entry, "\x1f")
		if len(fields) != 2 {
			return nil, fmt.Errorf("unexpected git log record %q", entry)
		}
		commits = append(commits, commit{
			Hash:    strings.TrimSpace(fields[0]),
			Subject: strings.TrimSpace(fields[1]),
		})
	}
	return commits, nil
}

func gitLines(repoPath string, args ...string) ([]string, error) {
	out, err := gitOutput(repoPath, args...)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return lines, nil
}

func gitOutput(repoPath string, args ...string) ([]byte, error) {
	cmdArgs := append([]string{"-C", repoPath}, args...)
	cmd := exec.Command("git", cmdArgs...)
	cmd.Env = cleanGitEnv()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return stdout.Bytes(), nil
}

func cleanGitEnv() []string {
	env := os.Environ()
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, "GIT_") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}
