package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func inspectRepository(path, baseSHA string) (RepositoryState, error) {
	if !gitSHAPattern.MatchString(baseSHA) {
		return RepositoryState{}, fmt.Errorf("base SHA %q must be a full lowercase Git SHA", baseSHA)
	}
	finalSHA, err := gitOutput(path, "rev-parse", "HEAD")
	if err != nil {
		return RepositoryState{}, err
	}
	status, err := gitOutput(path, "status", "--porcelain=v1", "--untracked-files=normal")
	if err != nil {
		return RepositoryState{}, err
	}
	untracked := 0
	if status != "" {
		for _, line := range strings.Split(status, "\n") {
			if strings.HasPrefix(line, "?? ") {
				untracked++
			}
		}
	}
	ancestor := exec.Command("git", "-C", path, "merge-base", "--is-ancestor", baseSHA, finalSHA)
	ancestor.Env = repositoryGitEnvironment()
	ancestorErr := ancestor.Run()
	if ancestorErr != nil {
		if exitErr, ok := ancestorErr.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			return RepositoryState{}, fmt.Errorf("inspect base ancestry: %w", ancestorErr)
		}
	}
	return RepositoryState{
		BaseSHA: baseSHA, FinalSHA: finalSHA, Dirty: status != "",
		UntrackedFileCount: untracked, BaseIsAncestor: ancestorErr == nil,
	}, nil
}

func gitOutput(path string, args ...string) (string, error) {
	commandArgs := append([]string{"-C", path}, args...)
	command := exec.Command("git", commandArgs...)
	command.Env = repositoryGitEnvironment()
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(output)), nil
}

func repositoryGitEnvironment() []string {
	environment := os.Environ()
	isolated := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "GIT_") {
			continue
		}
		isolated = append(isolated, entry)
	}
	return isolated
}
