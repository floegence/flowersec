package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("releasenotes", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	repo := fs.String("repo", ".", "path to the git repository")
	currentTag := fs.String("current-tag", "", "current release tag, for example flowersec-go/v0.17.1")
	currentRef := fs.String("current-ref", "", "git ref or commit to inspect; defaults to --current-tag")
	output := fs.String("output", "", "optional output file; stdout when empty")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *currentTag == "" {
		return errors.New("missing required flag: --current-tag")
	}
	if *currentRef == "" {
		*currentRef = *currentTag
	}

	repoPath, err := filepath.Abs(*repo)
	if err != nil {
		return err
	}
	notes, err := loadReleaseNotes(repoPath, *currentTag, *currentRef)
	if err != nil {
		return err
	}
	markdown := renderMarkdown(notes)
	if *output == "" {
		_, err = fmt.Print(markdown)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		return err
	}
	return os.WriteFile(*output, []byte(markdown), 0o644)
}
