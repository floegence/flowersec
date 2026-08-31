package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/floegence/flowersec/flowersec-go/v4/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/issuervector"
)

const fixtureRelativePath = "testdata/transport_v3/go_issuer_admission_vectors.json"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("issuer-admission-vectors", flag.ContinueOnError)
	write := flags.Bool("write", false, "rewrite the shared fixture")
	check := flags.Bool("check", false, "verify the shared fixture (default)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*write && *check) {
		return errors.New("usage: issuer-admission-vectors [--check|--write]")
	}
	fixturePath, err := findFixturePath()
	if err != nil {
		return err
	}
	generated, err := issuervector.Generate()
	if err != nil {
		return err
	}
	if *write {
		if err := os.WriteFile(fixturePath, generated, 0o644); err != nil {
			return fmt.Errorf("write issuer admission fixture: %w", err)
		}
		fmt.Printf("wrote %s\n", fixturePath)
		return nil
	}
	current, err := os.ReadFile(fixturePath)
	if err != nil {
		return fmt.Errorf("read issuer admission fixture: %w", err)
	}
	if !bytes.Equal(current, generated) {
		return errors.New("Go issuer admission fixture is stale; run with --write")
	}
	fmt.Printf("verified %s\n", fixturePath)
	return nil
}

func findFixturePath() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(directory, fixtureRelativePath)
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", errors.New("cannot locate testdata/transport_v3/go_issuer_admission_vectors.json")
		}
		directory = parent
	}
}
