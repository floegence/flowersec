package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	caseIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9-]*$`)
	targetPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	fieldPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

var registeredCaseOwnerTargets = map[string]struct{}{
	"bench-transport-capacity":    {},
	"bench-transport-soak":        {},
	"quic-native-proof":           {},
	"quic-native-race":            {},
	"quic-native-smoke":           {},
	"transport-browser-smoke":     {},
	"transport-conformance-full":  {},
	"transport-conformance-smoke": {},
	"weaknet-full":                {},
	"weaknet-system":              {},
}

func loadCaseRegistry(path string) (*CaseRegistry, error) {
	var registry CaseRegistry
	if err := decodeStrictFile(path, &registry); err != nil {
		return nil, err
	}
	return &registry, nil
}

func validateCaseRegistry(registry *CaseRegistry) error {
	if registry == nil {
		return errors.New("case registry is nil")
	}
	if registry.SchemaVersion != 1 {
		return fmt.Errorf("case registry schema_version = %d, want 1", registry.SchemaVersion)
	}
	if len(registry.Cases) == 0 {
		return errors.New("case registry is empty")
	}
	seen := make(map[string]struct{}, len(registry.Cases))
	for _, entry := range registry.Cases {
		if !caseIDPattern.MatchString(entry.ID) {
			return fmt.Errorf("invalid case ID %q", entry.ID)
		}
		if _, exists := seen[entry.ID]; exists {
			return fmt.Errorf("duplicate case ID %q", entry.ID)
		}
		seen[entry.ID] = struct{}{}
		if !targetPattern.MatchString(entry.Owner) {
			return fmt.Errorf("normal case %s must have exactly one owner target", entry.ID)
		}
		if _, registered := registeredCaseOwnerTargets[entry.Owner]; !registered {
			return fmt.Errorf("case %s owner target %q is not registered", entry.ID, entry.Owner)
		}
		if entry.RaceOwner != "" && !targetPattern.MatchString(entry.RaceOwner) {
			return fmt.Errorf("case %s has invalid race_owner %q", entry.ID, entry.RaceOwner)
		}
		if entry.RaceOwner != "" {
			if _, registered := registeredCaseOwnerTargets[entry.RaceOwner]; !registered {
				return fmt.Errorf("case %s race_owner target %q is not registered", entry.ID, entry.RaceOwner)
			}
		}
		if entry.Mode != "normal" && entry.Mode != "race" && entry.Mode != "perf" {
			return fmt.Errorf("case %s has invalid mode %q", entry.ID, entry.Mode)
		}
		if entry.Mode != "normal" && entry.Required {
			return fmt.Errorf("only normal cases may be required: %s", entry.ID)
		}
		if strings.TrimSpace(entry.Profile) == "" {
			return fmt.Errorf("case %s profile must not be empty", entry.ID)
		}
		if len(entry.EvidenceFields) == 0 {
			return fmt.Errorf("case %s evidence_fields must not be empty", entry.ID)
		}
		fields := make(map[string]struct{}, len(entry.EvidenceFields))
		for _, field := range entry.EvidenceFields {
			if !fieldPattern.MatchString(field) {
				return fmt.Errorf("case %s has invalid evidence field %q", entry.ID, field)
			}
			if _, exists := fields[field]; exists {
				return fmt.Errorf("case %s has duplicate evidence field %q", entry.ID, field)
			}
			fields[field] = struct{}{}
		}
	}
	return nil
}
