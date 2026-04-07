package internalnormalize

import (
	"context"
	"fmt"

	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

type ScopeResolver func(context.Context, protocolio.ScopeMetadataEntry) error

type ScopeWarningKind string

const (
	ScopeWarningMissingResolver          ScopeWarningKind = "missing_resolver"
	ScopeWarningRelaxedValidationIgnored ScopeWarningKind = "relaxed_validation_ignored"
)

type ScopeWarning struct {
	Entry protocolio.ScopeMetadataEntry
	Kind  ScopeWarningKind
	Err   error
}

type ScopeWarningSink func(ScopeWarning)

type ScopeValidationOptions struct {
	Resolvers                      map[string]ScopeResolver
	RelaxedOptionalScopeValidation bool
	WarningSink                    ScopeWarningSink
}

func ValidateArtifactScopes(ctx context.Context, artifact *protocolio.ConnectArtifact, opts ScopeValidationOptions) error {
	if artifact == nil || len(artifact.Scoped) == 0 {
		return nil
	}
	for _, entry := range artifact.Scoped {
		resolver := opts.Resolvers[entry.Scope]
		if resolver == nil {
			if entry.Critical {
				return fmt.Errorf("missing scope resolver for %s@%d", entry.Scope, entry.ScopeVersion)
			}
			if opts.WarningSink != nil {
				opts.WarningSink(ScopeWarning{
					Entry: entry,
					Kind:  ScopeWarningMissingResolver,
				})
			}
			continue
		}
		if err := resolver(ctx, entry); err != nil {
			if !entry.Critical && opts.RelaxedOptionalScopeValidation {
				if opts.WarningSink != nil {
					opts.WarningSink(ScopeWarning{
						Entry: entry,
						Kind:  ScopeWarningRelaxedValidationIgnored,
						Err:   err,
					})
				}
				continue
			}
			return fmt.Errorf("scope validation failed for %s@%d: %w", entry.Scope, entry.ScopeVersion, err)
		}
	}
	return nil
}
