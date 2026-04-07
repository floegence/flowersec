package internalnormalize

import (
	"context"
	"fmt"

	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

type ScopeResolver func(context.Context, protocolio.ScopeMetadataEntry) error

type ScopeValidationOptions struct {
	Resolvers                      map[string]ScopeResolver
	RelaxedOptionalScopeValidation bool
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
			continue
		}
		if err := resolver(ctx, entry); err != nil {
			if !entry.Critical && opts.RelaxedOptionalScopeValidation {
				continue
			}
			return fmt.Errorf("scope validation failed for %s@%d: %w", entry.Scope, entry.ScopeVersion, err)
		}
	}
	return nil
}
