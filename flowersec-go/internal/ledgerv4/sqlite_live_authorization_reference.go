package ledgerv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"

// LiveAuthorizationReference binds a concrete service to the original physical
// store. Current fencing remains a transaction/read check on every request.
func (s *SQLiteStore) LiveAuthorizationReference(environment resourcev4.Reference) (resourcev4.Reference, SQLiteIdentity, uint32, error) {
	ref, identity, _, limit, err := s.admissionReference(environment)
	return ref, identity, limit, err
}
