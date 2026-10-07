package ledgerv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// SQLiteOriginalParentWinnerContinuation belongs to an original registered
// publication. It compares the canonical control projection of the local
// admission selection (EncodePoolWinnerControlProjection) with the
// original relay publication, then matches the already committed remote winner.
// It cannot create a winner, replay admission, or retry an ambiguous result.
type SQLiteOriginalParentWinnerContinuation interface {
	ContinueOriginalParentWinner(context.Context, []byte, []byte, resourcev4.Reference, func() error) error
}
