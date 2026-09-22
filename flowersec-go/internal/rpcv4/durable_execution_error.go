package rpcv4

import (
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
)

// Preserve the provider cause while exposing the established RPC refusal.
func durableExecutionError(err error) error {
	var classification error
	switch {
	case errors.Is(err, ledgerv4.ErrConflict):
		classification = ErrExecutionConflict
	case errors.Is(err, ledgerv4.ErrExecutionCancelUnsupported):
		classification = ErrExecutionUnsupported
	case errors.Is(err, ledgerv4.ErrExecutionHistoryUnknown):
		classification = ErrHistoryUnknown
	case errors.Is(err, ledgerv4.ErrExecutionResultUnavailable):
		classification = ErrResultUnavailable
	case errors.Is(err, ledgerv4.ErrExecutionResultExpired):
		classification = ErrResultExpired
	case errors.Is(err, ledgerv4.ErrCapacity):
		classification = ErrCapacity
	}
	if classification != nil {
		return errors.Join(classification, err)
	}
	return err
}
