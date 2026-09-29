package controlv4

import (
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func poolControlError(err error) error {
	if errors.Is(err, ErrResponse) {
		fact, _ := protocolv4.TopUpErrorProjection(protocolv4.V4TopUpErrorCodeSourceContractInvalid, protocolv4.V4TopUpWriteActionNone)
		return errors.Join(err, ledgerv4.TopUpFailure{Fact: fact})
	}
	return err
}

func checkPoolControlResult(method uint32, applicationError bool, r sessionv4.TopUpExchangeResult, capacity int) error {
	if method != ControlPoolTopUp && method != ControlPoolAck || applicationError != (r.Code != "") {
		return ErrResponse
	}
	if applicationError {
		if _, ok := protocolv4.TopUpErrorProjection(r.Code, protocolv4.V4TopUpWriteActionNone); !ok || r.ResponseBytes != 0 || r.Replay {
			return ErrResponse
		}
		if r.FenceEvidence != nil {
			if r.Code != protocolv4.V4TopUpErrorCodeSourceResetRequired || r.Evidence != nil || r.Terminal != (ledgerv4.TopUpServerSnapshot{}) || r.Fence.Tenant == "" || r.Fence.Source == ([16]byte{}) || r.Fence.Generation == 0 {
				return ErrResponse
			}
			return nil
		}
		if r.Fence != (ledgerv4.TopUpPermanentFenceReceipt{}) {
			return ErrResponse
		}
		if r.Evidence == nil {
			if r.Terminal != (ledgerv4.TopUpServerSnapshot{}) {
				return ErrResponse
			}
		} else if r.Terminal.Terminal != r.Code || r.Code == protocolv4.V4TopUpErrorCodePermissionDenied {
			return ErrResponse
		}
		return nil
	}
	if r.Evidence != nil || r.Terminal != (ledgerv4.TopUpServerSnapshot{}) || r.FenceEvidence != nil || r.Fence != (ledgerv4.TopUpPermanentFenceReceipt{}) || r.ResponseBytes < 0 || r.ResponseBytes > capacity || method == ControlPoolTopUp && r.ResponseBytes == 0 || method == ControlPoolAck && r.ResponseBytes != 0 {
		return ErrResponse
	}
	return nil
}
