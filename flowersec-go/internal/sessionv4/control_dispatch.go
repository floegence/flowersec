package sessionv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// dispatchControl gives shared and native maintenance input the same semantic
// gate. Authentication alone never substitutes for the original state owner.
func (a *OpenAdmission) dispatchControl(ctx context.Context, record *ReceivedRecord, deadline *timev4.Deadline) error {
	if record == nil || record.receiver.engine != a.engine || record.receiver.direction != 1-a.direction {
		return ErrOpenAssociation
	}
	f, err := record.Body()
	if err != nil {
		return err
	}
	return a.dispatchControlFrame(ctx, record, deadline, f)
}

func (a *OpenAdmission) dispatchControlFrame(ctx context.Context, record *ReceivedRecord, deadline *timev4.Deadline, f *protocolv4.Frame) error {
	if record == nil || f == nil || record.receiver.engine != a.engine || record.receiver.direction != 1-a.direction {
		return ErrOpenAssociation
	}
	a.mu.Lock()
	messages, retirement, exchange, rekey := a.maintenanceMessages, a.retirement, a.exchange, a.rekeyService
	a.mu.Unlock()
	switch f.Schema {
	case "GOAWAY", "CLOSE", "ERROR":
		return a.applyLifecycleControl(record)
	case "STREAM_ACK_CREDIT", "STREAM_ACK_STOP", "STREAM_ACK_STOPPED", "STREAM_ACK_DRAINED", "OPEN_ACCEPT":
		return a.ApplyMaintenance(record)
	case "PING", "PONG":
		if messages != nil {
			_, err := messages.handleFrame(record, f)
			if errors.Is(err, ErrMaintenanceRate) || errors.Is(err, errPongQueueFull) {
				return errMaintenanceDiscarded
			}
			return err
		}
		return cryptov4.ErrConfiguration
	case "STREAM_ACK_RETIRE_BATCH", "STREAM_ACK_RETIRE_ACK":
		if retirement != nil {
			return retirement.Receive(record, deadline)
		}
	case "REKEY_REQUEST", "REKEY_INIT", "REKEY_REPLY", "REKEY_COMMIT", "REKEY_ACK":
		if rekey != nil {
			return rekey.Handle(ctx, record)
		}
		if exchange != nil {
			return exchange.Handle(record)
		}
	}
	return cryptov4.ErrConfiguration
}
