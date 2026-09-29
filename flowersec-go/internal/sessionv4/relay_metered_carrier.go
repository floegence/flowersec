package sessionv4

import (
	"context"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

// The relay bit is private and cannot be set on an endpoint preparation.
// Role names the remote logical endpoint; the local physical role is relay.
func NewPreparedRelayStream(ctx context.Context, c PreparedCarrierConfig, stream io.ReadWriteCloser) (*PreparedCarrier, error) {
	c.relay = true
	return NewPreparedStream(ctx, c, stream)
}

func NewPreparedRelayMessages(ctx context.Context, c PreparedCarrierConfig, messages InitialMessages) (*PreparedCarrier, error) {
	c.relay = true
	return NewPreparedMessages(ctx, c, messages)
}

func settleRelayIO(receipt relayByteReservation, n, maximum int, uncertain bool, err *error) {
	if receipt.owner == nil {
		return
	}
	if n < 0 || n > maximum {
		n, uncertain = 0, true
		*err = cryptov4.ErrConfiguration
	}
	if settle := receipt.settle(uint64(n), uncertain); settle != nil && *err == nil {
		*err = settle
	}
}

func (p *preparedCarrier) meteredRead(dst []byte) (n int, err error) {
	if p.relayBudget == nil || len(dst) == 0 {
		return p.stream.Read(dst)
	}
	receipt, err := p.relayBudget.reserveWait(uint64(len(dst)))
	if err != nil {
		return 0, err
	}
	returned := false
	defer func() { settleRelayIO(receipt, n, len(dst), !returned, &err) }()
	n, err = p.stream.Read(dst)
	returned = true
	return
}

func (p *preparedCarrier) meteredWrite(src []byte) (n int, err error) {
	if p.relayBudget == nil || len(src) == 0 {
		return p.stream.Write(src)
	}
	receipt, err := p.relayBudget.reserveWait(uint64(len(src)))
	if err != nil {
		return 0, err
	}
	returned := false
	defer func() { settleRelayIO(receipt, n, len(src), !returned, &err) }()
	n, err = p.stream.Write(src)
	returned = true
	return
}

func (p *preparedCarrier) meteredReadMessage(ctx context.Context, dst []byte) (n int, err error) {
	if p.relayBudget == nil {
		return p.messages.ReadMessage(ctx, dst)
	}
	receipt, err := p.relayBudget.reserveWait(uint64(len(dst)))
	if err != nil {
		return 0, err
	}
	returned := false
	defer func() { settleRelayIO(receipt, n, len(dst), !returned, &err) }()
	n, err = p.messages.ReadMessage(ctx, dst)
	returned = true
	return
}

func (p *preparedCarrier) meteredWriteMessage(ctx context.Context, src []byte) (err error) {
	if p.relayBudget == nil {
		return p.messages.WriteMessage(ctx, src)
	}
	receipt, err := p.relayBudget.reserveWait(uint64(len(src)))
	if err != nil {
		return err
	}
	returned := false
	defer func() { settleRelayIO(receipt, len(src), len(src), !returned || err != nil, &err) }()
	err = p.messages.WriteMessage(ctx, src)
	returned = true
	return
}
