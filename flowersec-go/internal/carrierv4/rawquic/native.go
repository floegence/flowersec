package rawquic

import (
	"context"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
)

func (p *OwnedConnection) OpenNativeStream(ctx context.Context) (native.Stream, error) {
	s, err := p.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (p *OwnedConnection) AcceptNativeStream(ctx context.Context) (native.Stream, error) {
	s, err := p.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}

var _ native.Connection = (*OwnedConnection)(nil)
