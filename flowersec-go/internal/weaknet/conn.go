package weaknet

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

// ConnPump relays one reliable byte-stream direction through a ByteRelay. A
// single writer serializes every delivery, so modeled jitter can never reorder
// stream bytes. The pump owns both connections for its lifetime.
type ConnPump struct {
	source      net.Conn
	destination net.Conn
	relay       *ByteRelay
	options     PumpOptions
	core        *pumpCore
}

func NewConnPump(source, destination net.Conn, relay *ByteRelay, options PumpOptions) (*ConnPump, error) {
	if source == nil || destination == nil || relay == nil {
		return nil, ErrInvalidPump
	}
	normalized, err := normalizePumpOptions(options, defaultConnReadBuffer)
	if err != nil {
		return nil, err
	}
	if relay.profile.BackpressureBytes > 0 && normalized.ReadBufferBytes > relay.profile.BackpressureBytes {
		normalized.ReadBufferBytes = relay.profile.BackpressureBytes
	}
	if relay.profile.Rate.enabled() && relay.profile.CoalesceBytes == 0 && len(relay.profile.FragmentPattern) == 0 &&
		int64(normalized.ReadBufferBytes) > relay.profile.Rate.BurstBytes {
		normalized.ReadBufferBytes = int(relay.profile.Rate.BurstBytes)
	}
	if normalized.ReadBufferBytes <= 0 {
		return nil, ErrInvalidPump
	}
	if relay.profile.RequireHalfClose {
		if _, ok := destination.(closeWriter); !ok {
			return nil, ErrHalfCloseUnsupported
		}
	}
	return &ConnPump{
		source: source, destination: destination, relay: relay,
		options: normalized, core: newPumpCore(source, destination),
	}, nil
}

func (pump *ConnPump) Close() error { return pump.core.closeExplicitly() }

func (pump *ConnPump) Run(ctx context.Context) (runErr error) {
	defer func() {
		if runErr != nil {
			pump.relay.discardPending()
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := pump.core.start(); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	pump.core.bindCancel(cancel)
	defer cancel()
	stopClose := context.AfterFunc(runCtx, func() { _ = pump.core.closeConnections() })
	defer stopClose()
	defer pump.core.closeConnections()
	if err := ctx.Err(); err != nil {
		return err
	}

	start := pump.options.Clock.Now()
	queueUnits := defaultPumpQueueUnits
	if pump.relay.profile.BackpressureBytes > 0 && pump.relay.profile.BackpressureBytes < queueUnits {
		queueUnits = pump.relay.profile.BackpressureBytes
	}
	deliveries := make(chan ByteDelivery, queueUnits)
	acknowledged := make(chan struct{}, 1)
	writerDone := make(chan error, 1)
	go func() {
		err := pump.writeBytes(runCtx, start, deliveries, acknowledged)
		if err != nil {
			cancel()
			_ = pump.core.closeConnections()
		}
		writerDone <- err
	}()

	buffer := make([]byte, pump.options.ReadBufferBytes)
	var readErr error
	normalEOF := false
	backpressureRecorded := false
readLoop:
	for {
		readCapacity := pump.relay.readCapacity(len(buffer))
		if readCapacity == 0 {
			if !backpressureRecorded {
				pump.relay.recordBackpressure()
				if pump.options.OnBackpressure != nil {
					pump.options.OnBackpressure()
				}
				backpressureRecorded = true
			}
			select {
			case <-acknowledged:
				continue
			case <-runCtx.Done():
				readErr = runCtx.Err()
				break readLoop
			}
		}
		backpressureRecorded = false
		n, err := pump.source.Read(buffer[:readCapacity])
		if n > 0 {
			at, elapsedErr := elapsedSince(pump.options.Clock, start)
			if elapsedErr != nil {
				readErr = elapsedErr
				break
			}
			for {
				output, writeErr := pump.relay.Write(ByteChunk{At: at, Payload: buffer[:n]})
				if !errors.Is(writeErr, ErrBackpressure) {
					if writeErr != nil {
						readErr = writeErr
						break readLoop
					}
					for _, delivery := range output {
						select {
						case deliveries <- delivery:
						case <-runCtx.Done():
							readErr = runCtx.Err()
							break readLoop
						}
					}
					break
				}
				select {
				case <-acknowledged:
				case <-runCtx.Done():
					readErr = runCtx.Err()
					break readLoop
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				normalEOF = true
				at, elapsedErr := elapsedSince(pump.options.Clock, start)
				if elapsedErr != nil {
					readErr = elapsedErr
					break
				}
				output, closeErr := pump.relay.CloseWrite(at)
				if closeErr != nil {
					readErr = closeErr
					break
				}
				for _, delivery := range output {
					select {
					case deliveries <- delivery:
					case <-runCtx.Done():
						readErr = runCtx.Err()
						break readLoop
					}
				}
			} else {
				readErr = err
			}
			break
		}
	}
	if readErr != nil && !normalEOF {
		cancel()
	}
	close(deliveries)
	writerErr := <-writerDone
	if classified := pump.core.classify(ctx, nil); classified != nil {
		return classified
	}
	if writerErr != nil && !errors.Is(writerErr, context.Canceled) {
		return writerErr
	}
	if readErr != nil {
		return readErr
	}
	if normalEOF {
		return nil
	}
	return io.ErrUnexpectedEOF
}

func (pump *ConnPump) writeBytes(ctx context.Context, start time.Time, deliveries <-chan ByteDelivery, acknowledged chan<- struct{}) error {
	for delivery := range deliveries {
		if err := pump.options.Clock.WaitUntil(ctx, start.Add(delivery.ReadyAt)); err != nil {
			return err
		}
		written, err := writeFull(pump.destination, delivery.Payload)
		if err != nil {
			if accountingErr := pump.relay.acknowledgeWrite(uint64(written), false); accountingErr != nil {
				return errors.Join(err, accountingErr)
			}
			return err
		}
		acknowledgedPayload := false
		if delivery.HalfClose && len(delivery.Payload) > 0 {
			if err := pump.relay.Acknowledge(uint64(len(delivery.Payload))); err != nil {
				return err
			}
			acknowledgedPayload = true
			select {
			case acknowledged <- struct{}{}:
			default:
			}
		}
		if delivery.HalfClose {
			if destination, ok := pump.destination.(closeWriter); ok {
				if err := destination.CloseWrite(); err != nil {
					return err
				}
			} else if pump.relay.profile.RequireHalfClose {
				return ErrHalfCloseUnsupported
			} else if err := pump.destination.Close(); err != nil {
				return err
			}
		}
		if !acknowledgedPayload {
			if err := pump.relay.Acknowledge(uint64(len(delivery.Payload))); err != nil {
				return err
			}
		}
		if len(delivery.Payload) > 0 && !acknowledgedPayload {
			select {
			case acknowledged <- struct{}{}:
			default:
			}
		}
	}
	return nil
}
