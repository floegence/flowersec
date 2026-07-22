package weaknet

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

// PacketPump relays one packet direction through a deterministic UDPRelay.
// It owns both PacketConns for its lifetime.
type PacketPump struct {
	source      net.PacketConn
	destination net.PacketConn
	target      net.Addr
	relay       *UDPRelay
	options     PumpOptions
	core        *pumpCore
}

func NewPacketPump(source, destination net.PacketConn, target net.Addr, relay *UDPRelay, options PumpOptions) (*PacketPump, error) {
	if source == nil || destination == nil || target == nil && options.PacketTargetResolver == nil || relay == nil {
		return nil, ErrInvalidPump
	}
	normalized, err := normalizePumpOptions(options, defaultPacketReadBuffer)
	if err != nil {
		return nil, err
	}
	if normalized.ReadBufferBytes < minimumPacketReadBuffer {
		return nil, ErrInvalidPump
	}
	return &PacketPump{
		source: source, destination: destination, target: target,
		relay: relay, options: normalized, core: newPumpCore(source, destination),
	}, nil
}

func (pump *PacketPump) Close() error { return pump.core.closeExplicitly() }

func (pump *PacketPump) Run(ctx context.Context) (runErr error) {
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
	if pump.relay.profile.QueueUnits > 0 {
		queueUnits = pump.relay.profile.QueueUnits
	}
	deliveries := make(chan UDPDelivery, queueUnits)
	writerDone := make(chan error, 1)
	go func() {
		err := pump.writePackets(runCtx, start, deliveries)
		if err != nil {
			cancel()
			_ = pump.core.closeConnections()
		}
		writerDone <- err
	}()

	buffer := make([]byte, pump.options.ReadBufferBytes)
	var readErr error
readLoop:
	for {
		n, sourceAddress, err := pump.source.ReadFrom(buffer)
		if sourceAddress != nil {
			target := pump.target
			if pump.options.PacketTargetResolver != nil {
				target, err = pump.options.PacketTargetResolver(sourceAddress)
				if err != nil || target == nil {
					if err == nil {
						err = ErrInvalidPump
					}
					readErr = err
					break
				}
			}
			at, elapsedErr := elapsedSince(pump.options.Clock, start)
			if elapsedErr != nil {
				readErr = elapsedErr
				break
			}
			output, processErr := pump.relay.Process(runCtx, Datagram{At: at, Payload: buffer[:n], Target: target})
			if processErr != nil {
				readErr = processErr
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
		}
		if err != nil {
			readErr = err
			break
		}
	}
	if readErr != nil {
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
	return io.EOF
}

func (pump *PacketPump) writePackets(ctx context.Context, start time.Time, deliveries <-chan UDPDelivery) error {
	for delivery := range deliveries {
		if err := pump.options.Clock.WaitUntil(ctx, start.Add(delivery.ReadyAt)); err != nil {
			return err
		}
		target := delivery.Target
		if target == nil {
			target = pump.target
		}
		written, err := pump.destination.WriteTo(delivery.Payload, target)
		if err != nil {
			return err
		}
		if written != len(delivery.Payload) {
			return io.ErrShortWrite
		}
		if err := pump.relay.Acknowledge(written); err != nil {
			return err
		}
	}
	return nil
}
