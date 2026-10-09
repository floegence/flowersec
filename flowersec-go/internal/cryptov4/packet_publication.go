package cryptov4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"

// MoveReliableOutput transfers an already sealed application envelope into its
// original Stream's preadmitted publication backing. The Packet remains the
// unique epoch/key/publication owner until Release, but no longer occupies a
// shared authentication workspace while its provider is blocked. The caller
// relinquishes all aliases to dst until that Release; this is neither another
// record ticket nor a replacement publication permission.
func (p *Packet) MoveReliableOutput(dst []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.moveReliableOutputLocked(dst)
}

func (p *Packet) moveReliableOutputLocked(dst []byte) error {
	if p.released {
		return ErrClosed
	}
	if !p.outgoing || p.datagram || p.scope == 0 || p.workspace == nil || len(dst) < len(p.data) {
		return ErrConfiguration
	}
	frame := protocolv4.FrameType(p.data[4])
	if frame != protocolv4.FrameStreamData && frame != protocolv4.FrameOpenStream {
		return ErrConfiguration
	}
	p.engine.mu.Lock()
	err := p.engine.live()
	if err == nil && (p.engine.detachedPackets >= p.engine.config.MaxScopes || p.key.detached) {
		err = ErrCapacity
	}
	if err == nil {
		p.engine.detachedPackets++
		p.key.detached = true
	}
	p.engine.mu.Unlock()
	if err != nil {
		return err
	}
	w := p.workspace
	n := copy(dst, p.data)
	p.data, p.workspace = dst[:n], nil
	p.engine.release(w)
	return nil
}

// PreparePublication reads metadata and moves this same original ciphertext
// under one packet gate. It returns no provider publication permission: the
// writer still calls Bytes at each actual provider attempt after its SDK hooks.
func (p *Packet) PreparePublication(dst []byte) (protocolv4.FrameType, protocolv4.RecordHeader, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var header protocolv4.RecordHeader
	if p.released {
		return 0, header, ErrClosed
	}
	if !p.outgoing {
		return 0, header, ErrConfiguration
	}
	frame, header, _, err := protocolv4.ParseRecord(p.data, p.engine.config.Profile, p.engine.config.MaxFrame)
	if err != nil {
		return frame, header, err
	}
	if dst != nil && (frame == protocolv4.FrameStreamData || frame == protocolv4.FrameOpenStream) {
		err = p.moveReliableOutputLocked(dst)
	} else {
		_, err = p.bytesLocked()
	}
	return frame, header, err
}
