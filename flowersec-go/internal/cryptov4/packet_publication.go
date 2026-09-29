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
