package sessionv4

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

const httpUpgradePiece = 64 * 1024

var ErrHTTPUpgrade = errors.New("sessionv4: HTTP upgrade failed")

// ControlledHTTPUpgradeConfig prepays both bounded copy loops and the maximum
// upstream parser head. ExternalRuntime must also cover the transferred native
// endpoint and its provider queues. RuntimeBytes is its qualified Go task and
// allocator allowance; this declaration does not constrain arbitrary net.Conn
// implementations. Nil Upgrade disables this transfer completely.
type ControlledHTTPUpgradeConfig struct {
	MaxHeadBytes uint32
	RuntimeBytes uint64
}

// HTTPUpgradePeer is a trusted, exclusively transferred native endpoint with
// real write half-close. Its Close must interrupt outstanding I/O. A provider
// that does not cooperate keeps the original service charged until real exit.
type HTTPUpgradePeer interface {
	net.Conn
	CloseWrite() error
}

// HTTPStreamUpgrader is the controlled alternative to obtaining a bare hijacked
// connection. The request handler writes a 101 response, transfers an authorized
// endpoint and its buffered incoming head, and returns. Only after its actual
// return do the SDK copy loops start; no ordinary permit covers idle upgraded
// I/O. On success the caller must never use peer again. On failure it retains
// peer. Head is copied before return and may then be reused by the caller.
type HTTPStreamUpgrader interface {
	BridgeUpgrade(peer HTTPUpgradePeer, head []byte) error
}

type controlledHTTPUpgrade struct {
	peer     HTTPUpgradePeer
	buffered *bufio.ReadWriter
	head     []byte
	pieces   [2][httpUpgradePiece]byte
	headSize int
	ready    chan struct{}
	// All state is under the original HTTP service gate.
	claimed, started bool
	running          uint8
}

func controlledHTTPStreamCharge(o HTTPStreamOptions, upgrade *ControlledHTTPUpgradeConfig) (resourcev4.Vector, error) {
	charge, err := HTTPStreamCharge(o)
	if err != nil || upgrade == nil {
		return charge, err
	}
	if upgrade.MaxHeadBytes == 0 || upgrade.RuntimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	extra := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(controlledHTTPUpgrade{})) + uint64(upgrade.MaxHeadBytes), resourcev4.Items: 1, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2}
	extra, err = extra.Add(resourcev4.Vector{resourcev4.SDKBytes: upgrade.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(extra)
}

func (w *controlledHTTPResponse) BridgeUpgrade(peer HTTPUpgradePeer, head []byte) error {
	h := w.service
	if peer == nil || w.status != http.StatusSwitchingProtocols {
		return ErrHTTPUpgrade
	}
	h.mu.Lock()
	u := h.upgrade
	if h.response != w || !h.callback || h.terminal || u == nil || u.claimed || len(head) > len(u.head) {
		h.mu.Unlock()
		return ErrHTTPUpgrade
	}
	if err := h.reservation.Check(); err != nil {
		h.mu.Unlock()
		return err
	}
	// This consumes this request's single transfer attempt. No external call
	// occurs under the service gate. The actual callback keeps backing alive.
	u.claimed = true
	h.mu.Unlock()
	c, buffered, err := http.NewResponseController(w.writer).Hijack()
	if err != nil {
		return ErrHTTPUpgrade
	}
	if c != h.conn || buffered == nil || buffered.Reader == nil || buffered.Writer == nil {
		h.fail(ErrHTTPUpgrade)
		return ErrHTTPUpgrade
	}
	// Native header/idle deadlines do not become an upgrade lifetime bound.
	// StreamConn still enforces the original Session and service hard deadline.
	if err := c.SetDeadline(time.Time{}); err != nil {
		h.fail(err)
		return err
	}
	h.mu.Lock()
	copy(u.head, head)
	u.headSize = len(head)
	u.peer, u.buffered = peer, buffered
	close(u.ready)
	h.mu.Unlock()
	return nil
}

func (h *HTTPStream) startControlledUpgrade(callbackError error) {
	h.mu.Lock()
	u := h.upgrade
	if u == nil || u.peer == nil || u.started || callbackError != nil {
		h.mu.Unlock()
		return
	}
	u.started, u.running = true, 2
	h.mu.Unlock()
	go h.pumpHTTPUpgrade(u, 0)
	go h.pumpHTTPUpgrade(u, 1)
}

func (h *HTTPStream) pumpHTTPUpgrade(u *controlledHTTPUpgrade, direction int) {
	err := ErrHTTPUpgrade
	defer func() {
		// Native providers are trusted but a panic must not escape an SDK task
		// or let its reservation go free before its actual stack has unwound.
		_ = recover()
		if err != nil {
			h.fail(ErrHTTPUpgrade)
		}
		h.mu.Lock()
		clear(u.pieces[direction][:])
		if direction == 1 {
			clear(u.head)
			u.headSize = 0
		}
		if u.running == 1 {
			_ = h.conn.Close()
		}
		u.running--
		connNotify(h.wake)
		h.mu.Unlock()
	}()
	if direction == 0 {
		// Buffered client bytes from native Hijack precede new Stream reads.
		err = copyHTTPUpgrade(u.peer, u.buffered.Reader, u.pieces[0][:])
		if err == nil {
			err = u.peer.CloseWrite()
		}
		return
	}
	// Flush the native 101 response before the upstream parser's head. Both
	// heads preserve their original order and are sent exactly once.
	err = u.buffered.Writer.Flush()
	if err == nil {
		err = writeHTTPUpgrade(h.conn, u.head[:u.headSize])
	}
	if err == nil {
		err = copyHTTPUpgrade(h.conn, u.peer, u.pieces[1][:])
	}
	if err == nil {
		err = h.conn.CloseWrite()
	}
}

func copyHTTPUpgrade(dst io.Writer, src io.Reader, buf []byte) error {
	empty := 0
	for {
		n, err := src.Read(buf)
		if n < 0 || n > len(buf) {
			return ErrHTTPUpgrade
		}
		if n != 0 {
			empty = 0
			if writeErr := writeHTTPUpgrade(dst, buf[:n]); writeErr != nil {
				return writeErr
			}
		} else if err == nil {
			empty++
			if empty == 100 {
				return io.ErrNoProgress
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func writeHTTPUpgrade(dst io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := dst.Write(p)
		if n < 0 || n > len(p) {
			return ErrHTTPUpgrade
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
