package cryptov4

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func requireEngineCleanupPending(t *testing.T, e *Engine) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.WaitCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("live backing reported cleanup complete", err)
	}
}

func requireEngineCleanup(t *testing.T, e *Engine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.WaitCleanup(ctx); err != nil {
		t.Fatal("record backing did not finish cleanup", err)
	}
}

func TestEngineCleanupRetainsEveryPacketLane(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		for _, role := range []protocolv4.Direction{protocolv4.ClientToServer, protocolv4.ServerToClient} {
			for _, shared := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/shared=%v", profile, role, shared), func(t *testing.T) {
					e, peer, _ := enginePair(t, profile)
					if role == protocolv4.ServerToClient {
						e, peer = peer, e
					}
					if shared {
						if err := e.ReserveSharedInput(); err != nil {
							t.Fatal(err)
						}
					}
					var packets []*Packet
					var backing, original [][]byte
					for _, lane := range []struct {
						frame protocolv4.FrameType
						scope uint64
					}{{protocolv4.FrameStreamData, 1}, {protocolv4.FrameDatagram, protocolv4.DatagramScope()}, {protocolv4.FramePing, 0}} {
						for _, outgoing := range []bool{true, false} {
							var p *Packet
							var err error
							if outgoing {
								p, err = e.Seal(lane.frame, lane.scope, []byte("original packet backing"))
							} else {
								wire := sealed(t, peer, lane.frame, lane.scope, []byte("original packet backing"))
								p, _, _, err = e.Open(wire, acceptRecord)
							}
							if err != nil {
								t.Fatal(err)
							}
							t.Cleanup(p.Release)
							data, err := p.Bytes()
							if err != nil {
								t.Fatal(err)
							}
							packets = append(packets, p)
							backing = append(backing, data)
							original = append(original, bytes.Clone(data))
						}
					}
					if e.flight != 0 || e.borrowedWork != 6 || e.outgoingPackets != 2 {
						t.Fatal("packet ownership was conflated with crypto flight or reliable output")
					}
					e.Close()
					e.Close()
					select {
					case <-e.Done():
					default:
						t.Fatal("logical close waited for a packet")
					}
					for i, p := range packets {
						requireEngineCleanupPending(t, e)
						if !bytes.Equal(backing[i], original[i]) {
							t.Fatal("close cleared a still borrowed packet")
						}
						if _, err := p.Bytes(); !errors.Is(err, ErrClosed) {
							t.Fatal("closed packet retained publication", err)
						}
						work := p.workspace
						p.Release()
						p.Release()
						if p.engine != nil || p.epoch != nil || p.key != nil || p.workspace != nil || work.input != nil || work.output != nil {
							t.Fatal("released packet retained engine/key/backing aliases")
						}
						if !bytes.Equal(backing[i], make([]byte, len(backing[i]))) {
							t.Fatal("original writable storage was not cleared")
						}
						if err := p.Published(); !errors.Is(err, ErrClosed) {
							t.Fatal("released packet reported new activity", err)
						}
					}
					requireEngineCleanup(t, e)
					if e.used[0] != nil || e.used[1] != nil || e.current.keys.slots != nil {
						t.Fatal("cleaned engine retained scope backing")
					}
				})
			}
		}
	}
}

func TestEngineCleanupDoesNotWaitForIdleSharedLane(t *testing.T) {
	e, _, _ := enginePair(t, protocolv4.DHProfileX25519)
	if err := e.ReserveSharedInput(); err != nil {
		t.Fatal(err)
	}
	requireEngineCleanupPending(t, e)
	e.Close()
	requireEngineCleanup(t, e)
}

func TestEngineCleanupWaitsForBusyRekeyWithoutRecordBorrow(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			e, _, now := enginePair(t, profile)
			round, err := e.BeginRekey(uint64(now.Add(time.Minute).UnixMilli()))
			if err != nil {
				t.Fatal(err)
			}
			if err := round.begin(); err != nil {
				t.Fatal(err)
			}
			secret := round.secret
			e.Close()
			if e.borrowedWork != 0 || e.flight != 0 {
				t.Fatal("test has an unrelated record borrow")
			}
			requireEngineCleanupPending(t, e)
			if round.secret != secret || round.engine != e || round.init == nil {
				t.Fatal("logical close released a busy rekey job's backing")
			}
			if err := round.end(nil); !errors.Is(err, ErrClosed) {
				t.Fatal("late rekey job remained usable", err)
			}
			requireEngineCleanup(t, e)
			if round.secret != [32]byte{} || round.engine != nil || round.init != nil {
				t.Fatal("exited rekey job retained backing")
			}
		})
	}
}

func TestEngineCleanupWaitsForRecordWork(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		for _, outgoing := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/outgoing=%v", profile, outgoing), func(t *testing.T) {
				e, peer, _ := enginePair(t, profile)
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				defer once.Do(func() { close(release) })
				done := make(chan error, 1)
				payload := []byte("still borrowed by original work")
				var borrowed []byte
				wire := sealed(t, peer, protocolv4.FrameStreamData, 1, payload)
				go func() {
					var p *Packet
					var err error
					if outgoing {
						p, err = e.SealBuild(protocolv4.FrameStreamData, 1, len(payload), func(_ protocolv4.RecordHeader, dst []byte) (int, error) {
							copy(dst, payload)
							borrowed = dst
							close(entered)
							<-release
							return len(payload), nil
						})
					} else {
						p, _, _, err = e.Open(wire, func(_ protocolv4.FrameType, _ protocolv4.RecordHeader, plain []byte) error {
							borrowed = plain
							close(entered)
							<-release
							return nil
						})
					}
					if p != nil {
						p.Release()
					}
					done <- err
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("record work did not enter")
				}
				e.Close()
				requireEngineCleanupPending(t, e)
				if !bytes.Equal(borrowed, payload) {
					t.Fatal("close changed in-progress input")
				}
				once.Do(func() { close(release) })
				if err := <-done; !errors.Is(err, ErrClosed) {
					t.Fatal("late record succeeded", err)
				}
				requireEngineCleanup(t, e)
			})
		}
	}
}

func TestEngineCleanupRekeyDecoderClose(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		for _, client := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/client=%v", profile, client), func(t *testing.T) {
				pair := preparedRound(t, profile)
				e, sender, round := pair.server, pair.c, pair.s
				if client {
					roundMarker(t, pair.c, pair.server)
					e, sender, round = pair.client, pair.s, pair.c
				}
				marker, err := sender.SealMarker()
				if err != nil {
					t.Fatal(err)
				}
				defer marker.Release()
				wire, err := marker.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				decode := roundDecoder(t, e)
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				defer once.Do(func() { close(release) })
				done := make(chan error, 1)
				go func() {
					p, body, err := e.OpenRekeyMarker(wire, func(kind protocolv4.FrameType, header protocolv4.RecordHeader, plain []byte) (*protocolv4.Frame, error) {
						close(entered)
						<-release
						return decode(kind, header, plain)
					})
					if body != nil {
						body.Release()
					}
					if p != nil {
						p.Release()
					}
					done <- err
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("marker decoder did not enter")
				}
				e.Close()
				requireEngineCleanupPending(t, e)
				once.Do(func() { close(release) })
				if err = <-done; !errors.Is(err, ErrClosed) {
					t.Fatal("late marker succeeded", err)
				}
				requireEngineCleanup(t, e)
				round.Close()
				if round.BelongsTo(e) || round.engine != nil || round.epoch != nil || round.init != nil || round.reply != nil || round.scratch != nil || round.barrier != nil {
					t.Fatal("closed round retained original engine/key/backing aliases")
				}
				if _, err := round.DeadlineRemainingMS(); err != nil {
					t.Fatal("cleanup changed the original deadline observation", err)
				}
				if err := round.Check(); !errors.Is(err, ErrClosed) {
					t.Fatal("closed round reopened", err)
				}
			})
		}
	}
}

type cleanupBlockingSigner struct {
	IdentitySigner
	entered, release chan struct{}
}

func (s cleanupBlockingSigner) Sign(input []byte) ([]byte, error) {
	close(s.entered)
	<-s.release
	return s.IdentitySigner.Sign(input)
}

func TestEngineCleanupFencesBlockedReadySigner(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		for _, role := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/%d", profile, role), func(t *testing.T) {
				client, server := handshakePair(t, profile)
				c, s := completeNoise(t, client, server)
				f := []*FinishedHandshake{c, s}[role]
				e, err := f.PrepareRecords(initialRecordConfig())
				if err != nil {
					t.Fatal(err)
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				defer once.Do(func() { close(release) })
				f.config.Signer = cleanupBlockingSigner{f.config.Signer, entered, release}
				done := make(chan error, 1)
				go func() { _, err := f.Ready(); done <- err }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("READY signer did not enter")
				}
				e.Close()
				// The signer owns separate handshake backing, not a record borrow.
				requireEngineCleanup(t, e)
				once.Do(func() { close(release) })
				if err := <-done; !errors.Is(err, ErrHandshake) {
					t.Fatal("closed Engine published late READY", err)
				}
				if f.root != [32]byte{} || f.records != nil {
					t.Fatal("finished signer retained handshake secrets")
				}
			})
		}
	}
}
