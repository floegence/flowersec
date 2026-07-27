package transportrelease

import (
	"context"
	"errors"
	"fmt"
	"io"

	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

const browserBulkPreacceptBytes int64 = 16 * 1024

// ServeBrowserBulk serves the fixed bidirectional bulk phases used by the
// Chromium release collector. RPC echo is already owned by the session router.
func ServeBrowserBulk(ctx context.Context, session flowersession.SessionV2, bytesPerPhase []int64) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if session == nil || len(bytesPerPhase) == 0 {
		return errors.New("browser bulk workload is not initialized")
	}
	var outgoing releaseByteStream
	for phase, byteCount := range bytesPerPhase {
		if byteCount < 1 {
			return fmt.Errorf("browser bulk phase %d has an invalid byte count", phase+1)
		}
		if outgoing == nil {
			opened, err := session.OpenStream(ctx, "release-bulk", flowersession.Metadata{"direction": "server-to-client"})
			if err != nil {
				return fmt.Errorf("browser bulk phase %d: open: %w", phase+1, err)
			}
			outgoing = opened
		}

		var next <-chan preparedBrowserBulkStream
		var cancelNext context.CancelFunc
		if phase+1 < len(bytesPerPhase) {
			prepareCtx, cancel := context.WithCancel(ctx)
			cancelNext = cancel
			prepared := make(chan preparedBrowserBulkStream, 1)
			next = prepared
			go func() {
				stream, err := session.OpenStream(prepareCtx, "release-bulk", flowersession.Metadata{"direction": "server-to-client"})
				prepared <- preparedBrowserBulkStream{stream: stream, err: err, cancel: cancel}
			}()
		}

		if err := serveBrowserBulkSessionPhaseWithOutgoing(ctx, session, outgoing, byteCount); err != nil {
			if next != nil {
				cancelNext()
				prepared := <-next
				prepared.cancel()
				if prepared.stream != nil {
					_ = prepared.stream.Reset()
				}
			}
			return fmt.Errorf("browser bulk phase %d: %w", phase+1, err)
		}
		if next != nil {
			prepared := <-next
			prepared.cancel()
			if prepared.err != nil {
				return fmt.Errorf("browser bulk phase %d: open next phase: %w", phase+2, prepared.err)
			}
			outgoing = prepared.stream
		}
	}
	return nil
}

type preparedBrowserBulkStream struct {
	stream releaseByteStream
	err    error
	cancel context.CancelFunc
}

func serveBrowserBulkSessionPhase(ctx context.Context, session flowersession.SessionV2, byteCount int64) error {
	outgoing, err := session.OpenStream(ctx, "release-bulk", flowersession.Metadata{"direction": "server-to-client"})
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	return serveBrowserBulkSessionPhaseWithOutgoing(ctx, session, outgoing, byteCount)
}

func serveBrowserBulkSessionPhaseWithOutgoing(ctx context.Context, session flowersession.SessionV2, outgoing releaseByteStream, byteCount int64) error {
	stopCancellation := context.AfterFunc(ctx, func() { _ = outgoing.Reset() })
	defer stopCancellation()
	preacceptBytes := min(byteCount, browserBulkPreacceptBytes)
	if err := writeExactFillData(ctx, outgoing, preacceptBytes, 0x5a); err != nil {
		_ = outgoing.Reset()
		return fmt.Errorf("prime outgoing stream: %w", err)
	}
	incoming, err := session.AcceptStream(ctx)
	if err != nil {
		_ = outgoing.Reset()
		return fmt.Errorf("accept: %w", err)
	}
	if incoming.Kind != "release-bulk" || incoming.Metadata["direction"] != "client-to-server" {
		_ = incoming.Stream.Reset()
		_ = outgoing.Reset()
		return errors.New("metadata mismatch")
	}
	writeDone := make(chan error, 1)
	go func() {
		writeErr := writeExactFillData(ctx, outgoing, byteCount-preacceptBytes, 0x5a)
		if writeErr == nil {
			writeErr = outgoing.CloseWrite()
		}
		writeDone <- writeErr
	}()
	return finishBrowserBulkPhase(ctx, incoming.Stream, outgoing, writeDone, byteCount)
}

// ServeBrowserNativeIsolation proves that one reset WebTransport stream does
// not interrupt its three sibling streams or the session RPC router.
func ServeBrowserNativeIsolation(ctx context.Context, session flowersession.SessionV2) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if session == nil {
		return errors.New("browser native isolation session is unavailable")
	}
	results := make(chan error, 4)
	for index := range 4 {
		incoming, err := session.AcceptStream(ctx)
		if err != nil {
			return fmt.Errorf("accept browser native isolation stream %d: %w", index, err)
		}
		if incoming.Kind != "native-isolation" || fmt.Sprint(incoming.Metadata["stream_index"]) != fmt.Sprint(index) {
			_ = incoming.Stream.Reset()
			return errors.New("browser native isolation stream metadata mismatch")
		}
		go func() {
			finished := false
			defer func() {
				if !finished {
					_ = incoming.Stream.Reset()
				}
			}()
			handshake := make([]byte, 1)
			if _, readErr := io.ReadFull(incoming.Stream, handshake); readErr != nil || handshake[0] != byte(index) {
				results <- errors.Join(readErr, errors.New("browser native isolation handshake mismatch"))
				return
			}
			if count, writeErr := incoming.Stream.Write([]byte{handshake[0] ^ 0xff}); writeErr != nil || count != 1 {
				results <- errors.Join(writeErr, io.ErrShortWrite)
				return
			}
			if index == 0 {
				buffer := make([]byte, 1)
				for {
					_, resetErr := incoming.Stream.Read(buffer)
					if resetErr == nil {
						continue
					}
					if errors.Is(resetErr, io.EOF) {
						results <- errors.New("browser native isolation reset stream ended with FIN")
						return
					}
					finished = true
					results <- nil
					return
				}
			}
			payload := make([]byte, 1)
			if _, readErr := io.ReadFull(incoming.Stream, payload); readErr != nil || payload[0] != byte(0x40+index) {
				results <- errors.Join(readErr, errors.New("browser native isolation sibling payload mismatch"))
				return
			}
			if count, readErr := incoming.Stream.Read(handshake); count != 0 || !errors.Is(readErr, io.EOF) {
				results <- errors.Join(readErr, errors.New("browser native isolation sibling did not finish with FIN"))
				return
			}
			if count, writeErr := incoming.Stream.Write([]byte{payload[0] ^ 0xff}); writeErr != nil || count != 1 {
				results <- errors.Join(writeErr, io.ErrShortWrite)
				return
			}
			if closeErr := incoming.Stream.CloseWrite(); closeErr != nil {
				results <- closeErr
				return
			}
			finished = true
			results <- nil
		}()
	}
	var result error
	for range 4 {
		result = errors.Join(result, <-results)
	}
	return result
}

func serveBrowserBulkPhase(ctx context.Context, incoming, outgoing releaseByteStream, byteCount int64) error {
	writeDone := make(chan error, 1)
	go func() { writeDone <- writeExactFill(ctx, outgoing, byteCount, 0x5a) }()
	return finishBrowserBulkPhase(ctx, incoming, outgoing, writeDone, byteCount)
}

func finishBrowserBulkPhase(ctx context.Context, incoming, outgoing releaseByteStream, writeDone <-chan error, byteCount int64) error {
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = incoming.Reset()
		_ = outgoing.Reset()
	})
	defer stopCancellation()
	results := make(chan error, 2)
	go func() { results <- <-writeDone }()
	go func() {
		if err := readExactFill(ctx, incoming, byteCount, 0xa5); err != nil {
			results <- err
			return
		}
		results <- incoming.CloseWrite()
	}()
	first := <-results
	if first != nil {
		_ = incoming.Reset()
		_ = outgoing.Reset()
	}
	second := <-results
	if err := errors.Join(first, second); err != nil {
		return fmt.Errorf("bidirectional transfer: %w", err)
	}
	return nil
}

func readExactFill(ctx context.Context, stream io.Reader, total int64, fill byte) error {
	buffer := make([]byte, 32*1024)
	remaining := total
	for remaining > 0 {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		want := int64(len(buffer))
		if remaining < want {
			want = remaining
		}
		count, err := io.ReadFull(stream, buffer[:want])
		if err != nil {
			return err
		}
		for _, value := range buffer[:count] {
			if value != fill {
				return errors.New("browser bulk payload mismatch")
			}
		}
		remaining -= int64(count)
	}
	one := make([]byte, 1)
	if count, err := stream.Read(one); count != 0 || !errors.Is(err, io.EOF) {
		return errors.New("browser bulk stream did not end at the exact byte count")
	}
	return nil
}

func writeExactFill(ctx context.Context, stream releaseByteStream, total int64, fill byte) error {
	if err := writeExactFillData(ctx, stream, total, fill); err != nil {
		return err
	}
	return stream.CloseWrite()
}

func writeExactFillData(ctx context.Context, stream releaseByteStream, total int64, fill byte) error {
	buffer := make([]byte, 32*1024)
	for index := range buffer {
		buffer[index] = fill
	}
	remaining := total
	for remaining > 0 {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		want := int64(len(buffer))
		if remaining < want {
			want = remaining
		}
		count, err := stream.Write(buffer[:want])
		if err != nil {
			return err
		}
		if count != int(want) {
			return io.ErrShortWrite
		}
		remaining -= int64(count)
	}
	return nil
}
