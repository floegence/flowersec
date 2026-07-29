package transportrelease

import (
	"context"
	"errors"
	"fmt"
	"io"

	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

// ServeBrowserBulk serves the fixed bidirectional bulk phases used by the
// Chromium release collector. RPC echo is already owned by the session router.
func ServeBrowserBulk(ctx context.Context, session flowersession.SessionV2, bytesPerPhase []int64) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if session == nil || len(bytesPerPhase) == 0 {
		return errors.New("browser bulk workload is not initialized")
	}
	for phase, byteCount := range bytesPerPhase {
		if byteCount < 1 {
			return fmt.Errorf("browser bulk phase %d has an invalid byte count", phase+1)
		}
		if err := serveBrowserBulkSessionPhase(ctx, session, byteCount); err != nil {
			return fmt.Errorf("browser bulk phase %d: %w", phase+1, err)
		}
	}
	return nil
}

func serveBrowserBulkSessionPhase(ctx context.Context, session flowersession.SessionV2, byteCount int64) error {
	incoming, err := session.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	if incoming.Kind != "release-bulk" || incoming.Metadata["direction"] != "client-to-server" {
		_ = incoming.Stream.Reset()
		return errors.New("metadata mismatch")
	}
	writeDone := make(chan error, 1)
	go func() { writeDone <- writeExactFillData(ctx, incoming.Stream, byteCount, 0x5a) }()
	return finishBrowserBulkPhase(ctx, incoming.Stream, incoming.Stream, writeDone, byteCount, true)
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
	return finishBrowserBulkPhase(ctx, incoming, outgoing, writeDone, byteCount, true)
}

func finishBrowserBulkPhase(ctx context.Context, incoming, outgoing releaseByteStream, writeDone <-chan error, byteCount int64, closeIncomingWrite bool) error {
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
		if closeIncomingWrite {
			results <- incoming.CloseWrite()
			return
		}
		results <- nil
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
