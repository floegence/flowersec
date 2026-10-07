package transporttest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// ServeBrowserBulk serves the fixed bidirectional bulk phases used by the
// Chromium test producer. RPC echo is already owned by the session router.
func ServeBrowserBulk(ctx context.Context, session *flowersec.Session, bytesPerPhase []int64) error {
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

func serveBrowserBulkSessionPhase(ctx context.Context, session *flowersec.Session, byteCount int64) error {
	incoming, err := session.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	if incoming.Kind != "release-bulk" || incoming.Metadata.Values()["direction"] != "client-to-server" {
		_ = incoming.Stream.Reset()
		return errors.New("metadata mismatch")
	}
	return serveBrowserBulkBidiPhase(ctx, incoming.Stream, byteCount)
}

func serveBrowserBulkBidiPhase(ctx context.Context, stream releaseByteStream, byteCount int64) error {
	writeDone := make(chan error, 1)
	go func() { writeDone <- writeExactFillData(ctx, stream, byteCount, 0x5a) }()
	return finishBrowserBulkPhase(ctx, stream, stream, writeDone, byteCount, true)
}

// ServeBrowserNativeIsolation proves that one reset WebTransport stream does
// not interrupt its three sibling streams or the session RPC router.
func ServeBrowserNativeIsolation(ctx context.Context, session *flowersec.Session) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if session == nil {
		return errors.New("browser native isolation session is unavailable")
	}
	operation, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)
	results := make(chan error, 4)
	var callbacks sync.WaitGroup
	started := 0
	var result error
	for index := range 4 {
		incoming, err := session.AcceptStream(operation)
		if err != nil {
			result = fmt.Errorf("accept browser native isolation stream %d: %w", index, err)
			cancel(result)
			break
		}
		if incoming.Kind != "native-isolation" || fmt.Sprint(incoming.Metadata.Values()["stream_index"]) != fmt.Sprint(index) {
			_ = incoming.Stream.Reset()
			result = errors.New("browser native isolation stream metadata mismatch")
			cancel(result)
			break
		}
		started++
		callbacks.Add(1)
		go func() {
			defer callbacks.Done()
			finishResult := func(err error) {
				if err != nil {
					cancel(err)
				}
				results <- err
			}
			// Every accepted stream retains cancellation until its real callback exits.
			// An early later-accept failure still joins all previously accepted peers.
			resetDone := make(chan struct{})
			stopCancellation := context.AfterFunc(operation, func() { defer close(resetDone); _ = incoming.Stream.Reset() })
			defer func() {
				if !stopCancellation() {
					<-resetDone
				}
			}()
			finished := false
			defer func() {
				if !finished {
					_ = incoming.Stream.Reset()
				}
			}()
			handshake := make([]byte, 1)
			if _, readErr := io.ReadFull(incoming.Stream, handshake); readErr != nil || handshake[0] != byte(index) {
				finishResult(errors.Join(readErr, errors.New("browser native isolation handshake mismatch")))
				return
			}
			if count, writeErr := incoming.Stream.Write([]byte{handshake[0] ^ 0xff}); writeErr != nil || count != 1 {
				finishResult(errors.Join(writeErr, io.ErrShortWrite))
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
						finishResult(errors.New("browser native isolation reset stream ended with FIN"))
						return
					}
					if !errors.Is(resetErr, sessionv4.ErrAbandoned) && !errors.Is(resetErr, native.ErrDirectionReset) {
						finishResult(errors.Join(errors.New("browser isolation stream did not observe authenticated abandonment"), resetErr))
						return
					}
					finished = true
					finishResult(incoming.Stream.Close())
					return
				}
			}
			payload := make([]byte, 1)
			if _, readErr := io.ReadFull(incoming.Stream, payload); readErr != nil || payload[0] != byte(0x40+index) {
				finishResult(errors.Join(readErr, errors.New("browser native isolation sibling payload mismatch")))
				return
			}
			if count, readErr := incoming.Stream.Read(handshake); count != 0 || !errors.Is(readErr, io.EOF) {
				finishResult(errors.Join(readErr, errors.New("browser native isolation sibling did not finish with FIN")))
				return
			}
			if count, writeErr := incoming.Stream.Write([]byte{payload[0] ^ 0xff}); writeErr != nil || count != 1 {
				finishResult(errors.Join(writeErr, io.ErrShortWrite))
				return
			}
			if closeErr := incoming.Stream.CloseWrite(); closeErr != nil {
				finishResult(closeErr)
				return
			}
			if err := incoming.Stream.Finish(operation); err != nil {
				finishResult(err)
				return
			}
			finished = true
			finishResult(incoming.Stream.Close())
		}()
	}
	for range started {
		err := <-results
		if err != nil {
			cancel(err)
		}
		result = errors.Join(result, err)
	}
	callbacks.Wait()
	return result
}

func serveBrowserBulkPhase(ctx context.Context, incoming, outgoing releaseByteStream, byteCount int64) error {
	writeDone := make(chan error, 1)
	go func() { writeDone <- writeExactFill(ctx, outgoing, byteCount, 0x5a) }()
	return finishBrowserBulkPhase(ctx, incoming, outgoing, writeDone, byteCount, true)
}

func finishBrowserBulkPhase(ctx context.Context, incoming, outgoing releaseByteStream, writeDone <-chan error, byteCount int64, closeIncomingWrite bool) error {
	resetDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		defer close(resetDone)
		_ = incoming.Reset()
		_ = outgoing.Reset()
	})
	defer func() {
		if !stopCancellation() {
			<-resetDone
		}
	}()
	results := make(chan error, 2)
	go func() { results <- <-writeDone }()
	go func() {
		if err := readExactFill(ctx, incoming, byteCount, 0xa5); err != nil {
			results <- err
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
	if closeIncomingWrite {
		if err := incoming.CloseWrite(); err != nil {
			_ = incoming.Reset()
			_ = outgoing.Reset()
			return fmt.Errorf("bidirectional transfer: close write: %w", err)
		}
	}
	if err := incoming.Finish(ctx); err != nil {
		return err
	}
	if incoming != outgoing {
		if err := outgoing.Finish(ctx); err != nil {
			return err
		}
	}
	// Finish observes authenticated DRAINED; Close then relinquishes the
	// accepted owner and its physical carrier position. Keep this after both
	// directions have drained so the peer's accepted output tail survives.
	if err := incoming.Close(); err != nil {
		return err
	}
	if incoming != outgoing {
		if err := outgoing.Close(); err != nil {
			return err
		}
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
