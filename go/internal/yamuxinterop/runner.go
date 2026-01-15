package yamuxinterop

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	hyamux "github.com/hashicorp/yamux"
)

// Result captures server-side metrics for a scenario run.
type Result struct {
	StreamsAccepted int64  `json:"streams_accepted"`
	StreamsHandled  int64  `json:"streams_handled"`
	BytesRead       int64  `json:"bytes_read"`
	BytesWritten    int64  `json:"bytes_written"`
	Resets          int64  `json:"resets"`
	Errors          int64  `json:"errors"`
	FirstError      string `json:"first_error,omitempty"`
}

// RunServer executes a scenario over an established yamux session.
func RunServer(ctx context.Context, sess *hyamux.Session, scenario Scenario) (Result, error) {
	var res Result
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		_ = sess.Close()
	}()
	if scenario.Scenario == ScenarioSessionClose {
		delay := time.Duration(scenario.SessionCloseDelayMs) * time.Millisecond
		go func() {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
				_ = sess.Close()
			case <-ctx.Done():
			}
		}()
	}

	var wg sync.WaitGroup
	var firstErrOnce sync.Once
	var firstErr error

	setErr := func(err error) {
		if err == nil {
			return
		}
		if scenario.Scenario == ScenarioSessionClose && errors.Is(err, hyamux.ErrSessionShutdown) {
			return
		}
		firstErrOnce.Do(func() { firstErr = err })
	}

	for i := 0; i < scenario.Streams; i++ {
		stream, err := sess.AcceptStream()
		if err != nil {
			setErr(err)
			break
		}
		atomic.AddInt64(&res.StreamsAccepted, 1)
		wg.Add(1)
		go func(s *hyamux.Stream) {
			defer wg.Done()
			if err := handleStream(ctx, s, scenario, &res); err != nil {
				setErr(err)
			}
			atomic.AddInt64(&res.StreamsHandled, 1)
		}(stream)
	}

	wg.Wait()
	if firstErr != nil && res.FirstError == "" {
		res.FirstError = firstErr.Error()
	}
	if firstErr != nil && !errors.Is(firstErr, hyamux.ErrSessionShutdown) {
		return res, firstErr
	}
	return res, nil
}

func handleStream(ctx context.Context, stream *hyamux.Stream, scenario Scenario, res *Result) error {
	switch scenario.Scenario {
	case ScenarioWindowUpdateRace:
		return runWindowUpdate(ctx, stream, scenario, res)
	case ScenarioRstMidWriteTS:
		return runReadUntilError(ctx, stream, scenario, res)
	case ScenarioRstMidWriteGo:
		return runRstAfterRead(ctx, stream, scenario, res)
	case ScenarioConcurrentClose:
		return runReadUntilError(ctx, stream, scenario, res)
	case ScenarioSessionClose:
		return runReadUntilError(ctx, stream, scenario, res)
	default:
		return errors.New("unknown scenario")
	}
}

func runBidi(ctx context.Context, stream *hyamux.Stream, scenario Scenario, res *Result) error {
	readCh := make(chan error, 1)
	writeCh := make(chan error, 1)

	go func() {
		readCh <- readExactly(ctx, stream, scenario.BytesPerStream, scenario.ChunkBytes, scenario.ReadDelayMs, res)
	}()
	go func() {
		writeCh <- writeExactly(ctx, stream, scenario.BytesPerStream, scenario.ChunkBytes, scenario.WriteDelayMs, res)
	}()

	var readErr error
	var writeErr error
	for i := 0; i < 2; i++ {
		select {
		case readErr = <-readCh:
		case writeErr = <-writeCh:
		}
		if (readErr != nil || writeErr != nil) && ctx.Err() == nil {
			_ = stream.Close()
		}
	}
	if err := classifyError(scenario, readErr, res); err != nil {
		return err
	}
	if err := classifyError(scenario, writeErr, res); err != nil {
		return err
	}
	_ = stream.Close()
	return nil
}

func runWindowUpdate(ctx context.Context, stream *hyamux.Stream, scenario Scenario, res *Result) error {
	if scenario.Direction == DirectionBidi {
		return runBidi(ctx, stream, scenario, res)
	}
	err := readExactly(ctx, stream, scenario.BytesPerStream, scenario.ChunkBytes, scenario.ReadDelayMs, res)
	if err := classifyError(scenario, err, res); err != nil {
		return err
	}
	_ = stream.Close()
	return nil
}

func runReadUntilError(ctx context.Context, stream *hyamux.Stream, scenario Scenario, res *Result) error {
	err := readUntilError(ctx, stream, scenario.ChunkBytes, scenario.ReadDelayMs, res)
	if err := classifyError(scenario, err, res); err != nil {
		return err
	}
	return nil
}

func runRstAfterRead(ctx context.Context, stream *hyamux.Stream, scenario Scenario, res *Result) error {
	if err := readExactly(ctx, stream, scenario.RstAfterBytes, scenario.ChunkBytes, scenario.ReadDelayMs, res); err != nil {
		if err := classifyError(scenario, err, res); err != nil {
			return err
		}
		return nil
	}
	_ = stream.Close()
	waitForReset(ctx, 100*time.Millisecond)
	return nil
}

func writeExactly(ctx context.Context, stream *hyamux.Stream, total int, chunkBytes int, delayMs int, res *Result) error {
	if total <= 0 {
		return nil
	}
	buf := make([]byte, minInt(chunkBytes, total))
	remaining := total
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := minInt(len(buf), remaining)
		wrote, err := stream.Write(buf[:n])
		if wrote > 0 {
			atomic.AddInt64(&res.BytesWritten, int64(wrote))
			remaining -= wrote
		}
		if err != nil {
			return err
		}
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}
	return nil
}

func readExactly(ctx context.Context, stream *hyamux.Stream, total int, chunkBytes int, delayMs int, res *Result) error {
	if total <= 0 {
		return nil
	}
	buf := make([]byte, minInt(chunkBytes, total))
	remaining := total
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := stream.Read(buf)
		if n > 0 {
			atomic.AddInt64(&res.BytesRead, int64(n))
			remaining -= n
		}
		if err != nil {
			return err
		}
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}
	return nil
}

func readUntilError(ctx context.Context, stream *hyamux.Stream, chunkBytes int, delayMs int, res *Result) error {
	buf := make([]byte, maxInt(chunkBytes, 1024))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := stream.Read(buf)
		if n > 0 {
			atomic.AddInt64(&res.BytesRead, int64(n))
		}
		if err != nil {
			return err
		}
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}
}

func classifyError(scenario Scenario, err error, res *Result) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	if errors.Is(err, hyamux.ErrConnectionReset) {
		atomic.AddInt64(&res.Resets, 1)
		return nil
	}
	if errors.Is(err, hyamux.ErrSessionShutdown) && scenario.Scenario == ScenarioSessionClose {
		return nil
	}
	atomic.AddInt64(&res.Errors, 1)
	return err
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func waitForReset(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
