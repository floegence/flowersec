package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/client"
	"github.com/floegence/flowersec/flowersec-go/v2/endpoint"
	endpointserve "github.com/floegence/flowersec/flowersec-go/v2/endpoint/serve"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/interopprotocol"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v2/internal/rpcwire"
	fsyamux "github.com/floegence/flowersec/flowersec-go/v2/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/v2/proxy"
	"github.com/floegence/flowersec/flowersec-go/v2/rpc"
)

const (
	rpcTypeEcho         uint32 = 1
	rpcTypeNotification uint32 = 2
	rpcTypeServerRekey  uint32 = 3
	rpcTypeDelay        uint32 = 4
	rpcTypeComplete     uint32 = 5
	rpcTypeDisconnect   uint32 = 6
	rpcTypeSaturation   uint32 = 7
	saturationGateKind         = "interop-rpc-saturation-gate"
	mixedEchoKind              = "interop-mixed-echo"
)

type saturationGate struct {
	once sync.Once
	done chan struct{}
}

func newSaturationGate() *saturationGate {
	return &saturationGate{done: make(chan struct{})}
}

func (g *saturationGate) release() {
	g.once.Do(func() { close(g.done) })
}

func (g *saturationGate) wait(ctx context.Context) error {
	select {
	case <-g.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func serveReferenceSession(
	ctx context.Context,
	session endpoint.Session,
	upstreamURL string,
	workload interopprotocol.Workload,
) (returnErr error) {
	if session == nil {
		return errors.New("missing reference endpoint session")
	}
	defer func() {
		returnErr = errors.Join(returnErr, session.Close())
	}()
	var completed atomic.Bool
	var disconnecting atomic.Bool
	var background sync.WaitGroup
	var errorMu sync.Mutex
	var backgroundErr error
	saturation := newSaturationGate()
	report := func(err error) {
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, fsyamux.ErrStreamReset) {
			return
		}
		errorMu.Lock()
		joinedError(&backgroundErr, err)
		errorMu.Unlock()
	}
	streamServer, err := endpointserve.New(endpointserve.Options{
		RPC: endpointserve.RPCOptions{
			Server: rpc.ServerOptions{
				MaxConcurrentRequests:  workload.RPC.SaturationActive,
				MaxQueuedRequests:      workload.RPC.SaturationQueued,
				MaxQueuedNotifications: workload.RPC.SaturationQueued,
			},
			Register: func(router *rpc.Router, rpcServer *rpc.Server) {
				router.Register(rpcTypeEcho, func(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
					var request struct {
						Value  int  `json:"value"`
						Notify bool `json:"notify"`
					}
					if err := decodeStrictJSON(payload, &request); err != nil {
						message := err.Error()
						return nil, &rpcv1.RpcError{Code: 400, Message: &message}
					}
					if request.Notify {
						if err := rpcServer.Notify(rpcTypeNotification, json.RawMessage(`{"hello":"world"}`)); err != nil {
							message := err.Error()
							return nil, &rpcv1.RpcError{Code: 500, Message: &message}
						}
					}
					response, err := json.Marshal(map[string]int{"value": request.Value})
					if err != nil {
						message := err.Error()
						return nil, &rpcv1.RpcError{Code: 500, Message: &message}
					}
					return response, nil
				})
				router.Register(rpcTypeServerRekey, func(_ context.Context, _ json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
					if err := session.Rekey(); err != nil {
						message := err.Error()
						return nil, &rpcv1.RpcError{Code: 500, Message: &message}
					}
					return json.RawMessage(`{"ok":true}`), nil
				})
				router.Register(rpcTypeDelay, func(callCtx context.Context, _ json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
					select {
					case <-time.After(100 * time.Millisecond):
						return json.RawMessage(`{"ok":true}`), nil
					case <-callCtx.Done():
						message := callCtx.Err().Error()
						return nil, &rpcv1.RpcError{Code: 499, Message: &message}
					}
				})
				router.Register(rpcTypeComplete, func(_ context.Context, _ json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
					completed.Store(true)
					return json.RawMessage(`{"ok":true}`), nil
				})
				router.Register(rpcTypeDisconnect, func(_ context.Context, _ json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
					disconnecting.Store(true)
					background.Add(1)
					go func() {
						defer background.Done()
						select {
						case <-time.After(50 * time.Millisecond):
							report(session.Close())
						case <-ctx.Done():
						}
					}()
					return json.RawMessage(`{"ok":true}`), nil
				})
				router.Register(rpcTypeSaturation, func(callCtx context.Context, _ json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
					if err := saturation.wait(callCtx); err != nil {
						message := callCtx.Err().Error()
						return nil, &rpcv1.RpcError{Code: 499, Message: &message}
					}
					return json.RawMessage(`{"ok":true}`), nil
				})
			},
		},
		OnError: report,
	})
	if err != nil {
		return err
	}
	streamServer.Handle("echo", func(_ context.Context, stream io.ReadWriteCloser) {
		_, copyErr := io.Copy(stream, stream)
		report(copyErr)
	})
	streamServer.Handle(mixedEchoKind, func(_ context.Context, stream io.ReadWriteCloser) {
		_, copyErr := io.Copy(stream, stream)
		report(copyErr)
	})
	streamServer.Handle("churn", func(context.Context, io.ReadWriteCloser) {})
	streamServer.Handle(saturationGateKind, func(_ context.Context, stream io.ReadWriteCloser) {
		var signal [1]byte
		if _, err := io.ReadFull(stream, signal[:]); err != nil {
			report(fmt.Errorf("read RPC saturation gate: %w", err))
			return
		}
		if signal[0] != 1 {
			report(fmt.Errorf("invalid RPC saturation gate signal %d", signal[0]))
			return
		}
		saturation.release()
	})
	if err := proxy.Register(streamServer, proxy.Options{Upstream: upstreamURL, UpstreamOrigin: upstreamURL}); err != nil {
		return err
	}
	serveErr := streamServer.ServeSession(ctx, session)
	background.Wait()
	var collected error
	if serveErr != nil && !errors.Is(serveErr, context.Canceled) && !completed.Load() && !disconnecting.Load() {
		joinedError(&collected, serveErr)
	}
	errorMu.Lock()
	joinedError(&collected, backgroundErr)
	errorMu.Unlock()
	return collected
}

func exerciseGoClient(
	ctx context.Context,
	connected client.Client,
	upstreamURL string,
	workload interopprotocol.Workload,
	diagnostics *[]interopprotocol.Diagnostic,
) (interopprotocol.Metrics, error) {
	if connected == nil {
		return interopprotocol.Metrics{}, errors.New("missing Go reference client")
	}
	metrics := interopprotocol.Metrics{Sessions: 1}
	notifyChannel := make(chan struct{}, workload.RPC.Notifications)
	unsubscribe := connected.RPC().OnNotify(rpcTypeNotification, func(payload json.RawMessage) {
		var message struct {
			Hello string `json:"hello"`
		}
		if err := decodeStrictJSON(payload, &message); err == nil && message.Hello == "world" {
			select {
			case notifyChannel <- struct{}{}:
			default:
			}
		}
	})
	defer unsubscribe()

	for index := 0; index < workload.Rekey.Client; index++ {
		if err := connected.Rekey(); err != nil {
			return metrics, fmt.Errorf("client rekey %d: %w", index, err)
		}
		metrics.Rekeys++
		if err := rpcEcho(ctx, connected, index, false); err != nil {
			return metrics, fmt.Errorf("post-client-rekey RPC: %w", err)
		}
	}
	for index := 0; index < workload.Rekey.Server; index++ {
		if err := rpcControl(ctx, connected, rpcTypeServerRekey); err != nil {
			return metrics, fmt.Errorf("server rekey %d: %w", index, err)
		}
		metrics.Rekeys++
	}
	for index := 0; index < workload.Rekey.Concurrent; index++ {
		errorChannel := make(chan error, 2)
		go func() { errorChannel <- connected.Rekey() }()
		go func() { errorChannel <- rpcControl(ctx, connected, rpcTypeServerRekey) }()
		for range 2 {
			if err := <-errorChannel; err != nil {
				return metrics, fmt.Errorf("concurrent rekey: %w", err)
			}
			metrics.Rekeys++
		}
	}

	if err := exerciseGoStreams(ctx, connected, workload.Streams, &metrics); err != nil {
		return metrics, err
	}
	if err := exerciseGoMixedStreamsAndRPC(ctx, connected, workload.Streams, &metrics); err != nil {
		return metrics, err
	}
	for index := 0; index < workload.LivenessProbes; index++ {
		if _, err := connected.ProbeLiveness(ctx); err != nil {
			return metrics, fmt.Errorf("liveness probe %d: %w", index, err)
		}
		metrics.LivenessProbes++
	}
	for index := 0; index < workload.RPC.Calls; index++ {
		if err := rpcEcho(ctx, connected, index, index < workload.RPC.Notifications); err != nil {
			return metrics, fmt.Errorf("RPC call %d: %w", index, err)
		}
		metrics.RPCCalls++
	}
	queueRejections, err := exerciseGoRPCSaturation(ctx, connected, workload.RPC)
	if err != nil {
		return metrics, err
	}
	metrics.RPCQueueRejections += queueRejections
	metrics.ResourceRejections += queueRejections
	metrics.LimitChecks++
	if err := recordDiagnostic(diagnostics, "rpc_queue", string(connected.Path())); err != nil {
		return metrics, err
	}
	for index := 0; index < workload.RPC.Cancellations; index++ {
		callCtx, cancel := context.WithCancel(ctx)
		cancel()
		_, _, err := connected.RPC().Call(callCtx, rpcTypeDelay, json.RawMessage(`{}`))
		if !errors.Is(err, context.Canceled) {
			return metrics, fmt.Errorf("RPC cancellation %d returned %v", index, err)
		}
		metrics.RPCCancellations++
	}
	for index := 0; index < workload.RPC.Timeouts; index++ {
		callCtx, cancel := context.WithTimeout(ctx, time.Millisecond)
		_, _, err := connected.RPC().Call(callCtx, rpcTypeDelay, json.RawMessage(`{}`))
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			return metrics, fmt.Errorf("RPC timeout %d returned %v", index, err)
		}
		metrics.RPCTimeouts++
	}
	for index := 0; index < workload.RPC.Notifications; index++ {
		select {
		case <-notifyChannel:
			metrics.RPCNotifications++
		case <-ctx.Done():
			return metrics, ctx.Err()
		}
	}
	if err := exerciseGoProxy(ctx, connected, upstreamURL, workload.Proxy, &metrics); err != nil {
		return metrics, err
	}
	if err := rpcControl(ctx, connected, rpcTypeComplete); err != nil {
		return metrics, fmt.Errorf("complete reference session: %w", err)
	}
	return metrics, nil
}

func exerciseGoStreams(ctx context.Context, connected client.Client, workload interopprotocol.StreamWorkload, metrics *interopprotocol.Metrics) error {
	var bytesWritten atomic.Int64
	var bytesRead atomic.Int64
	var slowReaders atomic.Int64
	errorChannel := make(chan error, workload.Concurrent)
	var group sync.WaitGroup
	for index := 0; index < workload.Concurrent; index++ {
		group.Add(1)
		go func(streamIndex int) {
			defer group.Done()
			stream, err := connected.OpenStream(ctx, "echo")
			if err != nil {
				errorChannel <- err
				return
			}
			payload := bytes.Repeat([]byte{byte(streamIndex % 251)}, workload.BytesPerStream)
			for offset := 0; offset < len(payload); offset += workload.ChunkBytes {
				end := min(len(payload), offset+workload.ChunkBytes)
				if _, err := stream.Write(payload[offset:end]); err != nil {
					errorChannel <- err
					return
				}
				bytesWritten.Add(int64(end - offset))
			}
			if streamIndex < workload.SlowReaders {
				time.Sleep(25 * time.Millisecond)
				slowReaders.Add(1)
			}
			echoed := make([]byte, len(payload))
			if _, err := io.ReadFull(stream, echoed); err != nil {
				errorChannel <- err
				return
			}
			bytesRead.Add(int64(len(echoed)))
			if !bytes.Equal(payload, echoed) {
				errorChannel <- errors.New("echo payload mismatch")
				return
			}
			if err := stream.Close(); err != nil {
				errorChannel <- err
			}
		}(index)
	}
	group.Wait()
	close(errorChannel)
	var combined error
	for err := range errorChannel {
		joinedError(&combined, err)
	}
	if combined != nil {
		return combined
	}
	metrics.Streams += workload.Concurrent
	metrics.SlowReaders += int(slowReaders.Load())
	metrics.BytesWritten += bytesWritten.Load()
	metrics.BytesRead += bytesRead.Load()
	if _, err := connected.ProbeLiveness(ctx); err != nil {
		return fmt.Errorf("post-stream FIN barrier: %w", err)
	}
	for index := 0; index < workload.Churn; index++ {
		stream, err := connected.OpenStream(ctx, "churn")
		if err != nil {
			return fmt.Errorf("stream churn open %d: %w", index, err)
		}
		var terminal [1]byte
		if _, err := stream.Read(terminal[:]); !errors.Is(err, io.EOF) {
			return fmt.Errorf("stream churn peer FIN %d: %w", index, err)
		}
		if err := stream.Close(); err != nil {
			return fmt.Errorf("stream churn close %d: %w", index, err)
		}
		metrics.Streams++
		if (index+1)%8 == 0 {
			if _, err := connected.ProbeLiveness(ctx); err != nil {
				return fmt.Errorf("stream churn FIN barrier %d: %w", index, err)
			}
		}
	}
	for index := 0; index < workload.FIN; index++ {
		stream, err := connected.OpenStream(ctx, "echo")
		if err != nil {
			return fmt.Errorf("FIN stream open %d: %w", index, err)
		}
		if err := stream.Close(); err != nil {
			return fmt.Errorf("FIN stream close %d: %w", index, err)
		}
		metrics.Streams++
		metrics.FINs++
		if (index+1)%8 == 0 {
			if _, err := connected.ProbeLiveness(ctx); err != nil {
				return fmt.Errorf("FIN barrier %d: %w", index, err)
			}
		}
	}
	for index := 0; index < workload.Reset; index++ {
		stream, err := connected.OpenStream(ctx, "echo")
		if err != nil {
			return fmt.Errorf("reset stream open %d: %w", index, err)
		}
		if err := stream.Reset(); err != nil {
			return fmt.Errorf("reset stream %d: %w", index, err)
		}
		metrics.Streams++
		metrics.Resets++
	}
	return nil
}

func exerciseGoMixedStreamsAndRPC(
	ctx context.Context,
	connected client.Client,
	workload interopprotocol.StreamWorkload,
	metrics *interopprotocol.Metrics,
) error {
	if workload.MixedConcurrent == 0 {
		return nil
	}
	type outcome struct {
		stream  bool
		rpc     bool
		written int
		read    int
		err     error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, workload.MixedConcurrent)
	for index := 0; index < workload.MixedConcurrent; index++ {
		if index%2 == 0 {
			go func(streamIndex int) {
				<-start
				stream, err := connected.OpenStream(ctx, mixedEchoKind)
				if err != nil {
					outcomes <- outcome{err: err}
					return
				}
				payload := bytes.Repeat([]byte{byte(streamIndex % 251)}, workload.MixedBytesPerStream)
				type readOutcome struct {
					payload []byte
					err     error
				}
				readDone := make(chan readOutcome, 1)
				go func() {
					echoed := make([]byte, len(payload))
					_, err := io.ReadFull(stream, echoed)
					readDone <- readOutcome{payload: echoed, err: err}
				}()
				var writeErr error
				for offset := 0; offset < len(payload); offset += workload.ChunkBytes {
					end := min(len(payload), offset+workload.ChunkBytes)
					if _, err := stream.Write(payload[offset:end]); err != nil {
						writeErr = err
						break
					}
				}
				if writeErr != nil {
					writeErr = errors.Join(writeErr, stream.Reset())
				}
				readResult := <-readDone
				if err := errors.Join(writeErr, readResult.err); err != nil {
					outcomes <- outcome{err: err}
					return
				}
				if !bytes.Equal(payload, readResult.payload) {
					outcomes <- outcome{err: errors.Join(errors.New("mixed echo payload mismatch"), stream.Reset())}
					return
				}
				outcomes <- outcome{stream: true, written: len(payload), read: len(readResult.payload), err: stream.Close()}
			}(index)
		} else {
			go func(rpcIndex int) {
				<-start
				outcomes <- outcome{rpc: true, err: rpcEcho(ctx, connected, rpcIndex, false)}
			}(index)
		}
	}
	close(start)
	var combined error
	for range workload.MixedConcurrent {
		result := <-outcomes
		if result.err != nil {
			joinedError(&combined, result.err)
			continue
		}
		if result.stream {
			metrics.Streams++
			metrics.BytesWritten += int64(result.written)
			metrics.BytesRead += int64(result.read)
		}
		if result.rpc {
			metrics.RPCCalls++
		}
	}
	if combined != nil {
		return fmt.Errorf("mixed RPC/stream workload: %w", combined)
	}
	return nil
}

func exerciseGoRPCSaturation(ctx context.Context, connected client.Client, workload interopprotocol.RPCWorkload) (int, error) {
	total := workload.SaturationActive + workload.SaturationQueued + workload.SaturationRejected
	gate, err := connected.OpenStream(ctx, saturationGateKind)
	if err != nil {
		return 0, fmt.Errorf("open RPC saturation gate: %w", err)
	}
	gateReleased := false
	defer func() {
		if !gateReleased {
			_ = gate.Reset()
		}
	}()
	type outcome struct {
		rejected bool
		err      error
	}
	outcomes := make(chan outcome, total)
	for range total {
		go func() {
			response, rpcError, err := connected.RPC().Call(ctx, rpcTypeSaturation, json.RawMessage(`{}`))
			if err != nil {
				outcomes <- outcome{err: err}
				return
			}
			if rpcError != nil {
				if rpcError.Code == 429 {
					outcomes <- outcome{rejected: true}
					return
				}
				outcomes <- outcome{err: fmt.Errorf("saturation RPC returned code %d", rpcError.Code)}
				return
			}
			var value struct {
				OK bool `json:"ok"`
			}
			if err := decodeStrictJSON(response, &value); err != nil || !value.OK {
				outcomes <- outcome{err: errors.Join(err, errors.New("invalid saturation RPC response"))}
				return
			}
			outcomes <- outcome{}
		}()
	}
	rejected := 0
	succeeded := 0
	var combined error
	for range total {
		var result outcome
		select {
		case result = <-outcomes:
		case <-ctx.Done():
			return rejected, ctx.Err()
		}
		if result.rejected {
			rejected++
			if !gateReleased {
				n, writeErr := gate.Write([]byte{1})
				if writeErr == nil && n != 1 {
					writeErr = io.ErrShortWrite
				}
				closeErr := gate.Close()
				if err := errors.Join(writeErr, closeErr); err != nil {
					return rejected, fmt.Errorf("release RPC saturation gate: %w", err)
				}
				gateReleased = true
			}
		} else if result.err != nil {
			joinedError(&combined, result.err)
		} else {
			succeeded++
		}
	}
	if combined != nil {
		return rejected, combined
	}
	if !gateReleased {
		return rejected, errors.New("RPC saturation completed without a queue rejection")
	}
	if succeeded != workload.SaturationActive+workload.SaturationQueued || rejected != workload.SaturationRejected {
		return rejected, fmt.Errorf("RPC saturation got %d successes and %d rejections", succeeded, rejected)
	}
	return rejected, nil
}

func exerciseGoProxy(ctx context.Context, connected client.Client, upstreamURL string, workload interopprotocol.ProxyWorkload, metrics *interopprotocol.Metrics) error {
	proxyClient, err := proxy.NewClient(proxy.ContractOptions{})
	if err != nil {
		return err
	}
	body := bytes.Repeat([]byte("p"), workload.HTTPBodyBytes)
	for index := 0; index < workload.HTTPRequests; index++ {
		response, err := proxyClient.Do(ctx, connected, proxy.ClientHTTPRequest{
			Method: http.MethodPost, Path: "/http", Body: bytes.NewReader(body),
		})
		if err != nil {
			return fmt.Errorf("proxy HTTP request %d: %w", index, err)
		}
		responseBody, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		if response.StatusCode != http.StatusOK || !bytes.Equal(responseBody, body) {
			return fmt.Errorf("proxy HTTP response %d does not match Go upstream %s", index, upstreamURL)
		}
		metrics.HTTPRequests++
	}
	if workload.StreamingHTTPBodyBytes > 0 {
		streamingBody := bytes.Repeat([]byte("s"), workload.StreamingHTTPBodyBytes)
		response, err := proxyClient.Do(ctx, connected, proxy.ClientHTTPRequest{
			Method: http.MethodPost, Path: "/http", Body: bytes.NewReader(streamingBody),
		})
		if err != nil {
			return fmt.Errorf("streaming proxy HTTP request: %w", err)
		}
		responseBody, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		if response.StatusCode != http.StatusOK || !bytes.Equal(responseBody, streamingBody) {
			return fmt.Errorf("streaming proxy HTTP response does not match Go upstream %s", upstreamURL)
		}
		metrics.HTTPRequests++
	}
	websocket, err := proxyClient.OpenWebSocket(ctx, connected, "/ws", nil)
	if err != nil {
		return err
	}
	payload := bytes.Repeat([]byte("w"), workload.WebSocketFrameBytes)
	for index := 0; index < workload.WebSocketFrames; index++ {
		if err := websocket.WriteFrame(1, payload); err != nil {
			return errors.Join(err, websocket.Close())
		}
		op, received, err := websocket.ReadFrame()
		if err != nil {
			return errors.Join(err, websocket.Close())
		}
		if op != 1 || !bytes.Equal(received, payload) {
			return errors.Join(errors.New("proxy WebSocket echo mismatch"), websocket.Close())
		}
		metrics.WebSocketFrames++
	}
	return websocket.Close()
}

func rpcEcho(ctx context.Context, connected client.Client, value int, notify bool) error {
	payload, err := json.Marshal(map[string]any{"value": value, "notify": notify})
	if err != nil {
		return err
	}
	response, rpcError, err := connected.RPC().Call(ctx, rpcTypeEcho, payload)
	if err != nil {
		return err
	}
	if rpcError != nil {
		return fmt.Errorf("remote RPC error %d", rpcError.Code)
	}
	var decoded struct {
		Value int `json:"value"`
	}
	if err := decodeStrictJSON(response, &decoded); err != nil {
		return err
	}
	if decoded.Value != value {
		return fmt.Errorf("RPC response value %d does not match %d", decoded.Value, value)
	}
	return nil
}

func rpcControl(ctx context.Context, connected client.Client, typeID uint32) error {
	_, rpcError, err := connected.RPC().Call(ctx, typeID, json.RawMessage(`{}`))
	if err != nil {
		return err
	}
	if rpcError != nil {
		return fmt.Errorf("remote control RPC error %d", rpcError.Code)
	}
	return nil
}

func decodeStrictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("JSON value contains trailing data")
	}
	return nil
}
