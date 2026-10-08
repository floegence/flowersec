package parityclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
)

// ExchangeResult retains the SDK's original facts even when an operation fails.
// Cancellation or Close never changes submitted work into "not executed".
type ExchangeResult struct {
	RPC          fs.Result
	Notification fs.NotificationResult
	Write        fs.WriteProgress
	Read         fs.ReadResult
	StreamClose  fs.CloseResult
	Liveness     fs.LivenessResult
}

// Exchange runs the shared parity contract on the Session returned by Connect.
// Its six-byte read bound admits "world" plus EOF and rejects trailing data.
// The caller always follows it with Close using a fresh cleanup deadline.
func (c *Client) Exchange(ctx context.Context, cell string) (result ExchangeResult, err error) {
	if ctx == nil || !c.connected || c.session == nil || c.closed || c.service != nil {
		return result, errors.New("parity exchange requires the original connected client")
	}
	if cell == "" {
		cell = "direct"
	}
	c.service, err = c.session.BindMethods(ctx, c.definition, fs.ServiceBindOptions{
		ContractSource: fs.ServiceContractsStatic,
		Workloads: []fs.ServiceMethodWorkload{
			{Type: 7001, Calls: 1, RequestBytes: 4096, ResponseLimitBytes: 4096},
			{Type: 7002, Calls: 1, RequestBytes: 4096},
		},
	})
	if err != nil {
		return result, err
	}
	result.RPC, err = c.service.CallMethod(ctx, fs.MethodSelector{Namespace: parityNamespace, Type: 7001},
		[]byte(`{"value":"ping"}`), fs.OperationOptions{DefaultLifetimeMS: 10000, ResponseLimitBytes: 4096})
	if err != nil {
		return result, err
	}
	if result.RPC.Err != nil {
		return result, result.RPC.Err
	}
	var response struct {
		Value string `json:"value"`
	}
	wire, ok := result.RPC.Value.([]byte)
	if !ok || json.Unmarshal(wire, &response) != nil || response.Value != "ping" {
		return result, errors.New("unexpected typed parity RPC result")
	}
	result.Notification, err = c.service.NotifyMethod(ctx, fs.MethodSelector{Namespace: parityNamespace, Type: 7002},
		[]byte(`{"value":"notify"}`), fs.OperationOptions{DefaultLifetimeMS: 10000})
	if err != nil {
		return result, err
	}
	if !result.Notification.MessageAccepted {
		return result, errors.New("notification was not accepted")
	}
	c.service.Close()
	// Result delivery can precede the original operation's physical cleanup.
	// Join that owner before opening the example's next application stream.
	if err = c.service.WaitCleanup(ctx); err != nil {
		return result, err
	}
	c.service = nil
	metadata, err := fs.NewStreamMetadata(map[string]any{"cell": cell})
	if err != nil {
		return result, err
	}
	stream, err := c.session.OpenStream(ctx, "parity.echo", metadata)
	if err != nil {
		return result, err
	}
	defer func() {
		closeErr := stream.Close()
		result.StreamClose, err = readCloseResult(stream, errors.Join(err, closeErr))
	}()
	write, err := stream.PrepareWrite([]byte("hello"), fs.WriteOptions{Timeout: 10 * time.Second})
	if err != nil {
		return result, err
	}
	defer write.Cancel()
	if err = write.Start(); err != nil {
		result.Write = write.Progress()
		return result, err
	}
	result.Write, err = write.Wait(ctx)
	if err != nil {
		// Stop this write's remaining input, retaining its accepted prefix facts.
		write.Cancel()
		result.Write = write.Progress()
		return result, err
	}
	if result.Write.Phase != fs.WriteTerminal || result.Write.TerminalReason != "complete" || result.Write.AcceptedBytes != 5 {
		return result, errors.New("stream did not accept the complete parity request")
	}
	if err = stream.CloseWrite(); err != nil {
		return result, err
	}
	cursor, err := stream.ReaderCursor(fs.ReaderCursorOptions{Exact: 6})
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, cursor.Close()) }()
	result.Read, err = cursor.ReadExactly(ctx)
	if err != nil && !errors.Is(err, io.EOF) {
		return result, err
	}
	if result.Read.WaitStatus != "ready" || result.Read.StreamStatus != "eof" || result.Read.Error != nil || string(result.Read.Data) != "world" {
		return result, errors.New("reliable parity response did not end with the expected FIN")
	}
	if err = stream.Finish(ctx); err != nil {
		return result, err
	}
	result.Liveness, err = c.session.ProbeLiveness(ctx, 1000)
	if err != nil {
		return result, err
	}
	if !result.Liveness.Complete {
		return result, errors.New("liveness probe did not complete")
	}
	return result, nil
}

func readCloseResult(stream fs.Stream, previous error) (fs.CloseResult, error) {
	result, err := stream.CloseResult()
	return result, errors.Join(previous, err)
}
