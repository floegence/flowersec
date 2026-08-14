package flowersec_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
)

const (
	exampleEchoRPCTypeID      = uint32(7001)
	exampleNotificationTypeID = uint32(7002)
	exampleEchoStreamKind     = "parity.echo"
)

type exampleValuePayload struct {
	Value string `json:"value"`
}

func ExampleConnect() {
	artifactJSON, err := os.ReadFile(os.Getenv("FSEC_ARTIFACT_V2_PATH"))
	if err != nil {
		reportExampleError(err)
		return
	}
	artifact, err := flowersec.ParseArtifact(artifactJSON)
	if err != nil {
		reportExampleError(err)
		return
	}
	receiptPath := os.Getenv("FSEC_SPEND_RECEIPT_V2_PATH")
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error {
		return commitSpendReceipt(receiptPath)
	})
	if err != nil {
		reportExampleError(err)
		return
	}
	trustRoots, err := x509.SystemCertPool()
	if err != nil {
		reportExampleError(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{
		TrustRoots:     trustRoots,
		Origin:         os.Getenv("FSEC_ORIGIN"),
		ConnectTimeout: 15 * time.Second,
	})
	if err != nil {
		reportRecovery(err)
		return
	}
	defer session.Close()
	if err := runExampleApplication(ctx, session); err != nil {
		reportRecovery(err)
	}
}

func runExampleApplication(ctx context.Context, session flowersec.Session) error {
	notifications := make(chan exampleValuePayload, 1)
	unsubscribe := session.RPC().OnNotify(exampleNotificationTypeID, func(_ context.Context, raw json.RawMessage) {
		var payload exampleValuePayload
		if json.Unmarshal(raw, &payload) == nil {
			select {
			case notifications <- payload:
			default:
			}
		}
	})
	defer unsubscribe()

	request := exampleValuePayload{Value: "ping"}
	var response exampleValuePayload
	if err := session.RPC().Call(ctx, exampleEchoRPCTypeID, request, &response); err != nil {
		return err
	}
	if response != request {
		return errors.New("unexpected typed RPC response")
	}
	if err := session.RPC().Notify(ctx, exampleNotificationTypeID, exampleValuePayload{Value: "notify"}); err != nil {
		return err
	}
	select {
	case notification := <-notifications:
		if notification.Value != "notify" {
			return errors.New("unexpected notification payload")
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	streamCell := os.Getenv("FSEC_EXAMPLE_STREAM_CELL")
	if streamCell == "" {
		streamCell = "direct"
	}
	metadata, err := flowersec.NewStreamMetadata(map[string]any{"cell": streamCell})
	if err != nil {
		return err
	}
	stream, err := session.OpenStream(ctx, exampleEchoStreamKind, metadata)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := writeExampleAll(stream, []byte("hello")); err != nil {
		return err
	}
	if err := stream.CloseWrite(); err != nil {
		return err
	}
	responseBytes, err := io.ReadAll(stream)
	if err != nil {
		return err
	}
	if string(responseBytes) != "world" {
		return errors.New("unexpected reliable stream response")
	}
	_, err = session.ProbeLiveness(ctx)
	return err
}

func writeExampleAll(stream flowersec.ByteStream, payload []byte) error {
	for len(payload) > 0 {
		written, err := stream.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func reportRecovery(err error) {
	var connectError *flowersec.ConnectError
	if errors.As(err, &connectError) {
		fmt.Fprintf(os.Stderr, "recovery=%s\n", connectError.RetryDisposition().Kind)
		return
	}
	var sessionError *flowersec.SessionError
	if errors.As(err, &sessionError) {
		fmt.Fprintf(os.Stderr, "recovery=%s\n", sessionError.RetryDisposition().Kind)
		return
	}
	reportExampleError(err)
}

func reportExampleError(err error) {
	fmt.Fprintf(os.Stderr, "flowersec example failed (%T)\n", err)
}

func commitSpendReceipt(path string) error {
	receipt, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := receipt.WriteString("flowersec-v2-artifact-spent\n")
	if err := errors.Join(writeErr, receipt.Sync(), receipt.Close()); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
