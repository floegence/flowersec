package flowersec_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
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
	if err := connectExample(); err != nil {
		reportRecovery(err)
	}
}

func TestExampleConnectE2E(t *testing.T) {
	if os.Getenv("FSEC_ARTIFACT_V3_PATH") == "" {
		t.Skip("example E2E input is supplied by the acceptance runner")
	}
	if err := connectExample(); err != nil {
		t.Fatal(err)
	}
}

func connectExample() error {
	artifactJSON, err := os.ReadFile(os.Getenv("FSEC_ARTIFACT_V3_PATH"))
	if err != nil {
		return err
	}
	artifact, err := flowersec.ParseArtifact(artifactJSON)
	if err != nil {
		return err
	}
	receiptPath := os.Getenv("FSEC_SPEND_RECEIPT_V3_PATH")
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error {
		return commitSpendReceipt(receiptPath)
	})
	if err != nil {
		return err
	}
	trustRoots, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	if trustRootPath := os.Getenv("FSEC_TRUST_ROOT_PEM_PATH"); trustRootPath != "" {
		trustRootPEM, readErr := os.ReadFile(trustRootPath)
		if readErr != nil {
			return readErr
		}
		if !trustRoots.AppendCertsFromPEM(trustRootPEM) {
			return errors.New("invalid trust root PEM")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{
		TrustRoots:     trustRoots,
		Origin:         os.Getenv("FSEC_ORIGIN"),
		ConnectTimeout: 15 * time.Second,
	})
	if err != nil {
		return err
	}
	if err := runExampleApplication(ctx, session); err != nil {
		_ = session.Close()
		return err
	}
	return session.Close()
}

func runExampleApplication(ctx context.Context, session flowersec.Session) error {
	request := exampleValuePayload{Value: "ping"}
	var response exampleValuePayload
	if err := session.RPC().Call(ctx, exampleEchoRPCTypeID, request, &response); err != nil {
		return fmt.Errorf("typed RPC: %w", err)
	}
	if response != request {
		return errors.New("unexpected typed RPC response")
	}
	if err := session.RPC().Notify(ctx, exampleNotificationTypeID, exampleValuePayload{Value: "notify"}); err != nil {
		return fmt.Errorf("send notification: %w", err)
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
		return fmt.Errorf("open stream: %w", err)
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
	if err != nil {
		return fmt.Errorf("probe liveness: %w", err)
	}
	return nil
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
	_, writeErr := receipt.WriteString("flowersec-v3-artifact-spent\n")
	if err := errors.Join(writeErr, receipt.Sync(), receipt.Close()); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
