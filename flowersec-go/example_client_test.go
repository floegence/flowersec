package flowersec_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/examples/parityclient"
)

func ExampleConnect() {
	if err := connectExample(); err != nil {
		reportExampleError(err)
	}
}

func reportExampleError(err error) {
	if err != nil {
		// A new attempt needs new material. Preserve the SDK's structured
		// recovery and original submission facts instead of replaying work.
		var connection *fs.ConnectError
		var session *fs.SessionError
		var operation *exampleExchangeError
		if errors.As(err, &operation) {
			fmt.Fprintf(os.Stderr, "flowersec operation failed (rpc-submitted=%t, notify-submitted=%t, stream-accepted=%d, rpc-reference=%t)\n",
				operation.facts.RPC.Submission.MessageAccepted, operation.facts.Notification.MessageAccepted,
				operation.facts.Write.AcceptedBytes, operation.facts.RPC.Reference.Valid())
		}
		switch {
		case errors.As(err, &connection):
			disposition := connection.RetryDisposition()
			fmt.Fprintf(os.Stderr, "flowersec connection failed (code=%s, retry=%s, not-before=%d)\n",
				connection.Code(), disposition.Kind, disposition.RetryAtUnixMilliseconds)
		case errors.As(err, &session):
			disposition := session.RetryDisposition()
			fmt.Fprintf(os.Stderr, "flowersec session failed (code=%s, retry=%s, not-before=%d)\n",
				session.Code(), disposition.Kind, disposition.RetryAtUnixMilliseconds)
		default:
			fmt.Fprintf(os.Stderr, "flowersec example failed (%T)\n", err)
		}
	}
}

func TestExampleConnectE2E(t *testing.T) {
	if os.Getenv("FSEC_MATERIAL_PATH") == "" {
		t.Skip("example E2E input is supplied by the acceptance runner")
	}
	if err := connectExample(); err != nil {
		t.Fatal(err)
	}
}

func connectExample() (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Only the acceptance runner supplies this trusted deployment manifest.
	// Applications configure independent pins, keys, clock and durable history
	// through parityclient.New; the entire consumer uses published SDK imports.
	client, err := parityclient.OpenAcceptanceFixture(ctx, os.Getenv("FSEC_MATERIAL_PATH"),
		os.Getenv("FSEC_TRUST_ROOT_PEM_PATH"), os.Getenv("FSEC_SPEND_RECEIPT_PATH"), os.Getenv("FSEC_ORIGIN"))
	if client != nil {
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			err = errors.Join(err, client.Close(cleanup))
		}()
	}
	if err != nil {
		return err
	}
	if _, err = client.Connect(ctx); err != nil {
		return err
	}
	if client.SourceAcquisitions() != 1 || !client.SpendStatus().CommitKnown {
		return errors.New("original source did not durably consume exactly once")
	}
	// Connect returned dual READY and observed the original SQLite consumer's
	// definite commit. This receipt reports that fact; it never authorizes it.
	if err = commitSpendReceipt(os.Getenv("FSEC_SPEND_RECEIPT_PATH")); err != nil {
		return err
	}
	facts, err := client.Exchange(ctx, os.Getenv("FSEC_EXAMPLE_STREAM_CELL"))
	if err != nil {
		return &exampleExchangeError{cause: err, facts: facts}
	}
	return nil
}

type exampleExchangeError struct {
	cause error
	facts parityclient.ExchangeResult
}

func (e *exampleExchangeError) Error() string { return "flowersec parity exchange failed" }
func (e *exampleExchangeError) Unwrap() error { return e.cause }

func commitSpendReceipt(path string) error {
	receipt, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := receipt.WriteString("flowersec-v4-material-spent\n")
	if err := errors.Join(writeErr, receipt.Sync(), receipt.Close()); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
