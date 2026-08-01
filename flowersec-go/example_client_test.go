package flowersec_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
)

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
	if _, err := session.ProbeLiveness(ctx); err != nil {
		reportRecovery(err)
	}
}

func reportRecovery(err error) {
	var connectError *flowersec.ConnectError
	if errors.As(err, &connectError) {
		fmt.Fprintf(os.Stderr, "recovery=%s\n", flowersec.ClassifyConnectError(connectError).Action)
		return
	}
	var sessionError *flowersec.SessionError
	if errors.As(err, &sessionError) {
		fmt.Fprintf(os.Stderr, "recovery=%s\n", flowersec.ClassifySessionError(sessionError).Action)
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
