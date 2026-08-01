package flowersec_test

import (
	"context"
	"errors"
	"os"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
)

func ExampleNewConnector() {
	artifactJSON, err := os.ReadFile(os.Getenv("FSEC_ARTIFACT_V2_PATH"))
	if err != nil {
		return
	}
	artifact, err := flowersec.ParseArtifact(artifactJSON)
	if err != nil {
		return
	}
	receiptPath := os.Getenv("FSEC_SPEND_RECEIPT_V2_PATH")
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error {
		return commitSpendReceipt(receiptPath)
	})
	if err != nil {
		return
	}
	connector, err := flowersec.NewConnector(lease, flowersec.ConnectorOptions{
		Origin:         os.Getenv("FSEC_ORIGIN"),
		ConnectTimeout: 15 * time.Second,
	})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := connector.Connect(ctx)
	if err != nil {
		return
	}
	defer session.Close()
	_, _ = session.ProbeLiveness(ctx)
}

func commitSpendReceipt(path string) error {
	receipt, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := receipt.WriteString("flowersec-v2-artifact-spent\n")
	return errors.Join(writeErr, receipt.Sync(), receipt.Close())
}
