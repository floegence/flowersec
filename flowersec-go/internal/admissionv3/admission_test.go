package admissionv3_test

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/admissionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
)

func TestRespondWritesRetryableExpiryAndFinishesResponseDirection(t *testing.T) {
	stream := &responseStream{}
	reasons := artifactv3.ReasonRegistry{artifactv3.ReasonExpiredArtifact: {}}
	response := artifactv3.AdmissionResponse{
		Status: artifactv3.AdmissionRetryable,
		Reason: artifactv3.ReasonExpiredArtifact,
	}
	if err := admissionv3.Respond(context.Background(), stream, response, reasons); err != nil {
		t.Fatal(err)
	}
	want := []byte("FSA3\x03\x02\x00\x10expired_artifact")
	if !bytes.Equal(stream.Bytes(), want) {
		t.Fatalf("FSA3 response = %x, want %x", stream.Bytes(), want)
	}
	if stream.closeWrites.Load() != 1 || stream.resets.Load() != 0 {
		t.Fatalf("response FIN/reset counts = %d/%d, want 1/0", stream.closeWrites.Load(), stream.resets.Load())
	}
}

type responseStream struct {
	bytes.Buffer
	closeWrites atomic.Int32
	resets      atomic.Int32
}

func (stream *responseStream) Context() context.Context { return context.Background() }
func (stream *responseStream) CloseWrite() error {
	stream.closeWrites.Add(1)
	return nil
}
func (stream *responseStream) StopSending() error { return nil }
func (stream *responseStream) Reset() error {
	stream.resets.Add(1)
	return nil
}
func (stream *responseStream) Close() error { return stream.Reset() }
