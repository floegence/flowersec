package sessionv4

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestControllerTransportFailureRequiresOriginalProviderWrite(t *testing.T) {
	for _, source := range []string{"provider", "builder", "prior_close", "prior_protocol"} {
		t.Run(source, func(t *testing.T) {
			e := newOpenEndpoint(t, 0, 2, 2, 1)
			w, err := NewRecordWriter(e.engine, 0, idleWriterFunc(func([]byte) (int, error) { return 0, io.ErrClosedPipe }))
			if err != nil {
				t.Fatal(err)
			}
			w.failureOwner = e.admission
			switch source {
			case "prior_close":
				e.admission.Close()
			case "prior_protocol":
				e.admission.closeWithCause(cryptov4.ErrConfiguration)
			}
			if source == "builder" {
				_, err = w.WriteBuild(context.Background(), protocolv4.FramePing, 32, func(protocolv4.RecordHeader, []byte) (int, error) { return 0, io.ErrClosedPipe })
			} else {
				_, err = w.Write(context.Background(), protocolv4.FramePing, pingBody(t, 1))
			}
			if source == "provider" && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal("provider cause lost", err)
			}
			e.admission.mu.Lock()
			failure, retry := e.admission.failure, e.admission.transportFailure
			e.admission.mu.Unlock()
			if retry != (source == "provider") {
				t.Fatal("transport provenance changed", source, retry)
			}
			if source == "provider" && failure != io.ErrClosedPipe || source == "prior_protocol" && failure != cryptov4.ErrConfiguration {
				t.Fatal("first failure overwritten", failure)
			}
		})
	}
}

func TestControllerRuntimeOriginalInputFailureSurvivesIngressClosure(t *testing.T) {
	for _, nativeStream := range []bool{false, true} {
		for _, kind := range []string{"eof", "truncated", "connection", "framing", "protocol"} {
			t.Run(kind+map[bool]string{false: "/shared", true: "/maintenance"}[nativeStream], func(t *testing.T) {
				local := newOpenEndpoint(t, 0, 2, 2, 1)
				var input io.Reader = bytes.NewReader(nil)
				expected := error(io.EOF)
				switch kind {
				case "truncated":
					input, expected = bytes.NewReader([]byte{0, 0}), io.ErrUnexpectedEOF
				case "connection":
					input, expected = initialFailedStream{err: native.ErrConnectionLost}, native.ErrConnectionLost
				case "protocol":
					input, expected = initialFailedStream{err: ErrInitialPhase}, ErrInitialPhase
				case "framing":
					prefix := make([]byte, protocolv4.EnvelopePrefixSize)
					binary.BigEndian.PutUint32(prefix, local.engine.MaxFrame()+1)
					prefix[4] = byte(protocolv4.FramePing)
					input, expected = bytes.NewReader(prefix), protocolv4.ErrPayloadTooLarge
				}
				f := newRuntimeFixture(t, local, &runtimeTestInput{Reader: input}, nativeStream)
				r := f.startOwner(t)
				if err := r.Run(context.Background()); err != expected {
					t.Fatal("original input result changed", kind, err, expected)
				}
				r.mu.Lock()
				retry := r.transportFailure
				r.mu.Unlock()
				if retry != (kind == "eof" || kind == "truncated" || kind == "connection") {
					t.Fatal("input provenance changed", kind, retry)
				}
			})
		}
	}
}

func TestControllerRuntimeServiceCannotForgeConnectionInterruption(t *testing.T) {
	local := newOpenEndpoint(t, 0, 2, 2, 1)
	reader, writer := io.Pipe()
	defer writer.Close()
	f := newRuntimeFixture(t, local, &runtimeTestInput{Reader: reader, interrupt: func() { _ = reader.Close() }}, false)
	r := f.startOwner(t)
	r.stopWith(native.ErrConnectionLost)
	r.mu.Lock()
	retry := r.transportFailure
	r.mu.Unlock()
	if retry {
		t.Fatal("service failure became provider provenance")
	}
}

func TestControllerRuntimeRetainsTransportFailureProvenance(t *testing.T) {
	for _, transport := range []bool{false, true} {
		local := newOpenEndpoint(t, 0, 2, 2, 1)
		reader, writer := io.Pipe()
		defer writer.Close()
		f := newRuntimeFixture(t, local, &runtimeTestInput{Reader: reader, interrupt: func() { _ = reader.Close() }}, false)
		r := f.startOwner(t)
		local.admission.closeWithSource(io.ErrClosedPipe, transport)
		r.stopWithSource(cryptov4.ErrClosed, !transport)
		r.mu.Lock()
		cause, retry := r.result, r.transportFailure
		r.mu.Unlock()
		if cause != io.ErrClosedPipe || retry != transport {
			t.Fatal("cleanup changed failure source", cause, retry, transport)
		}
	}
}
