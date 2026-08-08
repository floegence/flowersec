package artifactv2

import (
	"bytes"
	"testing"
)

func FuzzArtifactAndAdmissionParsers(f *testing.F) {
	f.Add([]byte(`{"v":2,"profile":"flowersec/2"}`))
	f.Add([]byte("FSB2\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeArtifactJSON(bytes.NewReader(raw))
		_, _ = ParseRequest(raw)
		_, _ = ParseResponse(raw, ReasonRegistry{})
		_, _ = ParseClientResponse(raw)
	})
}
