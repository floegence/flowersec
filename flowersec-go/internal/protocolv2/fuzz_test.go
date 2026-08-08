package protocolv2

import "testing"

func FuzzWireAndHandshakeParsers(f *testing.F) {
	f.Add([]byte("FSC2\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Add([]byte("FSH2\x02\x01\x00\x00\x00\x00\x00"))
	f.Add([]byte("FSR2\x02\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseSetupPreface(raw)
		_, _ = ParseRecordHeader(raw)
		_, _, _ = ParseInnerRecord(raw)
		_, _ = ParseUnreliableHeader(raw)
		_, _ = ParseOpenPayload(raw)
		_, _ = ParseOpenACK(raw)
		_, _ = ParseOpenReject(raw)
		_, _ = ParseHandshakeFrame(raw)
		_, _ = ParseClientInit(raw)
		_, _ = ParseServerFinished(raw, SuiteChaCha20Poly1305)
		_, _ = ParseClientFinished(raw)
	})
}
