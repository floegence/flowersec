package protocol

import "testing"

func FuzzParseAttachWithConstraints(f *testing.F) {
	// Valid endpoint_instance_id: base64url(16 zero bytes) = "AAAAAAAAAAAAAAAAAAAAAA".
	f.Add([]byte(`{"v":1,"channel_id":"ch_1","role":1,"token":"tok","endpoint_instance_id":"AAAAAAAAAAAAAAAAAAAAAA"}`))
	f.Add([]byte(`{"v":2}`))
	f.Add([]byte(`not json`))

	c := AttachConstraints{
		MaxAttachBytes: 8 * 1024,
		MaxChannelID:   256,
		MaxToken:       2048,
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseAttachWithConstraints(b, c)
	})
}
