package protocolv4

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestProxyApplicationSharedWireCorpus(t *testing.T) {
	count := 0
	for _, v := range cborRefVectors(t) {
		var out any
		switch v.Schema {
		case "ProxyHTTPRequest":
			out = &ProxyHTTPRequest{}
		case "ProxyHTTPResponse":
			out = &ProxyHTTPResponse{}
		case "ProxyWebSocketOpen":
			out = &ProxyWebSocketOpen{}
		case "ProxyWebSocketResponse":
			out = &ProxyWebSocketResponse{}
		case "ProxyBodyEnd":
			out = &ProxyBodyEnd{}
		default:
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			wire, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			err = DecodeProxyMetadata(wire, out)
			if v.ExpectedError != "" {
				if err == nil {
					t.Fatal("accepted malformed input")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var value any
			switch p := out.(type) {
			case *ProxyHTTPRequest:
				value = *p
			case *ProxyHTTPResponse:
				value = *p
			case *ProxyWebSocketOpen:
				value = *p
			case *ProxyWebSocketResponse:
				value = *p
			case *ProxyBodyEnd:
				value = *p
			}
			encoded, err := EncodeProxyMetadata(value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, wire) {
				t.Fatalf("wire differs: %x != %x", encoded, wire)
			}
		})
		count++
	}
	if count != 8 {
		t.Fatalf("expected six shared maps and two negatives, got %d", count)
	}
}

func TestProxyApplicationRejectsTextAndPreservesLargeFieldLists(t *testing.T) {
	headers := make([]ProxyHeader, 2048)
	for i := range headers {
		headers[i] = ProxyHeader{"x-octets", string([]byte{0x80, 0xff})}
	}
	request := ProxyHTTPRequest{Version: ProxyApplicationVersion(), RequestID: "r", Method: "pAtCh", Path: "/", Headers: headers}
	raw, err := EncodeProxyMetadata(request)
	if err != nil {
		t.Fatal(err)
	}
	var output ProxyHTTPRequest
	if err := DecodeProxyMetadata(raw, &output); err != nil {
		t.Fatal(err)
	}
	if output.Method != "pAtCh" || len(output.Headers) != 2048 || output.Headers[2047].Value != headers[0].Value {
		t.Fatal("lost method or ordered octets")
	}
	for _, raw := range [][]byte{[]byte(`{"v":1}`), {0xa1, 0, 2}, {0xbf, 0, 2, 0xff}} {
		if DecodeProxyMetadata(raw, &output) == nil {
			t.Fatal("accepted noncanonical or incomplete map")
		}
	}
}

func TestProxyCredentialClearFailureRetainsConfirmedServerFact(t *testing.T) {
	id := "0102030405060708090a0b0c0d0e0f10"
	for _, action := range []uint8{2, 3} {
		response := ProxyCredentialControlResponse{Version: ProxyApplicationVersion(), OperationID: id, Action: action, OK: false, ServerInvalidated: true, Error: &ProxyError{Code: "credential_scope_unavailable", Message: "credential scope unavailable"}}
		wire, err := EncodeProxyMetadata(response)
		if err != nil {
			t.Fatal(err)
		}
		var read ProxyCredentialControlResponse
		if err = DecodeProxyMetadata(wire, &read); err != nil {
			t.Fatal(err)
		}
		if read.OK || !read.ServerInvalidated || read.CredentialContext != "" || read.Error == nil {
			t.Fatal("replacement failure erased the independently confirmed invalidation")
		}
	}
	response := ProxyCredentialControlResponse{Version: ProxyApplicationVersion(), OperationID: id, Action: 1, OK: false, ServerInvalidated: true, Error: &ProxyError{Code: "credential_scope_unavailable", Message: "credential scope unavailable"}}
	if _, err := EncodeProxyMetadata(response); err == nil {
		t.Fatal("Bind claimed a server invalidation fact")
	}
}

func TestProxyCredentialMetadataRejectsNonCanonicalAssociation(t *testing.T) {
	for _, request := range []ProxyHTTPRequest{
		{Version: ProxyApplicationVersion(), RequestID: "r", Method: "GET", Path: "/", CredentialContext: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx="},
		{Version: ProxyApplicationVersion(), RequestID: "r", Method: "GET", Path: "/", Credentials: "ambient"},
	} {
		if _, err := EncodeProxyMetadata(request); err == nil {
			t.Fatal("accepted an invalid context or credentials mode")
		}
	}
}
