package flowersec_test

import (
	"reflect"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
)

func TestProxyServerPublicSurfaceIsApplicationOnly(t *testing.T) {
	var legacyRegister func(*flowersec.ProxyServer, *flowersec.SessionHandlers) error = (*flowersec.ProxyServer).Register
	var streamRegister func(*flowersec.ProxyServer, flowersec.StreamHandlerRegistrar) error = (*flowersec.ProxyServer).RegisterStreamHandlers
	_ = legacyRegister
	_ = streamRegister

	allowedOptions := map[string]struct{}{
		"Upstream": {}, "UpstreamOrigin": {}, "AllowedUpstreamHosts": {}, "AllowedOrigins": {},
		"MaxConcurrentStreams": {}, "MaxJSONFrameBytes": {}, "MaxChunkBytes": {},
		"MaxBodyBytes": {}, "MaxWebSocketFrameBytes": {}, "DefaultHTTPRequestTimeout": {},
		"MaxHTTPRequestTimeout": {}, "ExtraRequestHeaders": {}, "ExtraResponseHeaders": {},
		"BlockedResponseHeaders": {}, "ExtraWebSocketHeaders": {}, "ForbiddenCookieNames": {},
		"ForbiddenCookieNamePrefixes": {}, "OnError": {},
	}
	options := reflect.TypeOf(flowersec.ProxyServerOptions{})
	for index := 0; index < options.NumField(); index++ {
		field := options.Field(index)
		if _, ok := allowedOptions[field.Name]; !ok {
			t.Fatalf("ProxyServerOptions exposes implementation field %s", field.Name)
		}
	}
	server := reflect.TypeOf(flowersec.ProxyServer{})
	for index := 0; index < server.NumField(); index++ {
		if field := server.Field(index); field.PkgPath == "" {
			t.Fatalf("ProxyServer exposes implementation field %s", field.Name)
		}
	}
	for _, symbol := range []any{
		flowersec.NewProxyServer,
		(*flowersec.ProxyServer).Register,
		(*flowersec.ProxyServer).RegisterStreamHandlers,
		(*flowersec.ProxyServer).Close,
		flowersec.ErrInvalidProxyServer,
	} {
		if symbol == nil {
			t.Fatal("proxy server symbol is nil")
		}
	}
}
