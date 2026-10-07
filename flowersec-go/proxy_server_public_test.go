package flowersec

import (
	"context"
	"reflect"
	"testing"
)

func TestProxyServerPublicSurfaceIsApplicationOnly(t *testing.T) {
	var streamRegister func(*ProxyServer, *StreamHandlerPlanConfig, func(context.Context, any, []byte) error) error = (*ProxyServer).RegisterStreamHandlers
	_ = streamRegister

	allowedOptions := map[string]struct{}{
		"Credentials": {}, "Upstream": {}, "UpstreamOrigin": {}, "AllowedUpstreamHosts": {}, "AllowedUpstreamAddresses": {}, "AllowedOrigins": {},
		"MaxConcurrentStreams": {}, "MaxConcurrentHTTPStreams": {}, "MaxConcurrentEventStreams": {}, "EventStreamIdleTimeout": {}, "MaxMetadataBytes": {}, "MaxChunkBytes": {},
		"MaxBodyBytes": {}, "MaxWebSocketFrameBytes": {}, "DefaultHTTPRequestTimeout": {},
		"MaxHTTPRequestTimeout": {}, "ExtraRequestHeaders": {}, "ExtraResponseHeaders": {},
		"BlockedResponseHeaders": {}, "ExtraWebSocketHeaders": {}, "ForbiddenCookieNames": {},
		"ForbiddenCookieNamePrefixes": {}, "OnError": {},
	}
	options := reflect.TypeOf(ProxyServerOptions{})
	for index := 0; index < options.NumField(); index++ {
		field := options.Field(index)
		if _, ok := allowedOptions[field.Name]; !ok {
			t.Fatalf("ProxyServerOptions exposes implementation field %s", field.Name)
		}
	}
	server := reflect.TypeOf(ProxyServer{})
	for index := 0; index < server.NumField(); index++ {
		if field := server.Field(index); field.PkgPath == "" {
			t.Fatalf("ProxyServer exposes implementation field %s", field.Name)
		}
	}
	for _, symbol := range []any{
		NewProxyServer,
		(*ProxyServer).RegisterStreamHandlers,
		(*ProxyServer).Close,
		ErrInvalidProxyServer,
	} {
		if symbol == nil {
			t.Fatal("proxy server symbol is nil")
		}
	}
}
