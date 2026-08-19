package flowersec_test

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v3"
)

type websocketTestServer struct {
	URL       string
	endpoint  *flowersec.WebSocketHTTPServer
	listener  net.Listener
	cert      *x509.Certificate
	serveDone chan error
}

func newWebSocketTestServer(t *testing.T, handler http.Handler, serverTLS *tls.Config) *websocketTestServer {
	t.Helper()
	server, err := startWebSocketTestServer(handler, serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server
}

func startWebSocketTestServer(handler http.Handler, serverTLS *tls.Config) (*websocketTestServer, error) {
	endpoint, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{Handler: handler, TLSConfig: serverTLS})
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	certificate, err := x509.ParseCertificate(serverTLS.Certificates[0].Certificate[0])
	if err != nil {
		_ = listener.Close()
		_ = endpoint.Close()
		return nil, err
	}
	server := &websocketTestServer{URL: "https://" + listener.Addr().String(), endpoint: endpoint, listener: listener, cert: certificate}
	serveDone := make(chan error, 1)
	go func() { serveDone <- endpoint.Serve(listener) }()
	server.serveDone = serveDone
	return server, nil
}

func (server *websocketTestServer) Close() {
	if server != nil && server.endpoint != nil {
		_ = server.endpoint.Close()
		_ = server.listener.Close()
		if server.serveDone != nil {
			<-server.serveDone
			server.serveDone = nil
		}
	}
}

func (server *websocketTestServer) Certificate() *x509.Certificate {
	if server == nil {
		return nil
	}
	return server.cert
}
