package flowersec

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
)

type controllerWebSocketTestServer struct {
	URL       string
	endpoint  *WebSocketHTTPServer
	listener  net.Listener
	serveDone chan error
}

func startControllerWebSocketTestServer(handler http.Handler, serverTLS *tls.Config) (*controllerWebSocketTestServer, error) {
	endpoint, err := NewWebSocketHTTPServer(WebSocketHTTPServerOptions{Handler: handler, TLSConfig: serverTLS})
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = endpoint.Close()
		return nil, err
	}
	if _, err := x509.ParseCertificate(serverTLS.Certificates[0].Certificate[0]); err != nil {
		_ = listener.Close()
		_ = endpoint.Close()
		return nil, err
	}
	serveDone := make(chan error, 1)
	server := &controllerWebSocketTestServer{URL: "https://" + listener.Addr().String(), endpoint: endpoint, listener: listener, serveDone: serveDone}
	go func() { serveDone <- endpoint.Serve(listener) }()
	return server, nil
}

func (server *controllerWebSocketTestServer) Close() {
	if server == nil || server.endpoint == nil {
		return
	}
	_ = server.endpoint.Close()
	_ = server.listener.Close()
	if server.serveDone != nil {
		<-server.serveDone
		server.serveDone = nil
	}
}
