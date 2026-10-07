package flowersec

import "github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"

// InstallAcceptedRoute admits an independently installed complete direct route
// under this original listener's fixed physical endpoint and TLS policy. The
// finite capacity is declared before the native listener is constructed.
func (s *QUICServer) InstallAcceptedRoute(route []byte) error {
	if s == nil || s.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return s.inner.InstallAcceptedRoute(route)
}

func (s *WebTransportServer) InstallAcceptedRoute(route []byte) error {
	if s == nil || s.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return s.inner.InstallAcceptedRoute(route)
}
