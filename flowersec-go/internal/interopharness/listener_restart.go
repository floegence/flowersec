package interopharness

import (
	"context"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"net"
)

// StopTransport joins the actual listener and acceptance callbacks while the
// independently installed authority, namespace service and consumer stores stay
// owned by their original reporters. Existing Sessions observe physical failure.
func (s *Server) StopTransport(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("original native listener and cleanup context are required")
	}
	if s.positionOnly || s.nextAccepted == nil {
		return errors.New("listener restart requires independently owned acceptance positions")
	}
	// Accepted native connections have independent owners after handoff.
	// A host outage must interrupt them as well as close the listening socket.
	var err error
	if s.Carrier == "raw-quic" {
		// Closing a QUIC connection sends an application close, which correctly
		// grants no retry. Cut the actual socket to reproduce a network outage.
		err = s.quic.InterruptTransport()
	} else {
		err = s.InterruptConnections()
	}
	switch s.Carrier {
	case "websocket":
		s.webSocket.Close()
	case "raw-quic":
		err = errors.Join(err, s.quic.Close())
	case "webtransport":
		err = errors.Join(err, s.webTransport.Close())
	default:
		return errors.New("restart requires an original network listener")
	}
	if s.transportJoin != nil {
		err = errors.Join(err, s.transportJoin(ctx))
	}
	switch s.Carrier {
	case "websocket":
		err = errors.Join(err, s.webSocket.WaitCleanup(ctx))
	case "raw-quic":
		err = errors.Join(err, s.quic.WaitCleanup(ctx))
	case "webtransport":
		err = errors.Join(err, s.webTransport.WaitCleanup(ctx))
	}
	return err
}

// RestartTransport creates a new original native listener at the same signed
// deployment address. It does not move a Session, stream or operation. All
// complete accepted routes are independently reinstalled before publication.
func (s *Server) RestartTransport(ctx context.Context) (result *Server, resultErr error) {
	if err := s.StopTransport(ctx); err != nil {
		return nil, err
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if err := context.Cause(s.context); err != nil {
		return nil, err
	}
	reporter, err := s.Runtime.Reporter.ForkAuthority()
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, reporter.Close())
		}
	}()
	result, resultErr = construct(reporter, func() *Server {
		replacement, err := s.createRestartedTransport(reporter)
		if err != nil {
			reporter.Fatal(err)
		}
		return replacement
	})
	return result, resultErr
}
func (s *Server) createRestartedTransport(reporter *Reporter) (result *Server, resultErr error) {
	var err error
	h := *s.Runtime.Authority
	h.Reserve = func(v resourcev4.Vector, accounts ...resourcev4.Account) resourcev4.Reference {
		reference, err := h.Root.Reserve(h.Owner(), v, accounts...)
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Cleanup(reference.Release)
		return reference
	}
	runtime := &Runtime{Reporter: reporter, Authority: &h, Environment: s.Runtime.Environment, Executor: s.Runtime.Executor, Materials: s.Runtime.Materials}
	result = &Server{Runtime: runtime, Carrier: s.Carrier, Origin: s.Origin, TrustPEM: s.TrustPEM, Address: s.Address, Namespace: s.Namespace, certificate: s.certificate, roots: s.roots, context: s.context, results: make(chan SessionResult, 2), connections: s.connections, acceptedRouteCapacity: s.acceptedRouteCapacity, nextAccepted: s.nextAccepted, onTransportError: s.onTransportError}
	if s.Carrier == "websocket" {
		result.listener, err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(s.Address))
		if err != nil {
			return nil, err
		}
		listener := result.listener
		reporter.Cleanup(func() {
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				reporter.Error(err)
			}
		})
	}
	s.routeMu.Lock()
	for _, route := range s.acceptedRoutes {
		result.acceptedRoutes = append(result.acceptedRoutes, append([]byte(nil), route...))
	}
	s.routeMu.Unlock()
	if err = result.startTransport(reporter); err != nil {
		return nil, err
	}
	return result, nil
}
