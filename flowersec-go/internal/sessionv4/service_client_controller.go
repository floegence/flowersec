package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// BindMethods borrows this Controller's existing accepting current. The
// service retains the authenticated routing identity and immutable local
// contract snapshots, while every call uses the selected Session's resources.
// It never starts the Controller, acquires material or prepares a connection.
func (c *ConnectionController) BindMethods(ctx context.Context, definition ServiceDefinition, options UnaryServiceBindOptions) (*UnaryServiceClient, error) {
	if c == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := c.CaptureSession()
	if err != nil {
		return nil, err
	}
	r, routing, err := s.controllerRPCIdentity()
	if err != nil {
		return nil, err
	}
	return r.bindMethodsSource(ctx, definition, options, c, s, routing)
}

func (c *ConnectionController) BindUnaryMethods(ctx context.Context, definition UnaryServiceDefinition, options UnaryServiceBindOptions) (*UnaryServiceClient, error) {
	for _, method := range definition.Methods {
		if method.Shape != 0 {
			return nil, rpcv4.ErrMethod
		}
	}
	return c.BindMethods(ctx, definition, options)
}

// Callers hold an original visit or call position while outside the binding
// gate. That position keeps source, metadata and all local snapshots alive.
func (c *UnaryServiceClient) captureControllerSource(controller *ConnectionController) (*EnvironmentSession, *RPCServices, error) {
	s, err := controller.CaptureSession()
	if err != nil {
		return nil, nil, err
	}
	r, err := c.checkControllerSource(s)
	return s, r, err
}

func (c *UnaryServiceClient) checkControllerSource(s *EnvironmentSession) (*RPCServices, error) {
	return c.checkControllerSourceIdentity(s, true)
}

func (c *UnaryServiceClient) checkControllerSourceIdentity(s *EnvironmentSession, seal bool) (*RPCServices, error) {
	r, identity, err := s.controllerRPCIdentity()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.cleaned {
		return nil, cryptov4.ErrClosed
	}
	r.mu.Lock()
	root, clock, closed := r.root, r.clock, r.closed || r.retired
	r.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrNotReady
	}
	if identity != c.source.routing || root != c.root || clock != c.clock {
		// A later return to the old target does not reopen this binding.
		if seal {
			c.closeLocked()
		}
		return nil, ErrApplicationAuthorization
	}
	if err := c.metadata.Check(); err != nil {
		return nil, err
	}
	return r, nil
}

func (c *UnaryServiceClient) prepareUnaryAt(slot *serviceClientCall, ctx context.Context, services *RPCServices, method UnaryMethodDefinition, input []byte, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	c.mu.Lock()
	controller, session, routing := c.source.controller, slot.session, c.source.routing
	if slot.initializer {
		controller = nil
	}
	if slot.workload == nil {
		method.workload = nil
	}
	c.mu.Unlock()
	if controller != nil {
		return controller.prepareUnaryOn(ctx, session, routing, method, input, options)
	}
	return services.PrepareMethod(ctx, method, input, options)
}

func (c *UnaryServiceClient) preparationCore(slot *serviceClientCall, services *RPCServices) (*SessionCore, error) {
	c.mu.Lock()
	session := slot.session
	c.mu.Unlock()
	if session != nil {
		return session.Core()
	}
	return services.bindingCore()
}

// withSourceInstallation runs only a finite SDK metadata transfer. The current
// switch and this installation share the original Controller publication gate.
func (c *UnaryServiceClient) withSourceInstallation(session *EnvironmentSession, action func() error) error {
	controller := c.source.controller
	if controller == nil {
		return action()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed {
		return cryptov4.ErrClosed
	}
	if controller.blocked || controller.current != session {
		return cryptov4.ErrNotReady
	}
	return action()
}
