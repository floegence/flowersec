package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// Registration validation precedes application authorization and READY. A
// type advertised for Resume must have the actual original method, kind,
// history and independent key owners; a runtime refusal cannot stand in for
// the service's advertised checkpoint capability.
func validateResumeRegistrations(raw *StreamHandlerPlan, network *rpcv4.Network, config ServiceDispatchConfig) error {
	if raw == nil {
		for _, m := range config.Methods {
			if m.Resume {
				return cryptov4.ErrConfiguration
			}
		}
		return nil
	}
	raw.mu.Lock()
	defer raw.mu.Unlock()
	if raw.closed {
		return cryptov4.ErrClosed
	}
	for _, registration := range raw.registrations {
		binding := registration.config.Resume
		if binding == nil {
			continue
		}
		if _, _, err := network.ResumeBinding(binding.Method, binding.Namespace, binding.Type, binding.ContractDigest); err != nil {
			return err
		}
		methodFound := false
		for _, method := range config.Methods {
			if method.Method == binding.Method && method.Namespace == binding.Namespace && method.Type == binding.Type && method.Resume {
				methodFound = true
				break
			}
		}
		if !methodFound {
			return rpcv4.ErrMethod
		}
		serviceFound := false
		for _, service := range config.ExecutionServices {
			if service.Authority.Namespace != binding.Namespace {
				continue
			}
			if service.DurableHistory == nil || service.Recovery == nil {
				return rpcv4.ErrExecutionUnsupported
			}
			serviceFound = true
		}
		if !serviceFound {
			return rpcv4.ErrExecutionUnsupported
		}
	}
	for _, method := range config.Methods {
		if !method.Resume {
			continue
		}
		found := false
		for _, registration := range raw.registrations {
			b := registration.config.Resume
			if b != nil && b.Method == method.Method && b.Namespace == method.Namespace && b.Type == method.Type {
				found = true
				break
			}
		}
		if !found {
			return rpcv4.ErrMethod
		}
	}
	return nil
}
