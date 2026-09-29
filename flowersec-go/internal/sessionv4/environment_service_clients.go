package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"

// Unpublished Bind owns the same finite service and method positions as a
// delivered client. A blocked original authorization/clock adapter cannot let
// concurrent construction exceed the Environment's aggregate index.
func (e *Environment) reserveServiceBinding(methods uint16) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired || !e.services {
		return -1, cryptov4.ErrClosed
	}
	if uint32(e.boundMethods)+uint32(methods) > uint32(e.maxBoundMethods) {
		return -1, cryptov4.ErrCapacity
	}
	for j, client := range e.serviceClients {
		if client == nil && !e.serviceClientBinding[j] {
			e.serviceClientBinding[j] = true
			e.serviceClientActive++
			e.boundMethods += methods
			return j, nil
		}
	}
	return -1, cryptov4.ErrCapacity
}

func (e *Environment) releaseServiceBinding(index int, methods uint16) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.serviceClientBinding[index] {
		e.serviceClientBinding[index] = false
		e.serviceClientActive--
		e.boundMethods -= methods
		e.completeLocked()
		e.signalMaterials()
	}
}

// Bindings use the existing Environment coordinator. Their finite index and
// actual metadata remain occupied through Close and all original call tails.
func (e *Environment) advanceServiceClients() bool {
	for j := range e.serviceClients {
		e.mu.Lock()
		if e.serviceClientActive == 0 {
			e.mu.Unlock()
			return false
		}
		client := e.serviceClients[j]
		e.mu.Unlock()
		if client != nil && client.advance() {
			e.mu.Lock()
			if e.serviceClients[j] == client {
				e.serviceClients[j] = nil
				e.serviceClientActive--
				e.boundMethods -= client.methodCount
				e.completeLocked()
			}
			e.mu.Unlock()
		}
	}
	return true
}
