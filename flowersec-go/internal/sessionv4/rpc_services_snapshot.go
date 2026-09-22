package sessionv4

import (
	"bytes"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// An asynchronous source holds a frozen local recipe before material Acquire.
// This is preparation backing, separate from the eventual live route/dispatch
// owners. Application closures and store/provider objects remain dependencies;
// every SDK-owned slice, optional definition and string is copied exactly once.
func rpcServicesSnapshotCharge(c *RPCServicesConfig) (resourcev4.Vector, error) {
	if c == nil {
		return resourcev4.Vector{}, nil
	}
	if len(c.Routes.Methods) > 1024 || len(c.Methods)+len(c.StreamMethods) > 128 || len(c.NotificationMethods) > 128 || len(c.ExecutionServices) > 1024 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || len(c.ReferenceDomain) > 128 || len(c.CryptoProfile) > 128 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	n := uint64(unsafe.Sizeof(RPCServicesConfig{})) + uint64(len(c.ReferenceDomain)+len(c.CryptoProfile))
	n += uint64(len(c.Routes.Methods)) * uint64(unsafe.Sizeof(rpcv4.MethodRoutes{}))
	n += uint64(len(c.Methods)) * uint64(unsafe.Sizeof(UnaryRegistration{}))
	n += uint64(len(c.StreamMethods)) * uint64(unsafe.Sizeof(StreamRegistration{}))
	n += uint64(len(c.NotificationMethods)) * uint64(unsafe.Sizeof(NotificationMethod{}))
	n += uint64(len(c.ExecutionServices)) * uint64(unsafe.Sizeof(rpcv4.ServiceBinding{}))
	n += uint64(len(c.Accounts)) * uint64(unsafe.Sizeof(resourcev4.Account{}))
	for _, method := range c.Routes.Methods {
		if len(method.Contracts) == 0 || len(method.Contracts) > 8 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		n += uint64(len(method.Contracts)) * uint64(unsafe.Sizeof([]byte{}))
		for _, wire := range method.Contracts {
			if len(wire) == 0 || len(wire) > 8192 {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
			n += uint64(len(wire))
		}
	}
	for _, method := range c.Methods {
		if len(method.Namespace) > 128 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		n += uint64(len(method.Namespace))
	}
	for _, method := range c.StreamMethods {
		if len(method.Namespace) > 128 || len(method.Kind) > 128 || len(method.Metadata) > 4096 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		n += uint64(len(method.Namespace) + len(method.Kind) + len(method.Metadata))
		if method.EventSource != nil {
			if err := method.EventSource.validate(); err != nil {
				return resourcev4.Vector{}, err
			}
			n += uint64(unsafe.Sizeof(StreamEventSourceDefinition{}))
		}
	}
	for _, service := range c.ExecutionServices {
		a := service.Authority
		if len(a.Tenant) > 128 || len(a.Audience) > 128 || len(a.Namespace) > 128 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		n += uint64(len(a.Tenant) + len(a.Audience) + len(a.Namespace))
	}
	return resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1}, nil
}

// Called only after the complete snapshot charge has been acquired. The caller
// must not mutate its configuration concurrently with this synchronous copy.
func captureRPCServicesConfig(c *RPCServicesConfig) *RPCServicesConfig {
	if c == nil {
		return nil
	}
	out := *c
	out.ReferenceDomain = strings.Clone(c.ReferenceDomain)
	out.CryptoProfile = strings.Clone(c.CryptoProfile)
	out.Accounts = append([]resourcev4.Account(nil), c.Accounts...)
	out.Routes.Methods = append([]rpcv4.MethodRoutes(nil), c.Routes.Methods...)
	for i := range out.Routes.Methods {
		method := &out.Routes.Methods[i]
		method.Contracts = append([][]byte(nil), method.Contracts...)
		for j := range method.Contracts {
			method.Contracts[j] = bytes.Clone(method.Contracts[j])
		}
	}
	out.Methods = append([]UnaryRegistration(nil), c.Methods...)
	for i := range out.Methods {
		out.Methods[i].Namespace = strings.Clone(out.Methods[i].Namespace)
	}
	out.StreamMethods = append([]StreamRegistration(nil), c.StreamMethods...)
	for i := range out.StreamMethods {
		method := &out.StreamMethods[i]
		method.Namespace = strings.Clone(method.Namespace)
		method.Kind = strings.Clone(method.Kind)
		method.Metadata = bytes.Clone(method.Metadata)
		if method.EventSource != nil {
			definition := *method.EventSource
			method.EventSource = &definition
		}
	}
	out.NotificationMethods = append([]NotificationMethod(nil), c.NotificationMethods...)
	out.ExecutionServices = append([]rpcv4.ServiceBinding(nil), c.ExecutionServices...)
	for i := range out.ExecutionServices {
		a := &out.ExecutionServices[i].Authority
		a.Tenant, a.Audience, a.Namespace = strings.Clone(a.Tenant), strings.Clone(a.Audience), strings.Clone(a.Namespace)
	}
	return &out
}
