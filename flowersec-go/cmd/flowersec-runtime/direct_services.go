package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// Service contracts and execution histories are original host registrations.
// Neither an incoming method, imported reference nor changed certificate can
// create a second history owner or select another upstream or store.
type directRuntimeMethod struct {
	spec   directMethodSpec
	wire   []byte
	policy protocolv4.ServiceContractPolicy
	shape  [32]byte
	offers []protocolv4.AdmissionOfferBounds
}

func (r *directRuntime) installServices() error {
	if r.config.Services == nil {
		return nil
	}
	spec := r.config.Services
	for _, method := range spec.Methods {
		wire, err := readRuntimeFile(method.ContractFile, 8192)
		if err != nil {
			return err
		}
		codec, err := protocolv4.NewServiceContractCodec(spec.RPC.Routes.ContractNodes)
		if err != nil {
			return err
		}
		contract, err := codec.Decode(wire)
		if err != nil {
			return err
		}
		policy, err := contract.Policy()
		if err != nil {
			contract.Release()
			return err
		}
		shape, err := contract.MethodShapeDigest()
		contract.Release()
		if err != nil {
			return err
		}
		if policy.Namespace != method.Namespace || policy.Type != method.Type || policy.Shape > 2 {
			return errors.New("direct RPC registration requires its exact current unary, streaming or notification contract")
		}
		for _, previous := range r.methods {
			if previous.policy.Namespace == policy.Namespace && previous.policy.Type == policy.Type {
				return errors.New("duplicate original service method")
			}
		}
		if (policy.Shape == 1) != (method.Stream != nil) {
			return errors.New("streaming service requires its exact original OPEN binding")
		}
		if method.Stream != nil {
			if method.Stream.Kind == "" || method.WorkClass != sessionv4.ApplicationResident {
				return errors.New("streaming method requires an explicit kind and resident execution policy")
			}
			for _, raw := range r.config.Streams {
				if raw.Kind == method.Stream.Kind {
					return errors.New("streaming service kind conflicts with a raw stream registration")
				}
			}
		}
		if policy.Checkpoint || policy.RetainedContent {
			return errors.New("method requires a separately installed content/recovery application definition")
		}
		original := directRuntimeMethod{spec: method, wire: wire, policy: policy, shape: shape}
		if policy.Semantics == 1 && policy.ExecutionMode == 0 {
			if len(method.AdmissionOffers) == 0 {
				return errors.New("volatile execution requires explicitly configured original admission windows")
			}
			for _, offer := range method.AdmissionOffers {
				original.offers = append(original.offers, protocolv4.AdmissionOfferBounds{Digest: policy.Digest, NotBeforeMS: offer.LowerMS, NotAfterMS: offer.UpperMS})
			}
		} else if policy.Semantics == 0 && len(method.AdmissionOffers) != 0 {
			return errors.New("observation method cannot install an execution admission window")
		}
		r.methods = append(r.methods, original)
	}
	if len(spec.Histories) == 0 {
		return nil
	}
	config := rpcv4.ServiceRegistryConfig{Root: r.host.root, Owner: r.host.owner, Accounts: r.host.accounts, Entries: uint32(len(spec.Histories)), RuntimeBytes: 65536}
	cost, err := rpcv4.ServiceRegistryCharge(config)
	if err != nil {
		return err
	}
	ref, owner, err := r.host.reserve(cost)
	if err != nil {
		return err
	}
	config.Owner = owner
	r.serviceRegistry, err = rpcv4.NewServiceRegistry(config, ref)
	ref.Release()
	if err != nil {
		return err
	}
	for _, history := range spec.Histories {
		if history.Durable != nil {
			binding, err := r.installDurableHistory(history)
			if err != nil {
				return err
			}
			r.executionBindings = append(r.executionBindings, binding)
			if err = r.serviceRegistry.Bind(binding); err != nil {
				return err
			}
			continue
		}
		config := rpcv4.VolatileExecutionConfig{Root: r.host.root, Owner: r.host.owner, Accounts: r.host.accounts, Clock: r.host.clock, Service: history.Service, CallerAuthorities: history.CallerAuthorities, Records: history.Records, Active: history.Active, TaskCharge: r.executor.TaskCharge(), RuntimeBytes: history.RuntimeBytes, WorkRuntimeBytes: history.WorkRuntimeBytes, ResultRuntimeBytes: history.ResultRuntimeBytes}
		cost, err := rpcv4.VolatileExecutionsCharge(config)
		if err != nil {
			return err
		}
		ref, owner, err := r.host.reserve(cost)
		if err != nil {
			return err
		}
		config.Owner = owner
		original, err := rpcv4.NewVolatileExecutions(config, ref)
		ref.Release()
		if err != nil {
			return err
		}
		binding := rpcv4.ServiceBinding{Authority: rpcv4.ServiceAuthority(history.Service), History: original}
		r.executionBindings = append(r.executionBindings, binding)
		if err = r.serviceRegistry.Bind(binding); err != nil {
			return err
		}
	}
	return nil
}

func (r *directRuntime) servicePlanGeometry() ([]sessionv4.ContractQueryMethod, []string) {
	methods := make([]sessionv4.ContractQueryMethod, 0, len(r.methods))
	for _, method := range r.methods {
		methods = append(methods, sessionv4.ContractQueryMethod{Namespace: method.policy.Namespace, Type: method.policy.Type})
	}
	namespaces := make([]string, 0, len(r.executionBindings))
	for _, binding := range r.executionBindings {
		namespaces = append(namespaces, binding.Authority.Namespace)
	}
	return methods, namespaces
}
func (r *directRuntime) authorizeServiceLease(lease *fs.ApplicationLease) error {
	for _, method := range r.methods {
		p := method.policy
		var err error
		if p.Shape == 2 {
			err = lease.SetNotificationAccess(p.Namespace, p.Type, true)
		} else {
			err = lease.SetServiceAccess(p.Namespace, p.Type, true)
		}
		if err != nil {
			return err
		}
		if err = lease.SetContractQueryAccess(sessionv4.ContractQueryMethod{Namespace: p.Namespace, Type: p.Type}, rpcv4.QueryTargetAllowed); err != nil {
			return err
		}
	}
	for _, binding := range r.executionBindings {
		if err := lease.SetExecutionHistoryAccess(binding.Authority.Namespace, true, true); err != nil {
			return err
		}
	}
	return nil
}
func (r *directRuntime) serviceConfig(position *directRuntimeInput, material *directRuntimeMaterial, native bool, owner resourcev4.OwnerKey) (*fs.RPCServicesConfig, error) {
	if r.config.Services == nil {
		return nil, nil
	}
	profile := material.session.Contract.Limits().ApplicationProfile
	if profile != "services" && profile != "execution" {
		return nil, errors.New("RPC aggregate requires its signed service or execution profile")
	}
	config := r.config.Services.RPC
	config.Root = r.host.root
	config.Owner = owner
	config.Accounts = []resourcev4.Account{r.host.accounts[0], position.scope}
	config.Clock = r.host.clock
	config.Session = material.session.Contract
	config.CryptoProfile = material.session.Profile
	config.Native = native
	config.MixedCarrier = r.config.Core.MixedCarrier
	config.Bootstrap = r.config.Core.Streams
	config.MaxDataPayloadBytes = r.config.Core.MaxDataPayloadBytes
	config.Routes.Clock = r.host.clock
	config.ShortTaskCharge = r.executor.TaskCharge()
	config.ShortCompletionCharge = r.executor.CompletionFloorCharge()
	if profile == "execution" {
		config.ExecutionRegistry = r.serviceRegistry
		config.ExecutionServices = r.executionBindings
	} else if len(r.executionBindings) != 0 {
		return nil, errors.New("execution histories cannot be silently omitted from a service profile")
	}
	for index, method := range r.methods {
		method := method
		policy := method.policy
		if policy.Semantics == 1 && profile != "execution" {
			return nil, errors.New("execution method lacks the signed execution aggregate")
		}
		if policy.Semantics == 1 {
			matched := false
			for _, binding := range config.ExecutionServices {
				if binding.Authority.Namespace == policy.Namespace && ((policy.ExecutionMode == 0 && binding.History != nil) || (policy.ExecutionMode == 1 && binding.DurableHistory != nil)) {
					matched = true
					break
				}
			}
			if !matched {
				return nil, errors.New("execution method requires its exact independently installed history backend")
			}
		}
		route := rpcv4.MethodRoutes{Contracts: [][]byte{method.wire}, OfferWindowMS: policy.AdmissionWindowMS}
		if policy.Semantics == 0 {
			route.AdvertisedContract = policy.Digest
		} else {
			now, err := r.host.clock.Sample()
			if err != nil {
				return nil, err
			}
			for _, offer := range method.offers {
				if now.LowerMS < offer.NotAfterMS {
					route.InitialOffers = append(route.InitialOffers, offer)
				}
				if now.LowerMS >= offer.NotBeforeMS && now.UpperMS < offer.NotAfterMS {
					route.AdvertisedContract = policy.Digest
				}
			}
		}
		config.Routes.Methods = append(config.Routes.Methods, route)
		if policy.Shape == 1 {
			metadata, err := fs.NewStreamMetadata(method.spec.Stream.Metadata)
			if err != nil {
				return nil, err
			}
			config.StreamMethods = append(config.StreamMethods, fs.NewStreamRegistration(uint32(index), policy.Namespace, policy.Type, policy.Digest, method.spec.Stream.Kind, metadata, func(ctx context.Context, request fs.StreamingRequest, response *fs.StreamingResponse) (uint32, error) {
				if request.ApplicationContext != position {
					return 0, ledgerv4.ErrDenied
				}
				input, _, err := request.Input.Bytes()
				if err != nil {
					return 0, err
				}
				return 0, r.invokeStreamingUpstream(ctx, position, method, input, response)
			}))
		} else if policy.Shape == 2 {
			notification := sessionv4.NotificationMethod{Method: uint32(index), WorkClass: method.spec.WorkClass}
			if policy.Semantics == 1 {
				notification.ExecutionHandler = func(ctx context.Context, request sessionv4.NotificationRequest) error {
					if request.ApplicationContext != position {
						return ledgerv4.ErrDenied
					}
					input, _, err := request.Input.Bytes()
					if err != nil {
						return err
					}
					_, err = r.invokeUpstream(ctx, position, method, input, 0)
					return err
				}
			}
			config.NotificationMethods = append(config.NotificationMethods, notification)
		} else {
			config.Methods = append(config.Methods, fs.NewUnaryRegistration(uint32(index), policy.Namespace, policy.Type, method.spec.WorkClass, func(ctx context.Context, request fs.UnaryRequest, response *fs.UnaryResponse) (uint32, error) {
				if request.ApplicationContext != position {
					return 0, ledgerv4.ErrDenied
				}
				input, _, err := request.Input.Bytes()
				if err != nil {
					return 0, err
				}
				output, err := r.invokeUpstream(ctx, position, method, input, policy.MaxResponseBytes)
				if err != nil {
					return 0, err
				}
				defer clear(output)
				_, err = response.Write(output)
				return 0, err
			}))
		}
	}
	return &config, nil
}

// A bounded TCP application exchange preserves byte payloads. The fixed
// upstream returns its response after request FIN; the original callback owns
// the connection and cancellation tail until both have exited.
func (r *directRuntime) invokeUpstream(ctx context.Context, position *directRuntimeInput, method directRuntimeMethod, input []byte, maximum uint32) ([]byte, error) {
	if uint64(len(input)) > uint64(method.policy.RequestMaxBytes) {
		return nil, resourcev4.ErrCapacity
	}
	cost := resourcev4.Vector{resourcev4.SDKBytes: uint64(maximum) + 65536, resourcev4.ProviderBytes: 131072, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.Timers: 2, resourcev4.Connections: 1, resourcev4.NativeHandles: 1}
	ref, _, err := r.reserveSession(cost, position.scope)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	call, cancel := context.WithTimeout(ctx, time.Duration(method.spec.Upstream.TimeoutMS)*time.Millisecond)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(call, "tcp", method.spec.Upstream.Address)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	canceled := make(chan struct{})
	stop := context.AfterFunc(call, func() { defer close(canceled); _ = connection.Close() })
	defer func() {
		if !stop() {
			<-canceled
		}
	}()
	for len(input) > 0 {
		n, err := connection.Write(input)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
		input = input[n:]
	}
	if err = connection.(*net.TCPConn).CloseWrite(); err != nil {
		return nil, err
	}
	output := make([]byte, int(maximum)+1)
	n, err := io.ReadFull(connection, output)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		clear(output)
		return nil, err
	}
	if n > int(maximum) {
		clear(output)
		return nil, resourcev4.ErrCapacity
	}
	return output[:n], nil
}

func (r *directRuntime) subscribeServices(session *fs.Session, plan *fs.SessionPlan) error {
	if r.config.Services == nil {
		return nil
	}
	var position *directRuntimeInput
	r.mu.Lock()
	for _, original := range r.admissions {
		if original.plan == plan {
			position = original
			break
		}
	}
	r.mu.Unlock()
	if position == nil {
		return resourcev4.ErrOwner
	}
	for _, method := range r.methods {
		method := method
		if method.policy.Shape != 2 || method.policy.Semantics != 0 {
			continue
		}
		subscription, err := session.SubscribeNotification(fs.MethodSelector{Namespace: method.policy.Namespace, Type: method.policy.Type}, fs.NotificationDropNewest, fs.NotificationObserver{
			Decode: func(ctx context.Context, payload []byte) (any, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if uint64(len(payload)) > uint64(method.policy.RequestMaxBytes) {
					return nil, resourcev4.ErrCapacity
				}
				return append([]byte(nil), payload...), nil
			},
			Handle: func(ctx context.Context, value any) error {
				payload, ok := value.([]byte)
				if !ok {
					return resourcev4.ErrConfiguration
				}
				defer clear(payload)
				_, err := r.invokeUpstream(ctx, position, method, payload, 0)
				return err
			},
		})
		if err != nil {
			return err
		}
		position.subscriptions = append(position.subscriptions, subscription)
	}
	return nil
}

// The trusted TCP application emits big-endian uint32 length-prefixed items.
// Each complete item enters the original SDK stream response before reading
// the next frame, preserving the authenticated contract's native backpressure.
func (r *directRuntime) invokeStreamingUpstream(ctx context.Context, position *directRuntimeInput, method directRuntimeMethod, input []byte, response *fs.StreamingResponse) error {
	policy := method.policy
	if uint64(len(input)) > uint64(policy.RequestMaxBytes) {
		return resourcev4.ErrCapacity
	}
	ref, _, err := r.reserveSession(resourcev4.Vector{resourcev4.SDKBytes: uint64(policy.MaxResponseBytes) + 65536, resourcev4.ProviderBytes: 131072, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.Timers: 2, resourcev4.Connections: 1, resourcev4.NativeHandles: 1}, position.scope)
	if err != nil {
		return err
	}
	defer ref.Release()
	call, cancel := context.WithTimeout(ctx, time.Duration(method.spec.Upstream.TimeoutMS)*time.Millisecond)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(call, "tcp", method.spec.Upstream.Address)
	if err != nil {
		return err
	}
	defer connection.Close()
	canceled := make(chan struct{})
	stop := context.AfterFunc(call, func() { defer close(canceled); _ = connection.Close() })
	defer func() {
		if !stop() {
			<-canceled
		}
	}()
	for len(input) > 0 {
		n, err := connection.Write(input)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		input = input[n:]
	}
	if err = connection.(*net.TCPConn).CloseWrite(); err != nil {
		return err
	}
	buffer := make([]byte, policy.MaxResponseBytes)
	defer clear(buffer)
	var count uint32
	var total uint64
	var header [4]byte
	for {
		n, err := io.ReadFull(connection, header[:])
		if errors.Is(err, io.EOF) && n == 0 {
			return nil
		}
		if err != nil {
			return err
		}
		size := binary.BigEndian.Uint32(header[:])
		if size > policy.MaxResponseBytes || count >= policy.MaxItemCount || uint64(size) > policy.MaxStreamPayloadBytes-total {
			return resourcev4.ErrCapacity
		}
		payload := buffer[:size]
		if _, err = io.ReadFull(connection, payload); err != nil {
			return err
		}
		if err = response.SendItemEncoded(call, payload, 0); err != nil {
			return err
		}
		clear(payload)
		count++
		total += uint64(size)
	}
}
