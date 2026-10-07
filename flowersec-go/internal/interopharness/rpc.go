package interopharness

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type RPCMethod struct {
	Type            uint32
	MaxEncodedBytes uint32
	Notify          bool
	Handle          func(context.Context, []byte) ([]byte, error)
}
type RPCDefinition struct {
	SchemaDigest      [32]byte
	Definition        fs.ServiceDefinition
	Contracts         [][]byte
	Policies          []fs.ServiceContractPolicy
	NotificationTypes []uint32
}

// ConfigureRPC freezes current service contracts and handlers before admission.
// User payloads remain bounded codec bytes; numeric IDs are qualified by their
// service namespace and actual contract digest, rather than a legacy router.
func ConfigureRPC(r *Runtime, role uint8, namespace string, methods []RPCMethod) *RPCDefinition {
	h := r.Authority
	definition := &RPCDefinition{SchemaDigest: sha256.Sum256([]byte("flowersec/engineering/rpc-bytes/1\x00" + namespace)), Definition: fs.ServiceDefinition{Namespace: namespace}}
	config := fs.RPCServicesConfig{Native: h.Admission[role].Core.Native, NotifyReceivePending: 16, NotifyPublishPending: 16, NotificationWaitMS: 30000, NotificationCleanupMS: 5000, CompletionGraceMS: 5000,
		ShortRequestBytes: 4096, ShortResponseBytes: 4096, ShortTaskCharge: r.Executor.TaskCharge(), ShortCompletionCharge: r.Executor.CompletionFloorCharge(), CryptoProfile: h.Admission[role].Initial.Profile,
		Bootstrap: h.Admission[role].Core.Streams, MaxDataPayloadBytes: h.Admission[role].Core.MaxDataPayloadBytes, Root: h.Root, Owner: h.Owner(), Accounts: []fs.ResourceAccount{h.Scope[role].Tenant, h.Scope[role].Session}, Session: h.Admission[role].Core.Session.Contract, Clock: h.Clock,
		Query: rpcv4.QueryBinding{Type: 7, Contract: [32]byte{9}}, Routes: rpcv4.ContractRoutesConfig{ContractNodes: 256, RuntimeBytes: 16384, Clock: h.Clock}, Slots: 8, ResidentSlots: 4, MaxCaptureBytes: 1 << 20, RuntimeBytes: 65536, InputRuntimeBytes: 65536, HashRuntimeBytes: 4096, InvocationRuntimeBytes: 65536}
	for index, method := range methods {
		maximum := method.MaxEncodedBytes
		if maximum == 0 {
			maximum = 4096
		}
		if maximum > 1<<20 {
			r.Reporter.Fatal("RPC codec exceeds its original declared envelope")
		}
		if method.Type == 0 || method.Handle == nil && !method.Notify {
			r.Reporter.Fatal("invalid immutable RPC method")
		}
		wire, policy := sessionv4.EngineeringServiceContractWithLimit(r.Reporter, namespace, method.Type, method.Notify, maximum)
		if maximum > config.ShortRequestBytes {
			config.ShortRequestBytes = maximum
		}
		if maximum > config.ShortResponseBytes {
			config.ShortResponseBytes = maximum
		}
		definition.Contracts = append(definition.Contracts, wire)
		definition.Policies = append(definition.Policies, policy)
		config.Routes.Methods = append(config.Routes.Methods, rpcv4.MethodRoutes{
			Contracts:          [][]byte{wire},
			AdvertisedContract: policy.Digest,
		})
		local := fs.UnaryMethod{Contract: policy.Digest, WorkClass: fs.WorkShort, Codec: fs.UnaryCodec{MaxEncodedBytes: maximum, Encode: func(ctx context.Context, input, _ []byte) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if uint64(len(input)) > uint64(maximum) {
				return nil, errors.New("RPC input exceeds declared codec bound")
			}
			return input, nil
		}}, Decode: func(_ context.Context, payload []byte) (any, error) { return append([]byte(nil), payload...), nil }}
		descriptor := fs.ServiceMethod{Type: method.Type, Method: local}
		if method.Notify {
			descriptor.Shape = fs.CallNotify
			descriptor.Method.Decode = nil
			config.NotificationMethods = append(config.NotificationMethods, sessionv4.NotificationMethod{Method: uint32(index), WorkClass: sessionv4.ApplicationShort})
			definition.NotificationTypes = append(definition.NotificationTypes, method.Type)
		} else {
			descriptor.Method.DefaultResponseLimitBytes = maximum
			config.Methods = append(config.Methods, fs.NewUnaryRegistration(uint32(index), namespace, method.Type, fs.WorkShort, func(ctx context.Context, request fs.UnaryRequest, response *fs.UnaryResponse) (uint32, error) {
				input, _, err := request.Input.Bytes()
				if err != nil {
					return 0, err
				}
				output, err := method.Handle(ctx, input)
				if err != nil {
					return 0, err
				}
				_, err = response.Write(output)
				return 0, err
			}))
		}
		definition.Definition.Methods = append(definition.Definition.Methods, descriptor)
		r.QueryMethods[role] = append(r.QueryMethods[role], sessionv4.ContractQueryMethod{Namespace: namespace, Type: method.Type})
	}
	r.RPCDefinitions[role] = definition
	r.Services[role] = &config
	r.AuthorizeServices[role] = func(lease *fs.ApplicationLease) error {
		for _, method := range methods {
			var err error
			if method.Notify {
				err = lease.SetNotificationAccess(namespace, method.Type, true)
			} else {
				err = lease.SetServiceAccess(namespace, method.Type, true)
			}
			if err != nil {
				return err
			}
			if err = lease.SetContractQueryAccess(sessionv4.ContractQueryMethod{Namespace: namespace, Type: method.Type}, rpcv4.QueryTargetAllowed); err != nil {
				return err
			}
		}
		return nil
	}
	return definition
}

func (d *RPCDefinition) Bind(ctx context.Context, session *fs.Session) (*fs.ServiceClient, error) {
	return session.BindMethods(ctx, d.Definition, fs.ServiceBindOptions{ContractSource: fs.ServiceContractsStatic})
}

// ConfigurePeerRPC keeps the shared engineering service set stable for every
// peer. The server label is bounded application output, not an admission claim.
func ConfigurePeerRPC(r *Runtime, role uint8, server string) *RPCDefinition {
	response, err := json.Marshal(map[string]string{"server": server})
	if err != nil || len(response) > 4096 {
		r.Reporter.Fatal("peer RPC response exceeds its codec bound")
	}
	echo := func(_ context.Context, input []byte) ([]byte, error) {
		var value map[string]any
		if err := json.Unmarshal(input, &value); err != nil {
			return nil, err
		}
		return append([]byte(nil), input...), nil
	}
	return ConfigureRPC(r, role, "flowersec.parity", []RPCMethod{{Type: 7001, Handle: func(_ context.Context, input []byte) ([]byte, error) {
		var value map[string]any
		if err := json.Unmarshal(input, &value); err != nil {
			return nil, err
		}
		return append([]byte(nil), response...), nil
	}}, {Type: 7002, Notify: true}, {Type: 7003, Handle: echo}, {Type: 7005, Handle: echo}})
}
