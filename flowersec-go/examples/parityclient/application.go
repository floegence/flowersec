package parityclient

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
)

const parityNamespace = "flowersec.parity"

func (c *Client) installApplication(config Configuration) error {
	codec, err := fs.NewSignedMapCodec("Artifact", 65536, 4096)
	if err != nil {
		return err
	}
	artifact, err := codec.VerifyCredential(config.Material.Artifact, c.trust)
	if err != nil {
		return err
	}
	defer artifact.Release()
	parameters, err := artifact.SessionParameters()
	if err != nil {
		return err
	}
	limits := parameters.Contract.Limits()
	// This cookbook has a fixed service workload and one reliable WSS carrier.
	// It cannot silently downgrade another profile or resize itself from a peer.
	if limits.ApplicationProfile != "services" || limits.MaxStreams < 11 || limits.MaxStreams > 138 ||
		limits.MaxFrame < 4096 || limits.MaxFrame > 65536 || limits.RPCMaxGeneralOutstanding == 0 || limits.RPCMaxGeneralOutstanding > 32 {
		return errors.New("invitation does not fit the declared parity WSS service envelope")
	}
	if err = artifact.CheckDirectListenerCandidate(0); err != nil {
		return err
	}
	route, _, err := artifact.CopyCandidateRoute(0, make([]byte, 16384))
	if err != nil {
		return err
	}
	address, err := directWSSAddress(route)
	if err != nil {
		return err
	}
	features, err := artifact.FeatureEnvelope(0, fs.FeatureEnvelopePolicy{})
	if err != nil {
		return err
	}
	// The supported WSS profile offers no optional features. The SDK rejects
	// any signed required feature outside this explicitly declared capability.
	facts, err := c.lease.PoolSpendFacts(0)
	if err != nil {
		return err
	}
	fields, err := facts.Fields()
	if err != nil {
		return err
	}
	if fields.Profile != parameters.Profile {
		return errors.New("signed identity and artifact profiles differ")
	}
	if err = c.installFactory(config, route, address); err != nil {
		return err
	}
	executorConfig := fs.ApplicationExecutorConfig{QueryOwners: 2, Running: 16, ResidentRunning: 8,
		CompletionRunning: 2, CompletionReserved: 8, RuntimeBytes: 16384, RuntimeBytesPerTask: 131072}
	ref, err := c.reserve(fs.ApplicationExecutorCharge(executorConfig))
	if err != nil {
		return err
	}
	c.executor, err = fs.NewApplicationExecutor(executorConfig, ref)
	ref.Release()
	if err != nil {
		return err
	}
	environmentConfig := fs.EnvironmentConfig{Services: true, Positions: 1, Materials: 1,
		MaterialCreateMS: 10000, Clock: c.clock, Verification: c.verification, RuntimeBytes: 131072}
	ref, err = c.reserve(fs.EnvironmentCharge(environmentConfig))
	if err != nil {
		return err
	}
	c.environment, err = fs.NewTransportEnvironment(fs.TransportEnvironmentOptions{
		Config: environmentConfig, Reservation: ref, Dependencies: c.dependencies})
	ref.Release()
	if err != nil {
		return err
	}
	core := c.core(parameters)
	rpc, queries, err := c.rpcConfiguration(parameters, core.Streams)
	if err != nil {
		return err
	}
	expected := fs.ApplicationBinding{
		Artifact: fields.Artifact, ClientIdentity: fields.ClientIdentity, ServerIdentity: fields.ServerIdentity,
		Route: fields.Winner.RouteDigest, Attempt: fields.Attempt, Candidate: fields.Winner.CandidateID,
		CandidateIndex: 0, Role: fs.ClientToServer, Source: "preauthorized_pool", ApplicationProfile: "services",
	}
	planConfig := fs.SessionPlanConfig{RuntimeBytes: 16384, Services: true,
		ContractQueries: true, ContractQueryMethods: queries,
		AuthorizeApplication: func(ctx context.Context, request fs.AuthenticatedRequestContext) (fs.AuthorizeApplicationResult, error) {
			if err := ctx.Err(); err != nil {
				return fs.AuthorizeApplicationResult{}, err
			}
			if request.Binding() != expected {
				return fs.AuthorizeApplicationResult{}, errors.New("authenticated application target does not match the installed invitation")
			}
			lease, err := request.ReserveLease(expected, "parity-client", func(context.Context) error { return nil })
			if err != nil {
				return fs.AuthorizeApplicationResult{}, err
			}
			for _, method := range c.definition.Methods {
				if method.Shape == fs.CallNotify {
					err = lease.SetNotificationAccess(parityNamespace, method.Type, true)
				} else {
					err = lease.SetServiceAccess(parityNamespace, method.Type, true)
				}
				if err != nil {
					return fs.AuthorizeApplicationResult{Lease: lease}, err
				}
				if err = lease.SetContractQueryAccess(fs.ContractQueryMethod{Namespace: parityNamespace, Type: method.Type}, fs.QueryTargetAllowed); err != nil {
					return fs.AuthorizeApplicationResult{Lease: lease}, err
				}
			}
			return fs.AuthorizeApplicationResult{Lease: lease}, nil
		},
	}
	c.plan, err = (fs.SessionPlanFactory{Root: c.root, Executor: c.executor, Dependencies: c.dependencies}).Create(
		planConfig, c.nextOwner(), c.scope.Tenant, c.scope.Session)
	if err != nil {
		return err
	}
	deadline, err := fs.NewAge(c.clock, 10000, fields.ActivationEnd)
	if err != nil {
		return err
	}
	admission := fs.SessionAdmissionConfig{Core: core, Application: c.plan, RPC: rpc, Features: features,
		Initial: fs.InitialConfig{Role: fs.ClientToServer, Profile: parameters.Profile, ActivationSourceProfile: "preauthorized_pool",
			Limits: fs.InitialLimits{MaxFrame: int(limits.MaxFrame), Nodes: 4096}, Deadline: deadline},
		RuntimeBytes: 32768, InitialRuntimeBytes: 32768}
	c.options.Preparation = fs.SourceConnectConfig{
		Generation: config.Material.Generation, Identity: c.identity, MaterialRuntimeBytes: 8192,
		Requirements: fs.MaterialRequirements{ApplicationProfile: "services", RPCMaxGeneralOutstanding: limits.RPCMaxGeneralOutstanding,
			Connection: fs.RequiredGuarantees{LocalConsumerTls13Verification: true}},
		Carrier: c.factory, Hello: fs.InitialHello{Index: 0, Attempt: fields.Attempt, BindingModes: 2,
			Policy: fs.HelloPolicy{BindingMode: 1}},
		Limits: fs.EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, RuntimeBytes: 65536,
			Hello: fs.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}},
		Admission: admission, Root: c.root, Owner: c.nextOwner(), Environment: c.dependencies,
		Preauth: c.dependencies, Dependencies: c.dependencies, Scope: c.scope,
		RuntimeBytes: 8192, CarrierRuntimeBytes: 8192, ParallelCandidates: 1, AddressAttempts: 1,
		AttemptBudget: fs.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128},
	}
	return nil
}

func directWSSAddress(route []byte) (netip.AddrPort, error) {
	decoder, err := fs.NewProtocolDecoder(16384, 1024)
	if err != nil {
		return netip.AddrPort{}, err
	}
	document, err := decoder.DecodeMap(route, "Route", fs.DecodeContext{})
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer document.Release()
	path, pathOK := document.Root().Named("Route", "path_kind").Uint()
	leg := document.Root().Named("Route", "direct_leg")
	carrier, carrierOK := leg.Named("Leg", "carrier").Uint()
	access, accessOK := leg.Named("Leg", "access_class").Uint()
	dialer, dialerOK := leg.Named("Leg", "dialer_role").Uint()
	listener, listenerOK := leg.Named("Leg", "listener_role").Uint()
	host, hostOK := leg.Named("Leg", "host").Text()
	port, portOK := leg.Named("Leg", "port").Uint()
	mode, modeOK := leg.Named("Leg", "tls_policy").Named("TLSPolicy", "mode").Uint()
	if !pathOK || path != 0 || !carrierOK || carrier != 1 || !accessOK || access != 0 ||
		!dialerOK || dialer != 0 || !listenerOK || listener != 1 || !hostOK || !portOK || port == 0 || port > 65535 {
		return netip.AddrPort{}, errors.New("cookbook supports only a direct client-dialed WSS route")
	}
	// The signed factory validates the complete policy. This recipe declares
	// independently installed CA roots and does not substitute CA for pin mode.
	if !modeOK || mode != 0 {
		return netip.AddrPort{}, errors.New("cookbook requires the signed CA-verification TLS profile")
	}
	return numericAddress(host, strconv.FormatUint(port, 10))
}

func (c *Client) installFactory(config Configuration, route []byte, address netip.AddrPort) error {
	factoryConfig := fs.WebSocketFactoryConfig{Root: c.root, Owner: c.nextOwner(), Clock: c.clock,
		Role: fs.ClientToServer, Route: route, RemoteAddress: address, Roots: config.TLSRoots,
		Origin: config.Origin, Connections: 1, RuntimeBytes: 65536,
		Options: fs.WebSocketProviderOptions{MaxMessageBytes: 65544, ReadBufferBytes: 1024, WriteBufferBytes: 1024,
			HandshakeBytes: 8192, MaxControlsPerSecond: 16, HandshakeTimeout: 5 * time.Second,
			MessageTimeout: 30 * time.Second, RuntimeBytes: 32768, ProviderRuntimeBytes: 1 << 20, ProviderTasks: 4}}
	ref, err := c.reserve(fs.WebSocketCarrierFactoryCharge(factoryConfig))
	if err != nil {
		return err
	}
	c.factory, err = fs.NewWebSocketCarrierFactory(factoryConfig, ref, c.dependencies)
	ref.Release()
	return err
}

func (c *Client) core(parameters fs.SessionParameters) fs.SessionCoreConfig {
	maximum := parameters.Contract.Limits().MaxStreams
	pending := min(maximum, 128)
	classes := [3]uint32{maximum - 10, 10, 0}
	return fs.SessionCoreConfig{Session: parameters, Clock: c.clock,
		MaxScopes: maximum, PendingScopes: pending, WorkSlots: 6,
		Open: fs.OpenLimits{Active: maximum, Opening: pending, Terminal: maximum*2 + 2,
			RejectionReserve: 2, IngressItems: pending, IngressBytes: 64 << 10, PerClass: classes,
			PerOpener: [2][3]uint32{{classes[0], 5, 0}, {classes[0], 5, 0}},
			Protected: [2][3]uint32{{0, 5, 0}, {0, 5, 0}},
			Lifetime:  [2][3]uint64{{1 << 20, 1 << 20, 0}, {1 << 20, 1 << 20, 0}}},
		Maintenance:     fs.MaintenanceReserve{Calls: 4, Blocks: 65536, Bytes: 1 << 20},
		EngineResources: fs.EngineResourceOptions{RuntimeBytes: 4096}, RuntimeBytes: 65536,
		MessageCarrier: true, MessageRuntimeBytes: 65536, DecoderNodes: 128 + 5*int(maximum), MaxDataPayloadBytes: uint64(parameters.Contract.Limits().MaxFrame),
		Streams: fs.SessionStreamConfig{ReceivePoolBytes: uint64(maximum) * (128 << 10), ReceiveBytes: 128 << 10,
			InitialReceiveLimit: 16384, SendBytes: 4096, QueueBytes: 16384, WriteWaiters: 4,
			MaxPlaintext: 4224, Chunk: 4096, RuntimeBytes: 65536},
		SendWorkers: [3]uint32{min(classes[0], 2), 1, 0}, ProbeSlots: 2, PongSlots: 2, RekeyWaitSlots: 2,
		Automatic: fs.AutomaticLivenessPolicy{IntervalMS: 1000000, SubmissionMS: 1000, ResponseMS: 1000, MissThreshold: 3},
		Messages:  fs.MaintenanceMessagePolicy{IngressBurst: 256, IngressRefillMS: 1, ReplyTimeoutMS: 10000}, Termination: fs.StreamTerminationPolicy{NormalMS: 10000, QuarantineMS: 1000, QuarantineDirections: 8},
		Rekey: fs.RekeyPhaseBudgets{LocalPrepareMS: 5000, ProtocolPrepareMS: 10000, ConfirmationMS: 30000}, SharedDiscard: fs.SharedDiscardPolicy{MaxRecords: 16, MaxBytes: 65536, DurationMS: 10000},
		NativeIngress: fs.MaintenanceIngressPolicy{FrameTimeoutMS: 10000, RefillMS: 1, Burst: 256}, DispatchTimeoutMS: 10000,
		RetirementTimeoutMS: 10000, DrainTimeoutMS: 1000}
}

func (c *Client) rpcConfiguration(parameters fs.SessionParameters, streams fs.SessionStreamConfig) (*fs.RPCServicesConfig, []fs.ContractQueryMethod, error) {
	config := &fs.RPCServicesConfig{
		NotifyReceivePending: 16, NotifyPublishPending: 16, NotificationWaitMS: 30000, NotificationCleanupMS: 5000,
		CompletionGraceMS: 5000, ShortRequestBytes: 4096, ShortResponseBytes: 4096,
		ShortTaskCharge: c.executor.TaskCharge(), ShortCompletionCharge: c.executor.CompletionFloorCharge(),
		CryptoProfile: parameters.Profile, Bootstrap: streams, MaxDataPayloadBytes: uint64(parameters.Contract.Limits().MaxFrame),
		Root: c.root, Owner: c.nextOwner(), Accounts: []fs.ResourceAccount{c.scope.Tenant, c.scope.Session},
		Session: parameters.Contract, Clock: c.clock, Query: fs.QueryBinding{Type: 7, Contract: [32]byte{9}},
		Routes: fs.ContractRoutesConfig{ContractNodes: 256, RuntimeBytes: 16384, Clock: c.clock},
		Slots:  8, ResidentSlots: 4, MaxCaptureBytes: 1 << 20,
		RuntimeBytes: 65536, InputRuntimeBytes: 65536, HashRuntimeBytes: 4096, InvocationRuntimeBytes: 65536,
	}
	c.definition = fs.ServiceDefinition{Namespace: parityNamespace}
	var queries []fs.ContractQueryMethod
	for index, typeID := range []uint32{7001, 7002, 7003, 7005} {
		notify := typeID == 7002
		wire, policy, err := parityContract(typeID, notify)
		if err != nil {
			return nil, nil, err
		}
		config.Routes.Methods = append(config.Routes.Methods, fs.MethodRoutes{Contracts: [][]byte{wire}})
		method := fs.ServiceMethod{Type: typeID, Method: fs.UnaryMethod{Contract: policy.Digest, WorkClass: fs.WorkShort,
			Codec: fs.UnaryCodec{MaxEncodedBytes: 4096, Encode: func(ctx context.Context, input, _ []byte) ([]byte, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if len(input) > 4096 {
					return nil, errors.New("parity input exceeds declared codec bound")
				}
				return input, nil
			}}}}
		if notify {
			method.Shape = fs.CallNotify
			config.NotificationMethods = append(config.NotificationMethods, fs.NotificationMethod{Method: uint32(index), WorkClass: fs.WorkShort})
		} else {
			method.Method.DefaultResponseLimitBytes = 4096
			method.Method.Decode = func(ctx context.Context, payload []byte) (any, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return append([]byte(nil), payload...), nil
			}
			config.Methods = append(config.Methods, fs.NewUnaryRegistration(uint32(index), parityNamespace, typeID, fs.WorkShort,
				func(ctx context.Context, request fs.UnaryRequest, response *fs.UnaryResponse) (uint32, error) {
					if err := ctx.Err(); err != nil {
						return 0, err
					}
					input, _, err := request.Input.Bytes()
					if err != nil {
						return 0, err
					}
					_, err = response.Write(input)
					return 0, err
				}))
		}
		c.definition.Methods = append(c.definition.Methods, method)
		queries = append(queries, fs.ContractQueryMethod{Namespace: parityNamespace, Type: typeID})
		if typeID == 7001 || notify {
			workload := fs.ServiceMethodWorkload{Type: typeID, Calls: 1, RequestBytes: 4096}
			if !notify {
				workload.ResponseLimitBytes = 4096
			}
			config.Workloads = append(config.Workloads, fs.SessionMethodWorkload{Namespace: parityNamespace, Method: method, Workload: workload})
		}
	}
	return config, queries, nil
}

func parityContract(typeID uint32, notify bool) ([]byte, fs.ServiceContractPolicy, error) {
	fields := []fs.ServiceContractField{
		{Name: "service_namespace", Kind: fs.ContractTextString, Text: parityNamespace},
		{Name: "type_id", Number: uint64(typeID)},
		{Name: "request_schema_revision", Kind: fs.ContractTextString, Text: "1"},
		{Name: "response_schema_revision", Kind: fs.ContractTextString, Text: "1"},
		{Name: "min_response_limit_bytes"}, {Name: "max_message_lifetime_ms", Number: 30000},
		{Name: "restart_flush", Kind: fs.ContractBoolean}, {Name: "request_max_bytes", Number: 4096},
		{Name: "application_error_catalog", Kind: fs.ContractEncodedArray, Bytes: []byte{0x80}},
	}
	if notify {
		fields = append(fields, fs.ServiceContractField{Name: "call_shape", Number: 2},
			fs.ServiceContractField{Name: "notify_semantics"}, fs.ServiceContractField{Name: "response_limit_mode"},
			fs.ServiceContractField{Name: "max_response_bytes"})
	} else {
		fields = append(fields, fs.ServiceContractField{Name: "call_shape"}, fs.ServiceContractField{Name: "unary_semantics"},
			fs.ServiceContractField{Name: "response_limit_mode", Number: 1}, fs.ServiceContractField{Name: "max_response_bytes", Number: 4096},
			fs.ServiceContractField{Name: "max_transient_run_ms", Number: 30000})
	}
	wire, err := fs.EncodeServiceContract(make([]byte, 8192), fields)
	if err != nil {
		return nil, fs.ServiceContractPolicy{}, err
	}
	codec, err := fs.NewServiceContractCodec(256)
	if err != nil {
		return nil, fs.ServiceContractPolicy{}, err
	}
	contract, err := codec.Decode(wire)
	if err != nil {
		return nil, fs.ServiceContractPolicy{}, err
	}
	defer contract.Release()
	policy, err := contract.Policy()
	return wire, policy, err
}
