package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type queryIntegrationSink struct {
	wire   []byte
	writes uint64
	held   atomic.Bool
}

func (s *queryIntegrationSink) TryAccept(_ context.Context, batch [][]byte) (uint64, error) {
	s.writes++
	s.wire = bytes.Clone(batch[0])
	return uint64(len(s.wire)), nil
}
func (s *queryIntegrationSink) Published(uint64) (bool, error) { return !s.held.Load(), nil }
func (*queryIntegrationSink) Wake() <-chan struct{}            { return nil }

// TestSessionContractQueriesUseAuthenticatedCurrentLease implements v4.go_contract_query.authenticated_source and v4.go_contract_query.environment_acquisition.
func TestSessionContractQueriesUseAuthenticatedCurrentLease(t *testing.T) {
	var limit resourcev4.Vector
	for i := range limit {
		limit[i] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 128, ReferenceSlots: 512})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		root.Close()
		if !root.Snapshot().CleanupComplete {
			t.Error("fixed query assembly retained resources", root.Snapshot())
		}
	})
	f := &executorFixture{root: root, config: ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, CompletionRunning: 1, CompletionReserved: 2, QueryOwners: 4, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}}
	charge, err := ApplicationExecutorCharge(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.executor, err = NewApplicationExecutor(f.config, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.executor.Close(); awaitQuery(t, f.executor.Done()) })
	environment := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1})
	trust := newSessionAdmissionTrustFixture(t, root, environment, resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{83}, Backing: [16]byte{1}, Kind: 83})
	authorization, err := protocolv4.NewEndpointAuthorization(trust.subscriptions[0], trust.authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { authorization.Close(nil) })
	contractWire := initialFixture(t, "service_unary_transient")
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := codec.Decode(contractWire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(contract.Release)
	policy, err := contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	routeConfig := rpcv4.ContractRoutesConfig{Methods: []rpcv4.MethodRoutes{{Contracts: [][]byte{contractWire}}}, ContractNodes: 256, RuntimeBytes: 4096}
	charge, err = rpcv4.ContractRoutesCharge(routeConfig)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := rpcv4.NewContractRoutes(routeConfig, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routes.Close)
	if err := routes.Advertise(policy.Digest); err != nil {
		t.Fatal(err)
	}
	nc := rpcv4.NetworkConfig{Session: testSessionContract(t, protocolv4.DHProfileX25519, "services", 4096, 4, 0, 5000).Contract, Query: rpcv4.QueryBinding{Type: 7, Contract: [32]byte{9}}, RuntimeBytes: 4096}
	charge, err = rpcv4.NetworkCharge(nc)
	if err != nil {
		t.Fatal(err)
	}
	network, err := rpcv4.NewNetwork(nc, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(network.Close)
	inputsConfig := rpcv4.ServiceInputsConfig{GeneralOutstanding: 32, MaxCaptureBytes: 0, InputRuntimeBytes: 4096, HashRuntimeBytes: 512, RuntimeBytes: 4096, Root: root, Owner: resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{92}, Backing: [16]byte{92}, Kind: 92}}
	charge, err = rpcv4.ServiceInputsCharge(inputsConfig)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := network.NewServiceInputs(routes, inputsConfig, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inputs.Close)
	charge, err = rpcv4.ContractQueryServiceCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	service, err := network.NewContractQueryService(routes, trust.clock, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	sink := &queryIntegrationSink{}
	charge, _ = rpcv4.PublisherCharge(4096)
	publisher, err := network.NewPublisher([16]byte{1}, sink, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	charge, _ = rpcv4.ReceiverCharge(4096)
	receiver, err := network.NewReceiver(publisher, inputs, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		receiver.Close()
		publisher.Close()
		if err := publisher.Retire(); err != nil {
			t.Error(err)
		}
	})
	method := ContractQueryMethod{policy.Namespace, policy.Type}
	methods := []ContractQueryMethod{method, {"acme/missing", 99}}
	plan := applicationTestPlan(t, f, SessionPlanConfig{ContractQueries: true, ContractQueryMethods: methods, RuntimeBytes: 4096, AuthorizeApplication: func(_ context.Context, request AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		lease, err := request.ReserveLease(request.Binding(), nil, func(context.Context) error { return nil })
		if err == nil {
			err = lease.SetContractQueryAccess(method, rpcv4.QueryTargetAllowed)
		}
		if err == nil {
			err = lease.SetContractQueryAccess(ContractQueryMethod{"acme/missing", 99}, rpcv4.QueryTargetAllowed)
		}
		return AuthorizeApplicationResult{Lease: lease}, err
	}})
	methods[0] = ContractQueryMethod{"mutated/input", 1}
	if err := plan.InstallContractQueries(service); err != nil {
		t.Fatal(err)
	}
	charge, err = rpcv4.ContractQueryClientCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	client, err := network.NewContractQueryClient(trust.clock, f.reserve(t, 1, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if err = plan.InstallOutgoingContractQueries(client); err != nil {
		t.Fatal(err)
	}
	if err = plan.checkContractQueriesLocked(); err != nil {
		t.Fatal(err)
	}
	plan.claimed = true // Original aggregate adoption has separate real-carrier coverage.
	if err := plan.authorize(context.Background(), ApplicationBinding{Artifact: trust.session.ArtifactDigest, Attempt: trust.attempt}, authorization.Check); err != nil {
		t.Fatal(err)
	}
	if err := plan.lease.bindAuthorization(authorization); err != nil {
		t.Fatal(err)
	}
	targetCodec, _ := protocolv4.NewContractQueryCodec()
	headerCodec, _ := protocolv4.NewApplicationHeaderCodec()
	snapshotCodec, _ := protocolv4.NewContractSnapshotCodec()
	serial := uint64(0)
	query := func(targets []protocolv4.ContractQueryTarget, known []*protocolv4.ServiceContract) ([]byte, protocolv4.ApplicationHeader, protocolv4.ContractQueryTargets) {
		t.Helper()
		serial++
		request := make([]byte, 2048)
		n, targetSet, err := targetCodec.EncodeTargets(request, targets, known)
		if err != nil {
			t.Fatal(err)
		}
		var header [512]byte
		hn, _, err := headerCodec.Encode(header[:], "query_contracts_request", protocolv4.ApplicationHeaderFields{Type: nc.Query.Type, ServiceContractDigest: nc.Query.Contract, DeadlineAtMS: 2000, PayloadBytes: uint32(n)})
		if err != nil {
			t.Fatal(err)
		}
		var wire [4096]byte
		for _, frame := range []protocolv4.RPCFragment{{Kind: protocolv4.RPCBegin, Serial: serial, Header: header[:hn]}, {Kind: protocolv4.RPCData, Serial: serial, Payload: request[:n]}} {
			length, err := protocolv4.EncodeRPCFragment(wire[:], frame)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := receiver.Feed(wire[:length]); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var response protocolv4.ApplicationHeader
		var output []byte
		for {
			progressed, err := publisher.Step(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !progressed {
				select {
				case <-publisher.Wake():
				case <-ctx.Done():
					t.Fatal("fixed source failed to progress", ctx.Err())
				}
				continue
			}
			fragment, err := protocolv4.DecodeRPCFragment(sink.wire)
			if err != nil {
				t.Fatal(err)
			}
			if fragment.Kind == protocolv4.RPCBegin {
				response, err = headerCodec.Decode(fragment.Header)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				output = append(output, fragment.Payload...)
				if uint32(len(output)) == response.Fields().PayloadBytes {
					break
				}
			}
		}
		if _, err := publisher.Step(ctx); err != nil {
			t.Fatal(err)
		}
		return output, response, targetSet
	}
	plain := protocolv4.ContractQueryTarget{Namespace: method.Namespace, Type: method.Type}
	for _, test := range []struct {
		access rpcv4.QueryTargetAccess
		known  bool
		status string
	}{{rpcv4.QueryTargetAllowed, false, "available_full"}, {rpcv4.QueryTargetDenied, false, "denied"}, {rpcv4.QueryTargetUnavailable, false, "unavailable"}, {rpcv4.QueryTargetAllowed, true, "available_unchanged"}} {
		if err := plan.lease.SetContractQueryAccess(method, test.access); err != nil {
			t.Fatal(err)
		}
		target := plain
		bodies := []*protocolv4.ServiceContract{nil, nil, nil}
		if test.known {
			target.HasKnown, target.Known, bodies[0] = true, policy.Digest, contract
		}
		out, header, targets := query([]protocolv4.ContractQueryTarget{target, {Namespace: "acme/unauthorized", Type: 98}, {Namespace: "acme/missing", Type: 99}}, bodies)
		if header.IsSDKError() {
			t.Fatal("authorized fixed source returned whole-query error")
		}
		set, err := snapshotCodec.Decode(targets, out, bodies, []uint64{0, 0, 0}, [][]byte{make([]byte, 8192), nil, nil})
		if err != nil {
			t.Fatal(err)
		}
		for i, status := range []string{test.status, "denied", "unavailable"} {
			item, err := set.Item(i)
			if err != nil || item.Status != status {
				t.Fatal(i, item, status, err)
			}
		}
	}

	// Exercise the Environment acquisition, the same root's outgoing direction,
	// real authenticated current lease and actual RPC publication/response gates.
	// Handshake adoption is covered by the separate real-carrier integration.
	ec := EnvironmentConfig{Positions: 1, ContractQueryAcquisitions: 2, Clock: trust.clock, RuntimeBytes: 4096}
	charge, err = EnvironmentCharge(ec)
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvironment(ec, f.reserve(t, 1, charge), f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 64}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		env.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := env.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := env.Retire(); err != nil {
			t.Error(err)
		}
	})
	session := &EnvironmentSession{environment: env, application: plan, core: &SessionCore{}, delivered: true}
	snapshotCharge, err := ContractQuerySnapshotsCharge(1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, err := env.BeginContractQuery(ctx, session, publisher, []protocolv4.ContractQueryTarget{plain}, []*protocolv4.ServiceContract{nil}, []uint64{0}, 2000, f.reserve(t, 1, snapshotCharge))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	conditional := plain
	conditional.HasKnown = true
	conditional.Known = policy.Digest
	second, err := env.BeginContractQuery(ctx, session, publisher, []protocolv4.ContractQueryTarget{conditional}, []*protocolv4.ServiceContract{contract}, []uint64{0}, 2000, f.reserve(t, 1, snapshotCharge))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err = env.BeginContractQuery(ctx, session, publisher, []protocolv4.ContractQueryTarget{plain}, []*protocolv4.ServiceContract{nil}, []uint64{0}, 2000, f.reserve(t, 1, snapshotCharge)); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("acquisition cap bypassed", err)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err = first.Wait(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("wait cancellation", err)
	}
	pumpAcquisitions := func(first, second *ContractQueryAcquisition) {
		var readyA, readyB <-chan struct{}
		if first != nil {
			readyA = first.ready
		}
		if second != nil {
			readyB = second.ready
		}
		seen := sink.writes
		for readyA != nil || readyB != nil {
			progressed, err := publisher.Step(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if sink.writes != seen {
				seen = sink.writes
				frame, err := protocolv4.DecodeRPCFragment(sink.wire)
				if err != nil {
					t.Fatal(err)
				}
				serial = max(serial, frame.Serial)
				if _, err = receiver.Feed(sink.wire); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-readyA:
				readyA = nil
			default:
			}
			select {
			case <-readyB:
				readyB = nil
			default:
			}
			if !progressed && (readyA != nil || readyB != nil) {
				select {
				case <-publisher.Wake():
				case <-readyA:
					readyA = nil
				case <-readyB:
					readyB = nil
				case <-ctx.Done():
					t.Fatal("protected outgoing query stalled", ctx.Err())
				}
			}
		}
	}
	pumpAcquisitions(first, second)
	for i, q := range []*ContractQueryAcquisition{first, second} {
		if err = q.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		owned, err := q.Take()
		if err != nil {
			t.Fatal(err)
		}
		info, err := owned.Item(0)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"available_full", "available_unchanged"}[i]
		if info.Status != want {
			t.Fatal(info, want)
		}
		body := make([]byte, 8192)
		n, err := owned.CopyCanonical(0, body)
		if err != nil || !bytes.Equal(body[:n], contractWire) {
			t.Fatal("snapshot is not independently owned", err)
		}
		owned.Close()
	}
	for i := 0; i < 8; i++ {
		progressed, err := publisher.Step(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !progressed {
			break
		}
	}
	if err = first.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err = second.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}

	for _, expire := range []bool{false, true} {
		original, abort := context.WithCancel(context.Background())
		cap := uint64(2000)
		if expire {
			cap = 1300
		}
		owner, err := env.BeginContractQuery(original, session, publisher, []protocolv4.ContractQueryTarget{plain}, []*protocolv4.ServiceContract{nil}, []uint64{0}, cap, f.reserve(t, 1, snapshotCharge))
		if err != nil {
			t.Fatal(err)
		}
		pumpAcquisitions(owner, nil)
		if err = owner.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		want := error(context.Canceled)
		if expire {
			trust.tick.Store(75)
			want = timev4.ErrExpired
		} else {
			abort()
		}
		if _, err = owner.Take(); !errors.Is(err, want) {
			t.Fatal("late snapshot escaped its original delivery gate", err, want)
		}
		abort()
		owner.Close()
		for i := 0; i < 8; i++ {
			progressed, err := publisher.Step(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !progressed {
				break
			}
		}
		if err = owner.WaitCleanup(ctx); err != nil {
			t.Fatal(err)
		}
	}
	env.Close()
	if err = env.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err = env.Retire(); err != nil {
		t.Fatal(err)
	}
	plan.lease.Revoke()
	_, header, _ := query([]protocolv4.ContractQueryTarget{plain}, []*protocolv4.ServiceContract{nil})
	if !header.IsSDKError() {
		t.Fatal("revoked original lease still disclosed a contract")
	}
}
