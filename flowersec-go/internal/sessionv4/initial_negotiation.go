package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// InitialHello is the original verified Artifact and selected complete route.
// The workspace and HelloBinding backing are included in the prior admission
// reservation. Policy is fixed from the real carrier / whole-route grants and
// the prior binding-mode choice, never constructed from a peer's offer.
type InitialHello struct {
	Artifact              *protocolv4.SignedMap
	Index                 uint64
	Attempt               [16]byte
	Workspace             *protocolv4.HelloWorkspace
	Policy                protocolv4.HelloPolicy
	Offered, BindingModes uint64
	IdentityHint          []byte
}

func (x *InitialExchange) helloStart(role protocolv4.Direction, hello InitialHello) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.checkLocked(); err != nil {
		return err
	}
	if x.sending || x.receiving {
		return cryptov4.ErrCapacity
	}
	if hello.Artifact == nil || hello.Workspace == nil || x.config.Role != role || x.phase != 0 {
		return x.failLocked(ErrInitialPhase)
	}
	return x.config.original.checkProposal(hello)
}

// NegotiateClient sends the original ClientHello and validates ServerHello's
// complete echoes, exact feature intersection and actual transport binding.
func (x *InitialExchange) NegotiateClient(hello InitialHello) (*protocolv4.HelloBinding, error) {
	if err := x.helloStart(protocolv4.ClientToServer, hello); err != nil {
		return nil, err
	}
	_, err := x.Send(protocolv4.FrameNegotiate, func(dst []byte) (int, error) {
		wire, err := hello.Workspace.BuildClientHello(dst, hello.Artifact, hello.Index, hello.Attempt, hello.Offered, hello.BindingModes, hello.IdentityHint)
		return len(wire), err
	})
	if err != nil {
		return nil, err
	}
	var binding *protocolv4.HelloBinding
	err = x.Receive(protocolv4.FrameNegotiate, func(server []byte) error {
		var err error
		binding, err = hello.Workspace.Bind(hello.Artifact, hello.Index, hello.Attempt, x.clientHello[:x.clientHelloBytes], server, hello.Policy)
		if err == nil {
			err = x.config.original.checkHello(binding)
		}
		if err == nil {
			x.hello = binding
			x.session = binding.SessionParameters()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return binding, nil
}

// NegotiateServer retains the first canonical ClientHello, validates it against
// the independently trusted original material, then generates the original
// ServerHello nonce inside the one logical send. Replays cannot enter its build.
func (x *InitialExchange) NegotiateServer(hello InitialHello) (*protocolv4.HelloBinding, error) {
	if err := x.helloStart(protocolv4.ServerToClient, hello); err != nil {
		return nil, err
	}
	if err := x.Receive(protocolv4.FrameNegotiate, func([]byte) error { return nil }); err != nil {
		return nil, err
	}
	return x.negotiateServerRetained(hello)
}

// The accepted entrance may perform trusted material lookup after retaining
// the first ClientHello. It continues that same flight without a second read.
func (x *InitialExchange) negotiateServerRetained(hello InitialHello) (*protocolv4.HelloBinding, error) {
	var binding *protocolv4.HelloBinding
	_, err := x.Send(protocolv4.FrameNegotiate, func(dst []byte) (int, error) {
		wire, h, err := hello.Workspace.BuildServerHello(dst, hello.Artifact, hello.Index, hello.Attempt, x.clientHello[:x.clientHelloBytes], hello.Offered, hello.Policy, hello.IdentityHint)
		if err == nil {
			err = x.config.original.checkHello(h)
		}
		if err == nil {
			binding = h
			x.hello = h
			x.session = h.SessionParameters()
		}
		return len(wire), err
	})
	if err != nil {
		return nil, err
	}
	return binding, nil
}

func (x *InitialExchange) admissionHello() (*protocolv4.HelloBinding, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.checkLocked(); err != nil {
		return nil, err
	}
	if x.phase < 2 || x.hello == nil {
		return nil, ErrInitialPhase
	}
	return x.hello, nil
}

// SendAdmission generates/signs the single original FSB from this connection's
// retained hello binding. The independent original activation/trust/time/key
// guard is rechecked around signing and once more before the first publication.
// The returned map retains its bytes for FSA/Noise and caller cleanup. It is
// returned even on a later publication error to preserve the original facts.
func (x *InitialExchange) SendAdmission(activation *protocolv4.ActivationBinding, proof, certificate *protocolv4.SignedMap, codec *protocolv4.SignedMapCodec, signer protocolv4.MapSigner, guard func() error) (*protocolv4.SignedMap, InitialWriteResult, error) {
	h, err := x.admissionHello()
	if err != nil {
		return nil, InitialWriteResult{}, err
	}
	if x.config.original.enabled {
		if err := x.config.original.activation.MatchBinding(activation); err != nil {
			return nil, InitialWriteResult{}, err
		}
	}
	if guard == nil {
		return nil, InitialWriteResult{}, cryptov4.ErrConfiguration
	}
	check := func() error {
		if err := x.check(); err != nil {
			return err
		}
		return guard()
	}
	var fsb *protocolv4.SignedMap
	result, err := x.sendFlight(protocolv4.FrameAdmission, func(dst []byte) (int, error) {
		request, err := protocolv4.NewAdmissionRequest(h, activation, proof, certificate, codec, signer, check)
		if err != nil {
			return 0, err
		}
		defer request.Close()
		fsb, err = request.Build()
		if err != nil {
			return 0, err
		}
		wire, err := fsb.Bytes()
		if err != nil {
			return 0, err
		}
		if len(wire) > len(dst) {
			return 0, protocolv4.ErrPayloadTooLarge
		}
		return copy(dst, wire), nil
	}, check, false)
	return fsb, result, err
}

// SendAdmissionResponse belongs inside the confirmed original admission CAS's
// one-shot dispatch callback. guard cannot be made from a row/query/receipt;
// it checks the original Acceptor, carrier, local token, trust and deadlines.
func (x *InitialExchange) SendAdmissionResponse(codec *protocolv4.SignedMapCodec, certificate *protocolv4.SignedMap, response protocolv4.AdmissionResponse, signer protocolv4.MapSigner, guard func() error) (*protocolv4.SignedMap, InitialWriteResult, error) {
	h, err := x.admissionHello()
	if err != nil {
		return nil, InitialWriteResult{}, err
	}
	if guard == nil {
		return nil, InitialWriteResult{}, cryptov4.ErrConfiguration
	}
	check := func() error {
		if err := x.check(); err != nil {
			return err
		}
		if x.config.accepted != nil {
			if err := x.config.accepted.checkResponse(response.Admitted); err != nil {
				return err
			}
			if err := x.config.accepted.matchResponse(response); err != nil {
				return err
			}
		}
		return guard()
	}
	var fsa *protocolv4.SignedMap
	result, err := x.sendFlight(protocolv4.FrameAdmissionResult, func(dst []byte) (int, error) {
		var err error
		fsa, err = h.BuildResponse(codec, certificate, response, signer, check)
		if err != nil {
			return 0, err
		}
		wire, err := fsa.Bytes()
		if err != nil {
			return 0, err
		}
		if len(wire) > len(dst) {
			return 0, protocolv4.ErrPayloadTooLarge
		}
		return copy(dst, wire), nil
	}, check, false)
	return fsa, result, err
}
