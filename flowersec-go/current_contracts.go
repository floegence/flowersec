package flowersec

import "github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"

// SignedMapBackingBytes reports the bounded backing required by the original
// signed-map codec. A codec verifies bytes against independently installed trust;
// constructing it does not confer admission or consumption authority.
func SignedMapBackingBytes(schema string, byteCap, nodeCap int) (uint64, error) {
	return protocolv4.SignedMapBackingBytes(schema, byteCap, nodeCap)
}

func ProtocolDecoderBackingBytes(byteCap, nodeCap int) (uint64, error) {
	return protocolv4.DecoderBackingBytes(byteCap, nodeCap)
}

func CredentialBackingBytes(schema string) (uint64, error) {
	return protocolv4.CredentialBackingBytes(schema)
}

func NewSignedMapCodec(schema string, byteCap, nodeCap int) (*SignedMapCodec, error) {
	return protocolv4.NewSignedMapCodec(schema, byteCap, nodeCap)
}

// ServiceContract preserves the canonical contract until Release. Decoding a
// contract does not register a service, grant access or promise durable execution.
type ServiceContract = protocolv4.ServiceContract
type ServiceContractCodec = protocolv4.ServiceContractCodec

func ServiceContractBackingBytes(nodeCap int) (uint64, error) {
	return protocolv4.ServiceContractBackingBytes(nodeCap)
}

func NewServiceContractCodec(nodeCap int) (*ServiceContractCodec, error) {
	return protocolv4.NewServiceContractCodec(nodeCap)
}

// ProtocolDecoder is a bounded host-composition codec. Decoding untrusted bytes
// never establishes a signature, trust continuity, admission or spend right.
type ProtocolDecoder = protocolv4.Decoder
type ProtocolDocument = protocolv4.Document
type ProtocolValue = protocolv4.Value

func NewProtocolDecoder(byteCap, nodeCap int) (*ProtocolDecoder, error) {
	return protocolv4.NewDecoder(byteCap, nodeCap)
}

// ServiceContractField names a registered contract field; callers cannot choose
// wire field IDs. The bounded contract codec validates complete field rules.
type ServiceContractField = protocolv4.Field
type ServiceContractFieldKind = protocolv4.FieldKind

const (
	ContractUnsigned     = protocolv4.Unsigned
	ContractByteString   = protocolv4.ByteString
	ContractTextString   = protocolv4.TextString
	ContractBoolean      = protocolv4.Boolean
	ContractEncodedMap   = protocolv4.EncodedMap
	ContractEncodedArray = protocolv4.EncodedArray
)

func EncodeServiceContract(dst []byte, fields []ServiceContractField) ([]byte, error) {
	wire, err := protocolv4.EncodeMap(dst, "ServiceContract", fields)
	if err != nil {
		return nil, err
	}
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		return nil, err
	}
	contract, err := codec.Decode(wire)
	if err != nil {
		return nil, err
	}
	contract.Release()
	return wire, nil
}

type SessionParameters = protocolv4.ArtifactSessionParameters
type FeatureEnvelopePolicy = protocolv4.FeatureEnvelopePolicy
