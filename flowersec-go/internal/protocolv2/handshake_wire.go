package protocolv2

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"unicode/utf8"
)

const (
	ControlPrefaceSize       = 16
	HandshakeHeaderSize      = 12
	MaxHandshakePayloadBytes = 8_192
)

var (
	ErrInvalidControlPreface    = errors.New("invalid FSC2 control preface")
	ErrInvalidHandshakeFrame    = errors.New("invalid FSH2 handshake frame")
	ErrHandshakePayloadTooLarge = errors.New("FSH2 handshake payload too large")
	ErrInvalidHandshakeMessage  = errors.New("invalid Flowersec v2 handshake message")
	ErrHandshakeBinding         = errors.New("Flowersec v2 handshake binding mismatch")
)

var handshakeRegistryIDPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

type HandshakeMessageType uint8

const (
	HandshakeClientInit     HandshakeMessageType = 1
	HandshakeServerFinished HandshakeMessageType = 2
	HandshakeClientFinished HandshakeMessageType = 3
)

type HandshakeFrame struct {
	Type    HandshakeMessageType
	Payload []byte
	Raw     []byte
}

type ClientInit struct {
	Profile                  string
	ChannelID                string
	SessionContractHash      [32]byte
	ClientRole               uint8
	Suite                    Suite
	ClientEphemeralPublic    []byte
	NonceC                   [32]byte
	SelectedFeatures         uint32
	MaxInboundStreams        uint16
	ClientAdmissionBinding   [32]byte
	ClientEndpointInstanceID string
}

type ServerFinishedCore struct {
	Suite                    Suite
	HandshakeID              []byte
	ServerEphemeralPublic    []byte
	NonceS                   [32]byte
	SessionContractHash      [32]byte
	SelectedFeatures         uint32
	MaxInboundStreams        uint16
	ServerAdmissionBinding   [32]byte
	ServerEndpointInstanceID string
}

type ServerFinished struct {
	Core          ServerFinishedCore
	ServerConfirm [32]byte
}

type ClientFinished struct {
	HandshakeID   []byte
	ClientConfirm [32]byte
}

type HandshakePath uint8

const (
	HandshakeDirect HandshakePath = 1
	HandshakeTunnel HandshakePath = 2
)

type HandshakeExpectations struct {
	Path                       HandshakePath
	ChannelID                  string
	SessionContractHash        [32]byte
	Suite                      Suite
	MaxInboundStreams          uint16
	AdmissionBinding           [32]byte
	ExpectedEndpointInstanceID string
}

type clientInitWire struct {
	ChannelID                       string `json:"channel_id"`
	ClientAdmissionBindingBase64URL string `json:"client_admission_binding_b64u"`
	ClientEndpointInstanceID        string `json:"client_endpoint_instance_id"`
	ClientEphemeralPublicBase64URL  string `json:"client_eph_pub_b64u"`
	ClientRole                      uint8  `json:"client_role"`
	MaxInboundStreams               uint16 `json:"max_inbound_streams"`
	NonceCBase64URL                 string `json:"nonce_c_b64u"`
	Profile                         string `json:"profile"`
	SelectedFeatures                uint32 `json:"selected_features"`
	SessionContractHashBase64URL    string `json:"session_contract_hash_b64u"`
	Suite                           Suite  `json:"suite"`
}

type serverCoreWire struct {
	HandshakeIDBase64URL            string `json:"handshake_id"`
	MaxInboundStreams               uint16 `json:"max_inbound_streams"`
	NonceSBase64URL                 string `json:"nonce_s_b64u"`
	SelectedFeatures                uint32 `json:"selected_features"`
	ServerAdmissionBindingBase64URL string `json:"server_admission_binding_b64u"`
	ServerEndpointInstanceID        string `json:"server_endpoint_instance_id"`
	ServerEphemeralPublicBase64URL  string `json:"server_eph_pub_b64u"`
	SessionContractHashBase64URL    string `json:"session_contract_hash_b64u"`
}

type serverFinishedWire struct {
	HandshakeIDBase64URL            string `json:"handshake_id"`
	MaxInboundStreams               uint16 `json:"max_inbound_streams"`
	NonceSBase64URL                 string `json:"nonce_s_b64u"`
	SelectedFeatures                uint32 `json:"selected_features"`
	ServerAdmissionBindingBase64URL string `json:"server_admission_binding_b64u"`
	ServerConfirmBase64URL          string `json:"server_confirm_b64u"`
	ServerEndpointInstanceID        string `json:"server_endpoint_instance_id"`
	ServerEphemeralPublicBase64URL  string `json:"server_eph_pub_b64u"`
	SessionContractHashBase64URL    string `json:"session_contract_hash_b64u"`
}

type clientCoreWire struct {
	HandshakeIDBase64URL string `json:"handshake_id"`
}

type clientFinishedWire struct {
	ClientConfirmBase64URL string `json:"client_confirm_b64u"`
	HandshakeIDBase64URL   string `json:"handshake_id"`
}

func MarshalControlPreface() []byte {
	out := make([]byte, ControlPrefaceSize)
	copy(out[0:4], "FSC2")
	out[4] = 2
	out[5] = byte(RoleClient)
	return out
}

func ParseControlPreface(raw []byte) error {
	if len(raw) != ControlPrefaceSize || string(raw[0:4]) != "FSC2" || raw[4] != 2 || raw[5] != byte(RoleClient) {
		return ErrInvalidControlPreface
	}
	for _, value := range raw[6:] {
		if value != 0 {
			return ErrInvalidControlPreface
		}
	}
	return nil
}

func ReadHandshakeFrame(reader io.Reader) (*HandshakeFrame, error) {
	var header [HandshakeHeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrInvalidHandshakeFrame, err)
	}
	if string(header[0:4]) != "FSH2" || header[4] != 2 || header[6] != 0 || header[7] != 0 {
		return nil, ErrInvalidHandshakeFrame
	}
	typ := HandshakeMessageType(header[5])
	if typ < HandshakeClientInit || typ > HandshakeClientFinished {
		return nil, ErrInvalidHandshakeFrame
	}
	payloadLength := binary.BigEndian.Uint32(header[8:12])
	if payloadLength > MaxHandshakePayloadBytes {
		return nil, ErrHandshakePayloadTooLarge
	}
	if payloadLength == 0 {
		return nil, ErrInvalidHandshakeFrame
	}
	payload := make([]byte, int(payloadLength))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrInvalidHandshakeFrame, err)
	}
	if !utf8.Valid(payload) {
		return nil, ErrInvalidHandshakeFrame
	}
	raw := make([]byte, HandshakeHeaderSize+len(payload))
	copy(raw, header[:])
	copy(raw[HandshakeHeaderSize:], payload)
	return &HandshakeFrame{Type: typ, Payload: payload, Raw: raw}, nil
}

func ParseHandshakeFrame(raw []byte) (*HandshakeFrame, error) {
	reader := bytes.NewReader(raw)
	frame, err := ReadHandshakeFrame(reader)
	if err != nil {
		return nil, err
	}
	if reader.Len() != 0 {
		return nil, ErrInvalidHandshakeFrame
	}
	return frame, nil
}

func MarshalClientInit(message ClientInit) ([]byte, error) {
	if err := validateClientInitFields(message); err != nil {
		return nil, err
	}
	wire := clientInitWire{
		ClientAdmissionBindingBase64URL: encodeHandshake32(message.ClientAdmissionBinding),
		ClientEndpointInstanceID:        message.ClientEndpointInstanceID,
		ClientEphemeralPublicBase64URL:  base64.RawURLEncoding.EncodeToString(message.ClientEphemeralPublic),
		ClientRole:                      message.ClientRole, ChannelID: message.ChannelID,
		MaxInboundStreams: message.MaxInboundStreams, NonceCBase64URL: encodeHandshake32(message.NonceC),
		Profile: message.Profile, SelectedFeatures: message.SelectedFeatures,
		SessionContractHashBase64URL: encodeHandshake32(message.SessionContractHash), Suite: message.Suite,
	}
	return marshalHandshakeMessage(HandshakeClientInit, wire)
}

func ParseClientInit(raw []byte) (ClientInit, error) {
	frame, err := ParseHandshakeFrame(raw)
	if err != nil || frame.Type != HandshakeClientInit {
		return ClientInit{}, ErrInvalidHandshakeMessage
	}
	object, err := decodeHandshakeObject(frame.Payload, []string{
		"client_admission_binding_b64u", "client_endpoint_instance_id", "client_eph_pub_b64u", "client_role",
		"channel_id", "max_inbound_streams", "nonce_c_b64u", "profile", "selected_features",
		"session_contract_hash_b64u", "suite",
	})
	if err != nil {
		return ClientInit{}, err
	}
	message := ClientInit{}
	if message.ClientAdmissionBinding, err = decodeHandshake32(object["client_admission_binding_b64u"]); err != nil {
		return ClientInit{}, err
	}
	if message.ClientEndpointInstanceID, err = decodeJSONString(object["client_endpoint_instance_id"]); err != nil {
		return ClientInit{}, err
	}
	if message.ClientEphemeralPublic, err = decodeCanonicalBase64URL(object["client_eph_pub_b64u"], 0); err != nil {
		return ClientInit{}, err
	}
	if message.ClientRole, err = decodeJSONUint8(object["client_role"]); err != nil {
		return ClientInit{}, err
	}
	if message.ChannelID, err = decodeJSONString(object["channel_id"]); err != nil {
		return ClientInit{}, err
	}
	if message.MaxInboundStreams, err = decodeJSONUint16(object["max_inbound_streams"]); err != nil {
		return ClientInit{}, err
	}
	if message.NonceC, err = decodeHandshake32(object["nonce_c_b64u"]); err != nil {
		return ClientInit{}, err
	}
	if message.Profile, err = decodeJSONString(object["profile"]); err != nil {
		return ClientInit{}, err
	}
	if message.SelectedFeatures, err = decodeJSONUint32(object["selected_features"]); err != nil {
		return ClientInit{}, err
	}
	if message.SessionContractHash, err = decodeHandshake32(object["session_contract_hash_b64u"]); err != nil {
		return ClientInit{}, err
	}
	suite, err := decodeJSONUint16(object["suite"])
	if err != nil {
		return ClientInit{}, err
	}
	message.Suite = Suite(suite)
	if err := validateClientInitFields(message); err != nil {
		return ClientInit{}, err
	}
	canonical, err := MarshalClientInit(message)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ClientInit{}, ErrInvalidHandshakeMessage
	}
	return message, nil
}

func MarshalServerFinishedCore(core ServerFinishedCore, suite Suite) ([]byte, error) {
	core.Suite = suite
	if err := validateServerCoreFields(core); err != nil {
		return nil, err
	}
	wire := serverCoreWire{
		HandshakeIDBase64URL: base64.RawURLEncoding.EncodeToString(core.HandshakeID),
		MaxInboundStreams:    core.MaxInboundStreams, NonceSBase64URL: encodeHandshake32(core.NonceS),
		SelectedFeatures:                core.SelectedFeatures,
		ServerAdmissionBindingBase64URL: encodeHandshake32(core.ServerAdmissionBinding),
		ServerEndpointInstanceID:        core.ServerEndpointInstanceID,
		ServerEphemeralPublicBase64URL:  base64.RawURLEncoding.EncodeToString(core.ServerEphemeralPublic),
		SessionContractHashBase64URL:    encodeHandshake32(core.SessionContractHash),
	}
	return marshalHandshakeMessage(HandshakeServerFinished, wire)
}

func MarshalServerFinished(message ServerFinished, suite Suite) ([]byte, error) {
	message.Core.Suite = suite
	if err := validateServerCoreFields(message.Core); err != nil {
		return nil, err
	}
	wire := serverFinishedWire{
		HandshakeIDBase64URL: base64.RawURLEncoding.EncodeToString(message.Core.HandshakeID),
		MaxInboundStreams:    message.Core.MaxInboundStreams, NonceSBase64URL: encodeHandshake32(message.Core.NonceS),
		SelectedFeatures:                message.Core.SelectedFeatures,
		ServerAdmissionBindingBase64URL: encodeHandshake32(message.Core.ServerAdmissionBinding),
		ServerConfirmBase64URL:          encodeHandshake32(message.ServerConfirm),
		ServerEndpointInstanceID:        message.Core.ServerEndpointInstanceID,
		ServerEphemeralPublicBase64URL:  base64.RawURLEncoding.EncodeToString(message.Core.ServerEphemeralPublic),
		SessionContractHashBase64URL:    encodeHandshake32(message.Core.SessionContractHash),
	}
	return marshalHandshakeMessage(HandshakeServerFinished, wire)
}

func ParseServerFinished(raw []byte, suite Suite) (ServerFinished, error) {
	frame, err := ParseHandshakeFrame(raw)
	if err != nil || frame.Type != HandshakeServerFinished {
		return ServerFinished{}, ErrInvalidHandshakeMessage
	}
	object, err := decodeHandshakeObject(frame.Payload, []string{
		"handshake_id", "max_inbound_streams", "nonce_s_b64u", "selected_features",
		"server_admission_binding_b64u", "server_confirm_b64u", "server_endpoint_instance_id",
		"server_eph_pub_b64u", "session_contract_hash_b64u",
	})
	if err != nil {
		return ServerFinished{}, err
	}
	message := ServerFinished{Core: ServerFinishedCore{Suite: suite}}
	if message.Core.HandshakeID, err = decodeCanonicalBase64URL(object["handshake_id"], 0); err != nil {
		return ServerFinished{}, err
	}
	if message.Core.MaxInboundStreams, err = decodeJSONUint16(object["max_inbound_streams"]); err != nil {
		return ServerFinished{}, err
	}
	if message.Core.NonceS, err = decodeHandshake32(object["nonce_s_b64u"]); err != nil {
		return ServerFinished{}, err
	}
	if message.Core.SelectedFeatures, err = decodeJSONUint32(object["selected_features"]); err != nil {
		return ServerFinished{}, err
	}
	if message.Core.ServerAdmissionBinding, err = decodeHandshake32(object["server_admission_binding_b64u"]); err != nil {
		return ServerFinished{}, err
	}
	if message.ServerConfirm, err = decodeHandshake32(object["server_confirm_b64u"]); err != nil {
		return ServerFinished{}, err
	}
	if message.Core.ServerEndpointInstanceID, err = decodeJSONString(object["server_endpoint_instance_id"]); err != nil {
		return ServerFinished{}, err
	}
	if message.Core.ServerEphemeralPublic, err = decodeCanonicalBase64URL(object["server_eph_pub_b64u"], 0); err != nil {
		return ServerFinished{}, err
	}
	if message.Core.SessionContractHash, err = decodeHandshake32(object["session_contract_hash_b64u"]); err != nil {
		return ServerFinished{}, err
	}
	if err := validateServerCoreFields(message.Core); err != nil {
		return ServerFinished{}, err
	}
	canonical, err := MarshalServerFinished(message, suite)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ServerFinished{}, ErrInvalidHandshakeMessage
	}
	return message, nil
}

func MarshalClientFinishedCore(handshakeID []byte) ([]byte, error) {
	if len(handshakeID) < 16 || len(handshakeID) > 32 {
		return nil, ErrInvalidHandshakeMessage
	}
	return marshalHandshakeMessage(HandshakeClientFinished, clientCoreWire{HandshakeIDBase64URL: base64.RawURLEncoding.EncodeToString(handshakeID)})
}

func MarshalClientFinished(message ClientFinished) ([]byte, error) {
	if len(message.HandshakeID) < 16 || len(message.HandshakeID) > 32 {
		return nil, ErrInvalidHandshakeMessage
	}
	wire := clientFinishedWire{
		ClientConfirmBase64URL: encodeHandshake32(message.ClientConfirm),
		HandshakeIDBase64URL:   base64.RawURLEncoding.EncodeToString(message.HandshakeID),
	}
	return marshalHandshakeMessage(HandshakeClientFinished, wire)
}

func ParseClientFinished(raw []byte) (ClientFinished, error) {
	frame, err := ParseHandshakeFrame(raw)
	if err != nil || frame.Type != HandshakeClientFinished {
		return ClientFinished{}, ErrInvalidHandshakeMessage
	}
	object, err := decodeHandshakeObject(frame.Payload, []string{"client_confirm_b64u", "handshake_id"})
	if err != nil {
		return ClientFinished{}, err
	}
	message := ClientFinished{}
	if message.ClientConfirm, err = decodeHandshake32(object["client_confirm_b64u"]); err != nil {
		return ClientFinished{}, err
	}
	if message.HandshakeID, err = decodeCanonicalBase64URL(object["handshake_id"], 0); err != nil {
		return ClientFinished{}, err
	}
	if len(message.HandshakeID) < 16 || len(message.HandshakeID) > 32 {
		return ClientFinished{}, ErrInvalidHandshakeMessage
	}
	canonical, err := MarshalClientFinished(message)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ClientFinished{}, ErrInvalidHandshakeMessage
	}
	return message, nil
}

func ValidateClientInit(message ClientInit, expected HandshakeExpectations) error {
	if err := validateClientInitFields(message); err != nil {
		return err
	}
	if message.ChannelID != expected.ChannelID || message.Suite != expected.Suite || message.MaxInboundStreams != expected.MaxInboundStreams ||
		!constantArrayEqual(message.SessionContractHash, expected.SessionContractHash) || !validAdmissionBinding(expected.Path, message.ClientAdmissionBinding, expected.AdmissionBinding) ||
		!validExpectedEndpoint(expected.Path, message.ClientEndpointInstanceID, expected.ExpectedEndpointInstanceID) {
		return ErrHandshakeBinding
	}
	return nil
}

func ValidateServerFinished(message ServerFinished, expected HandshakeExpectations) error {
	if err := validateServerCoreFields(message.Core); err != nil {
		return err
	}
	if message.Core.Suite != expected.Suite || message.Core.MaxInboundStreams != expected.MaxInboundStreams ||
		!constantArrayEqual(message.Core.SessionContractHash, expected.SessionContractHash) || !validAdmissionBinding(expected.Path, message.Core.ServerAdmissionBinding, expected.AdmissionBinding) ||
		!validExpectedEndpoint(expected.Path, message.Core.ServerEndpointInstanceID, expected.ExpectedEndpointInstanceID) {
		return ErrHandshakeBinding
	}
	return nil
}

func validateClientInitFields(message ClientInit) error {
	if message.Profile != "flowersec/2" || !validHandshakeRegistryID(message.ChannelID, false) || message.ClientRole != byte(RoleClient) ||
		(message.Suite != SuiteChaCha20Poly1305 && message.Suite != SuiteAES256GCM) || message.SelectedFeatures != 0 ||
		message.MaxInboundStreams < 1 || message.MaxInboundStreams > 128 || !validHandshakeRegistryID(message.ClientEndpointInstanceID, true) {
		return ErrInvalidHandshakeMessage
	}
	if _, err := ParseEphemeralPublicKey(message.Suite, message.ClientEphemeralPublic); err != nil {
		return err
	}
	return nil
}

func validateServerCoreFields(core ServerFinishedCore) error {
	if len(core.HandshakeID) < 16 || len(core.HandshakeID) > 32 || core.SelectedFeatures != 0 ||
		core.MaxInboundStreams < 1 || core.MaxInboundStreams > 128 || !validHandshakeRegistryID(core.ServerEndpointInstanceID, true) {
		return ErrInvalidHandshakeMessage
	}
	if _, err := ParseEphemeralPublicKey(core.Suite, core.ServerEphemeralPublic); err != nil {
		return err
	}
	return nil
}

func marshalHandshakeMessage(typ HandshakeMessageType, value any) ([]byte, error) {
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	payloadBytes := bytes.TrimSuffix(payload.Bytes(), []byte{'\n'})
	if len(payloadBytes) == 0 || len(payloadBytes) > MaxHandshakePayloadBytes {
		return nil, ErrHandshakePayloadTooLarge
	}
	out := make([]byte, HandshakeHeaderSize+len(payloadBytes))
	copy(out[0:4], "FSH2")
	out[4] = 2
	out[5] = byte(typ)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(payloadBytes)))
	copy(out[12:], payloadBytes)
	return out, nil
}

func decodeHandshakeObject(raw []byte, fields []string) (map[string]json.RawMessage, error) {
	allowed := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		allowed[field] = struct{}{}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, ErrInvalidHandshakeMessage
	}
	object := make(map[string]json.RawMessage, len(fields))
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, ErrInvalidHandshakeMessage
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, ErrInvalidHandshakeMessage
		}
		if _, ok := allowed[key]; !ok {
			return nil, ErrInvalidHandshakeMessage
		}
		if _, duplicate := object[key]; duplicate {
			return nil, ErrInvalidHandshakeMessage
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, ErrInvalidHandshakeMessage
		}
		object[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(object) != len(fields) {
		return nil, ErrInvalidHandshakeMessage
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidHandshakeMessage
	}
	return object, nil
}

func decodeJSONString(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", ErrInvalidHandshakeMessage
	}
	return value, nil
}

func decodeJSONUint8(raw json.RawMessage) (uint8, error) {
	value, err := decodeJSONUint(raw, 8)
	return uint8(value), err
}

func decodeJSONUint16(raw json.RawMessage) (uint16, error) {
	value, err := decodeJSONUint(raw, 16)
	return uint16(value), err
}

func decodeJSONUint32(raw json.RawMessage) (uint32, error) {
	value, err := decodeJSONUint(raw, 32)
	return uint32(value), err
}

func decodeJSONUint(raw json.RawMessage, bits int) (uint64, error) {
	text := string(raw)
	if text == "" || text[0] < '0' || text[0] > '9' {
		return 0, ErrInvalidHandshakeMessage
	}
	for i := 1; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, ErrInvalidHandshakeMessage
		}
	}
	if len(text) > 1 && text[0] == '0' {
		return 0, ErrInvalidHandshakeMessage
	}
	value, err := strconv.ParseUint(text, 10, bits)
	if err != nil {
		return 0, ErrInvalidHandshakeMessage
	}
	return value, nil
}

func decodeHandshake32(raw json.RawMessage) ([32]byte, error) {
	value, err := decodeJSONString(raw)
	if err != nil {
		return [32]byte{}, err
	}
	decoded, err := decodeCanonicalBase64URLString(value, 32)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], decoded)
	return out, nil
}

func decodeCanonicalBase64URL(raw json.RawMessage, length int) ([]byte, error) {
	value, err := decodeJSONString(raw)
	if err != nil {
		return nil, err
	}
	return decodeCanonicalBase64URLString(value, length)
}

func decodeCanonicalBase64URLString(value string, length int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || (length != 0 && len(decoded) != length) || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidHandshakeMessage
	}
	return decoded, nil
}

func encodeHandshake32(value [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func validHandshakeRegistryID(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	return len(value) <= 128 && handshakeRegistryIDPattern.MatchString(value)
}

func constantArrayEqual(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func validAdmissionBinding(path HandshakePath, actual, expected [32]byte) bool {
	if path != HandshakeTunnel {
		return constantArrayEqual(actual, expected)
	}
	var zero [32]byte
	if !constantArrayEqual(expected, zero) {
		return constantArrayEqual(actual, expected)
	}
	return !constantArrayEqual(actual, zero)
}

func validExpectedEndpoint(path HandshakePath, got, expected string) bool {
	switch path {
	case HandshakeDirect:
		return got == "" && expected == ""
	case HandshakeTunnel:
		if !validHandshakeRegistryID(got, false) || !validHandshakeRegistryID(expected, false) || len(got) != len(expected) {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
	default:
		return false
	}
}
