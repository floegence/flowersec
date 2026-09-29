package protocolv4

import (
	"sync"
	"unsafe"
)

type SpendState string
type AuthorizationOutcome string

const (
	SpendSpending           SpendState           = "spending"
	SpendConsumed           SpendState           = "consumed"
	AuthorizationUnknown    AuthorizationOutcome = "unknown"
	AuthorizationDenied     AuthorizationOutcome = "denied"
	AuthorizationAuthorized AuthorizationOutcome = "authorized"
	AuthorizationNotStarted AuthorizationOutcome = "not_started"
)

// SpendReceipt describes authenticated caller facts without a dispatch or
// activation capability. It contains no original authorization material.
type SpendReceipt struct {
	Lease, Attempt                    [16]byte
	State                             SpendState
	AuthorizationOutcome              AuthorizationOutcome
	UpdatedAtMS, QueryAfterDurationMS uint64
}

// SpendReceiptCodec consumes the shared canonical schema. Its original caller
// admits the fixed backing before construction and authenticates each result
// against the original request; a decoded receipt is never admission evidence.
type SpendReceiptCodec struct {
	mu      sync.Mutex
	decoder *Decoder
}

func SpendReceiptCodecBackingBytes() (uint64, error) {
	n, err := DecoderBackingBytes(61, 13)
	return n + uint64(unsafe.Sizeof(SpendReceiptCodec{})), err
}

func NewSpendReceiptCodec() (*SpendReceiptCodec, error) {
	d, err := NewDecoder(61, 13)
	if err != nil {
		return nil, err
	}
	return &SpendReceiptCodec{decoder: d}, nil
}

func (c *SpendReceiptCodec) Decode(wire []byte) (SpendReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.decode(wire)
}

func (c *SpendReceiptCodec) decode(wire []byte) (out SpendReceipt, err error) {
	doc, err := c.decoder.DecodeMap(wire, "SpendReceipt", DecodeContext{})
	if err != nil {
		return out, err
	}
	defer doc.Release()
	r := doc.Root()
	lease, _ := r.Named("SpendReceipt", "lease_id").ByteString()
	attempt, _ := r.Named("SpendReceipt", "attempt_id").ByteString()
	copy(out.Lease[:], lease)
	copy(out.Attempt[:], attempt)
	state, _ := r.Named("SpendReceipt", "state").Uint()
	outcome, _ := r.Named("SpendReceipt", "authorization_outcome").Uint()
	label, err := managementLabel("SpendReceipt", "state", state, []string{"spending", "consumed"})
	if err != nil {
		return SpendReceipt{}, err
	}
	out.State = SpendState(label)
	label, err = managementLabel("SpendReceipt", "authorization_outcome", outcome, []string{"unknown", "denied", "authorized", "not_started"})
	if err != nil {
		return SpendReceipt{}, err
	}
	out.AuthorizationOutcome = AuthorizationOutcome(label)
	out.UpdatedAtMS, _ = r.Named("SpendReceipt", "updated_at_ms").Uint()
	out.QueryAfterDurationMS, _ = r.Named("SpendReceipt", "query_after_duration_ms").Uint()
	return out, nil
}

func (c *SpendReceiptCodec) Encode(dst []byte, receipt SpendReceipt) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	state, err := EnumValue("SpendReceipt", "state", string(receipt.State))
	if err != nil {
		return 0, err
	}
	outcome, err := EnumValue("SpendReceipt", "authorization_outcome", string(receipt.AuthorizationOutcome))
	if err != nil {
		return 0, err
	}
	wire, err := EncodeMap(dst, "SpendReceipt", []Field{
		{Name: "lease_id", Kind: ByteString, Bytes: receipt.Lease[:]},
		{Name: "attempt_id", Kind: ByteString, Bytes: receipt.Attempt[:]},
		{Name: "state", Number: state}, {Name: "authorization_outcome", Number: outcome},
		{Name: "updated_at_ms", Number: receipt.UpdatedAtMS},
		{Name: "query_after_duration_ms", Number: receipt.QueryAfterDurationMS},
	})
	if err == nil {
		_, err = c.decode(wire)
	}
	if err != nil {
		clear(wire)
		return 0, err
	}
	return len(wire), nil
}
