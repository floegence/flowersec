package controlv4

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// The HTTPS owner-proof request is an application envelope, not a new protocol
// credential. uint64 values are canonical decimal strings; fixed binary values
// use padded canonical base64. No field, duplicate key or trailing value is
// ignored. The original issuer recomputes the registered immutable digest.
func parsePoolOwnerProofJSON(wire []byte) (protocolv4.TopUpRequestFacts, error) {
	var request protocolv4.TopUpRequestFacts
	if len(wire) == 0 || len(wire) > 4096 {
		return request, ledgerv4.ErrDenied
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return request, ledgerv4.ErrDenied
	}
	names := [11]string{"wire_revision", "tenant_id", "source_incarnation", "operation_id", "request_digest", "binding_generation", "pool_digest", "client_identity_digest", "request_deadline_ms", "desired_count", "max_item_bytes"}
	var seen uint16
	decimal := func(value any, stringValue bool) (uint64, error) {
		var text string
		if stringValue {
			var ok bool
			text, ok = value.(string)
			if !ok {
				return 0, ledgerv4.ErrDenied
			}
		} else {
			number, ok := value.(json.Number)
			if !ok {
				return 0, ledgerv4.ErrDenied
			}
			text = number.String()
		}
		number, err := strconv.ParseUint(text, 10, 64)
		if err != nil || strconv.FormatUint(number, 10) != text {
			return 0, ledgerv4.ErrDenied
		}
		return number, nil
	}
	binary := func(value any, dst []byte) error {
		text, ok := value.(string)
		if !ok || len(text) != base64.StdEncoding.EncodedLen(len(dst)) {
			return ledgerv4.ErrDenied
		}
		n, err := base64.StdEncoding.Strict().Decode(dst, []byte(text))
		if err != nil || n != len(dst) || base64.StdEncoding.EncodeToString(dst) != text {
			return ledgerv4.ErrDenied
		}
		return nil
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return request, ledgerv4.ErrDenied
		}
		name, ok := token.(string)
		if !ok {
			return request, ledgerv4.ErrDenied
		}
		index := -1
		for i, item := range names {
			if name == item {
				index = i
				break
			}
		}
		if index < 0 || seen&(1<<index) != 0 {
			return request, ledgerv4.ErrDenied
		}
		seen |= 1 << index
		value, err := decoder.Token()
		if err != nil {
			return request, ledgerv4.ErrDenied
		}
		switch index {
		case 0:
			revision, e := decimal(value, false)
			if e != nil || revision != 4 {
				return request, ledgerv4.ErrDenied
			}
		case 1:
			tenant, ok := value.(string)
			if !ok || len(tenant) == 0 || len(tenant) > 128 {
				return request, ledgerv4.ErrDenied
			}
			request.Tenant = tenant
		case 2:
			err = binary(value, request.Source[:])
		case 3:
			err = binary(value, request.Operation[:])
		case 4:
			err = binary(value, request.Digest[:])
		case 5:
			request.Generation, err = decimal(value, true)
		case 6:
			err = binary(value, request.Pool[:])
		case 7:
			err = binary(value, request.Identity[:])
		case 8:
			request.DeadlineMS, err = decimal(value, true)
		case 9:
			count, e := decimal(value, false)
			if e != nil || count == 0 || count > 4 {
				return request, ledgerv4.ErrDenied
			}
			request.DesiredCount = uint32(count)
		case 10:
			size, e := decimal(value, false)
			if e != nil || size == 0 || size > 65536 {
				return request, ledgerv4.ErrDenied
			}
			request.MaxItemBytes = uint32(size)
		}
		if err != nil {
			return request, err
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || seen != (1<<len(names))-1 {
		return request, ledgerv4.ErrDenied
	}
	if _, err = decoder.Token(); err != io.EOF {
		return request, ledgerv4.ErrDenied
	}
	return request, nil
}
