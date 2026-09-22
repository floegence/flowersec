// Package tlspolicy verifies the signed network TLS policy at the original
// native TLS callback. It creates no connection, retry, task or trust source.
package tlspolicy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrPolicy = errors.New("tlspolicy: invalid original TLS policy")
var ErrCertificate = errors.New("tlspolicy: certificate does not satisfy original policy")

const CertificateProfile = "x509v3-p256-14d"
const maxCertificateLifetimeMS = 14 * 86400 * 1000
const MaxPins = 16

// Pin is an issuer projection of actual DER. Its fields are private so an
// issuer must call PinFromDER instead of asserting a fabricated short lifetime.
type Pin struct {
	digest              [32]byte
	notBefore, notAfter uint64
}

func (p Pin) Digest() [32]byte           { return p.digest }
func (p Pin) Validity() (uint64, uint64) { return p.notBefore, p.notAfter }

// Policy is an immutable detached value. Its enclosing provider owner admits
// this backing before Capture; shared certificate roots remain independently
// admitted immutable dependencies. A policy is not signature/trust evidence.
type Policy struct {
	mode            uint64
	requireConsumer bool
	pins            [MaxPins]Pin
	count           uint8
}

func (p Policy) RequiresRoots() bool { return p.mode == 0 }

// Prepared retains the exact original active pin set. Native TLS identifies
// the actual matching member, which Verification then keeps through claim.
type Prepared struct {
	policy Policy
	active [MaxPins]uint8
	count  uint8
}

// Verification contains only the exact observed peer's validity intersection.
// It is not a TLS-completion or activation token. The enclosing original
// carrier must observe successful TLS Finished before publishing preparation.
type Verification struct {
	notBefore, notAfter uint64
	valid               bool
}

func BackingBytes() uint64 {
	return uint64(unsafe.Sizeof(Prepared{})) + uint64(unsafe.Sizeof(Verification{}))
}

func (v Verification) Check(now timev4.Interval) error {
	if !v.valid || now.LowerMS > now.UpperMS || !now.ValidBefore(v.notAfter) {
		return ErrCertificate
	}
	return now.LowerBound(v.notBefore, false)
}

func certificateValidity(c *x509.Certificate) (uint64, uint64, error) {
	if c == nil || c.NotBefore.Before(time.UnixMilli(0)) || c.NotAfter.After(time.UnixMilli(math.MaxInt64)) {
		return 0, 0, ErrCertificate
	}
	start, end := c.NotBefore.UnixMilli(), c.NotAfter.UnixMilli()
	if start < 0 || end <= start {
		return 0, 0, ErrCertificate
	}
	return uint64(start), uint64(end), nil
}

// CheckCertificateTime checks the actual certificate over the complete trusted
// interval. It grants no CA, pin, hostname or application identity authority.
func CheckCertificateTime(c *x509.Certificate, now timev4.Interval) error {
	start, end, err := certificateValidity(c)
	if err != nil {
		return err
	}
	return (Verification{notBefore: start, notAfter: end, valid: true}).Check(now)
}

func pinCertificate(c *x509.Certificate) (uint64, uint64, error) {
	start, end, err := certificateValidity(c)
	if err != nil || c.Version != 3 || end-start > maxCertificateLifetimeMS || len(c.UnhandledCriticalExtensions) != 0 {
		return 0, 0, ErrCertificate
	}
	key, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) ||
		c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return 0, 0, ErrCertificate
	}
	if len(c.ExtKeyUsage)+len(c.UnknownExtKeyUsage) != 0 {
		server := false
		for _, usage := range c.ExtKeyUsage {
			server = server || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
		}
		if !server {
			return 0, 0, ErrCertificate
		}
	}
	return start, end, nil
}

// PinFromDER derives the complete leaf digest and checks its full certificate
// profile, current validity and exact signed subwindow. No CA or hostname/SAN
// authorization is inferred or added to the pin mode.
func PinFromDER(der []byte, notBefore, notAfter uint64, now timev4.Interval) (Pin, error) {
	if len(der) == 0 || len(der) > 65536 || notBefore >= notAfter {
		return Pin{}, ErrCertificate
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return Pin{}, ErrCertificate
	}
	start, end, err := pinCertificate(certificate)
	if err != nil || notBefore < start || notAfter > end {
		return Pin{}, ErrCertificate
	}
	// Issuance may authorize a future rotation window within a currently
	// valid certificate. Prepare decides which signed entries are active.
	if err = (Verification{notBefore: start, notAfter: end, valid: true}).Check(now); err != nil {
		return Pin{}, err
	}
	return Pin{digest: sha256.Sum256(der), notBefore: notBefore, notAfter: notAfter}, nil
}

// Capture reads an already decoded canonical TLSPolicy from its original
// signed route. It repeats the closed union and ordering checks, preserving
// exact bytes32 DER identities and finite authorization windows by value.
func Capture(value protocolv4.Value) (Policy, error) {
	var p Policy
	var ok bool
	p.mode, ok = value.Named("TLSPolicy", "mode").Uint()
	if !ok || p.mode > 1 {
		return p, ErrPolicy
	}
	p.requireConsumer, ok = value.Named("TLSPolicy", "require_consumer_tls13_verification").Bool()
	if !ok {
		return Policy{}, ErrPolicy
	}
	fields := value.Named("TLSPolicy", "pins")
	kind := value.Named("TLSPolicy", "pin_kind")
	if p.mode == 0 {
		if fields.Encoded() != nil || kind.Encoded() != nil {
			return Policy{}, ErrPolicy
		}
		return p, nil
	}
	pinKind, ok := kind.Uint()
	if !ok || pinKind != 0 || fields.Len() < 1 || fields.Len() > MaxPins {
		return Policy{}, ErrPolicy
	}
	for index := range fields.Len() {
		field := fields.Index(index)
		digest, ok := field.Named("TLSPin", "leaf_der_sha256").ByteString()
		if !ok || len(digest) != 32 {
			return Policy{}, ErrPolicy
		}
		start, startOK := field.Named("TLSPin", "not_before_ms").Uint()
		end, endOK := field.Named("TLSPin", "not_after_ms").Uint()
		profile, profileOK := field.Named("TLSPin", "certificate_profile").Text()
		if !startOK || !endOK || start >= end || !profileOK || profile != CertificateProfile || index > 0 && bytes.Compare(p.pins[index-1].digest[:], digest) >= 0 {
			return Policy{}, ErrPolicy
		}
		p.pins[index] = Pin{digest: [32]byte(digest), notBefore: start, notAfter: end}
	}
	p.count = uint8(fields.Len())
	return p, nil
}

func (p Policy) Prepare(now timev4.Interval) (Prepared, error) {
	result := Prepared{policy: p}
	if now.LowerMS > now.UpperMS || p.mode > 1 || p.mode == 1 && p.count == 0 {
		return Prepared{}, ErrPolicy
	}
	if p.mode == 0 {
		return result, nil
	}
	pending := false
	for i := range p.count {
		pin := p.pins[i]
		if !now.ValidBefore(pin.notAfter) {
			continue
		}
		if err := now.LowerBound(pin.notBefore, false); err != nil {
			pending = true
			continue
		}
		result.active[result.count] = i
		result.count++
	}
	if result.count == 0 {
		if pending {
			return Prepared{}, timev4.ErrPending
		}
		return Prepared{}, ErrCertificate
	}
	return result, nil
}

func (p *Prepared) Verify(state tls.ConnectionState, host string, roots *x509.CertPool, now timev4.Interval) (Verification, error) {
	if p == nil || state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 16 || state.PeerCertificates[0] == nil || now.LowerMS > now.UpperMS || now.UpperMS > math.MaxInt64 {
		return Verification{}, ErrCertificate
	}
	if p.policy.mode == 1 {
		certificate := state.PeerCertificates[0]
		start, end, err := pinCertificate(certificate)
		if err != nil {
			return Verification{}, err
		}
		digest := sha256.Sum256(certificate.Raw)
		for _, index := range p.active[:p.count] {
			pin := p.policy.pins[index]
			if digest != pin.digest {
				continue
			}
			if pin.notBefore < start || pin.notAfter > end {
				return Verification{}, ErrCertificate
			}
			v := Verification{notBefore: pin.notBefore, notAfter: pin.notAfter, valid: true}
			return v, v.Check(now)
		}
		return Verification{}, ErrCertificate
	}
	if p.policy.mode != 0 || roots == nil || host == "" {
		return Verification{}, ErrPolicy
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		if certificate == nil {
			return Verification{}, ErrCertificate
		}
		intermediates.AddCert(certificate)
	}
	chains, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates, CurrentTime: time.UnixMilli(int64(now.UpperMS)), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return Verification{}, ErrCertificate
	}
	for _, chain := range chains {
		v := Verification{notAfter: math.MaxUint64, valid: true}
		for _, certificate := range chain {
			start, end, err := certificateValidity(certificate)
			if err != nil {
				v.valid = false
				break
			}
			v.notBefore, v.notAfter = max(v.notBefore, start), min(v.notAfter, end)
		}
		if v.Check(now) == nil {
			return v, nil
		}
	}
	return Verification{}, ErrCertificate
}
