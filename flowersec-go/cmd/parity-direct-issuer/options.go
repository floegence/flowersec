package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"math"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

type options struct {
	dirs   directories
	direct controlplane.DirectIssueOptions
	ttl    time.Duration
}

func parseOptions(args []string, help io.Writer) (options, error) {
	var config options
	flags := flag.NewFlagSet("parity-direct-issuer", flag.ContinueOnError)
	flags.SetOutput(help)
	flags.StringVar(&config.dirs.record, "record-dir", "", "optional private directory for authorization records")
	flags.StringVar(&config.dirs.approval, "approval-dir", "", "private directory for server approvals (required)")
	flags.StringVar(&config.dirs.invitation, "invitation-dir", "", "private directory for client invitations (required)")
	endpoint := flags.String("url", "", "Direct WSS, QUIC, or HTTPS carrier URL (required)")
	endpointID := flags.String("endpoint-id", "parity", "carrier candidate ID")
	tlsMode := flags.String("tls", "", "explicit TLS policy: ca or pin (required)")
	pinHash := flags.String("pin-sha256", "", "leaf DER SHA-256, unpadded base64url (pin mode)")
	pinEnd := flags.Int64("pin-not-after", 0, "pin expiry in Unix seconds (pin mode)")
	flags.StringVar(&config.direct.ListenerAudience, "audience", "server-parity", "listener audience")
	flags.StringVar(&config.direct.RendezvousGroupID, "group", "cross-language-direct-parity", "rendezvous group ID")
	flags.StringVar(&config.direct.UpstreamAddress, "upstream", "127.0.0.1:1", "application upstream host:port")
	flags.DurationVar(&config.ttl, "ttl", time.Minute, "artifact admission lifetime (1s to 5m in whole seconds)")
	flags.DurationVar(&config.direct.Session.IdleTimeout, "idle", time.Minute, "session idle timeout in whole seconds")
	maxInbound := flags.Uint("max-inbound", 16, "maximum inbound streams per session (1 to 128)")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 || config.dirs.invitation == "" || config.dirs.approval == "" || *endpoint == "" {
		return options{}, errors.New("require -url, -approval-dir and -invitation-dir; no positional arguments")
	}
	idle := config.direct.Session.IdleTimeout
	if config.ttl < time.Second || config.ttl > 5*time.Minute || config.ttl%time.Second != 0 ||
		idle < time.Second || idle%time.Second != 0 || idle/time.Second > math.MaxUint32 || *maxInbound == 0 || *maxInbound > 128 {
		return options{}, errors.New("invalid -ttl, -idle or -max-inbound; see -help for limits")
	}
	config.direct.Session.MaxInboundStreams = uint16(*maxInbound)
	var policy controlplane.TLSPolicy
	switch *tlsMode {
	case "ca":
		if *pinHash != "" || *pinEnd != 0 {
			return options{}, errors.New("ca policy cannot include a pin")
		}
		policy = controlplane.CAPolicy()
	case "pin":
		digest, err := base64.RawURLEncoding.Strict().DecodeString(*pinHash)
		if err != nil || len(digest) != sha256.Size || base64.RawURLEncoding.EncodeToString(digest) != *pinHash || *pinEnd <= time.Now().Unix() {
			return options{}, errors.New("pin policy requires -pin-sha256 and a future -pin-not-after")
		}
		policy, err = controlplane.PinPolicy(controlplane.CertificatePin{SHA256: [sha256.Size]byte(digest), NotAfter: time.Unix(*pinEnd, 0)})
		if err != nil {
			return options{}, errors.New("invalid certificate pin policy")
		}
	default:
		return options{}, errors.New("explicit -tls ca or -tls pin is required")
	}
	endpoints, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{ID: *endpointID, URL: *endpoint, TLS: policy})
	if err != nil {
		return options{}, errors.New("invalid endpoint configuration")
	}
	config.direct.Endpoints = endpoints
	return config, nil
}
