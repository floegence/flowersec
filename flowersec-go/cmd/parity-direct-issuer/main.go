package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

var registryID = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)

type receipt struct {
	ChannelID     string `json:"channel_id"`
	LookupKey     string `json:"lookup_key"`
	RecordRef     string `json:"record_ref,omitempty"`
	ApprovalRef   string `json:"approval_ref"`
	InvitationRef string `json:"invitation_ref"`
}

func main() {
	options, err := parseOptions(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err == nil {
		var stop func() error
		stop, err = startCapacityMetrics()
		if err == nil {
			err = errors.Join(serve(options, os.Stdin, os.Stdout), stop())
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "parity-direct-issuer:", err)
		os.Exit(1)
	}
}

func serve(options options, input io.Reader, output io.Writer) error {
	if err := options.dirs.prepare(); err != nil {
		return err
	}
	issuer := controlplane.NewIssuer()
	requests := bufio.NewScanner(input)
	requests.Buffer(make([]byte, 4096), 4096)
	replies := json.NewEncoder(output)
	for line := 1; requests.Scan(); line++ {
		channel, err := parseChannel(requests.Bytes())
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		reply, err := options.issue(issuer, channel)
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if err := replies.Encode(reply); err != nil {
			return errors.New("could not write receipt; do not retry this channel")
		}
	}
	if requests.Err() != nil {
		return errors.New("could not read request (maximum line length: 4095 bytes)")
	}
	return nil
}

func parseChannel(line []byte) (string, error) {
	invalid := errors.New(`expected one JSON object with only a valid "channel_id"`)
	decoder := json.NewDecoder(bytes.NewReader(line))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return "", invalid
	}
	field, err := decoder.Token()
	if err != nil || field != "channel_id" {
		return "", invalid
	}
	var channel string
	if err := decoder.Decode(&channel); err != nil || !registryID.MatchString(channel) {
		return "", invalid
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return "", invalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return "", invalid
	}
	return channel, nil
}

func (options options) issue(issuer *controlplane.Issuer, channel string) (receipt, error) {
	name := channel + ".json"
	if err := options.dirs.reserve(name); err != nil {
		return receipt{}, err
	}
	direct := options.direct
	direct.Session.ChannelID = channel
	direct.Session.ExpiresAt = time.Now().Add(options.ttl).Truncate(time.Second)
	issued, err := issuer.IssueDirect(direct)
	if err != nil {
		return receipt{}, errors.New("production Direct issuance failed")
	}
	artifact := issued.ArtifactJSON()
	if !isDirectV5(artifact, channel) {
		return receipt{}, errors.New("issued artifact is not flowersec/5 Direct for the requested channel")
	}
	reply := receipt{ChannelID: channel, LookupKey: issued.LookupKey(), ApprovalRef: name, InvitationRef: name}
	if options.dirs.record != "" {
		reply.RecordRef = reply.LookupKey + ".json"
		record, err := issued.AuthorizationRecord().Encode()
		if err != nil {
			return receipt{}, errors.New("could not encode authorization record")
		}
		if err := publish(options.dirs.record, reply.RecordRef, record); err != nil {
			return receipt{}, fmt.Errorf("publish record: %w", err)
		}
	}
	if err := publish(options.dirs.approval, name, artifact); err != nil {
		return receipt{}, fmt.Errorf("publish approval: %w", err)
	}
	if err := publish(options.dirs.invitation, name, artifact); err != nil {
		return receipt{}, fmt.Errorf("publish invitation: %w", err)
	}
	return reply, nil
}

func isDirectV5(artifact []byte, channel string) bool {
	var header struct {
		Version int    `json:"v"`
		Profile string `json:"profile"`
		Session struct {
			ChannelID string `json:"channel_id"`
		} `json:"session"`
		Path struct {
			Kind string `json:"kind"`
		} `json:"path"`
	}
	return json.Unmarshal(artifact, &header) == nil && header.Version == 5 && header.Profile == "flowersec/5" &&
		header.Path.Kind == "direct" && header.Session.ChannelID == channel
}
