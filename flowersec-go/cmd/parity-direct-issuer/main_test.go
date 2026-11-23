package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

func testOptions(t *testing.T, extra ...string) options {
	t.Helper()
	root := t.TempDir()
	args := []string{"-approval-dir", filepath.Join(root, "approvals"), "-invitation-dir", filepath.Join(root, "invitations"),
		"-url", "wss://example.com/flowersec/v5/direct", "-tls", "ca"}
	options, err := parseOptions(append(args, extra...), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return options
}

func roleFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	path := filepath.Join(dir, name)
	dirInfo, err := os.Lstat(dir)
	if err != nil || dirInfo.Mode().Perm() != 0700 {
		t.Fatal("role directory is not private")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("role file is not private")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestResidentIssuance(t *testing.T) {
	for _, mode := range []string{"ca", "pin"} {
		t.Run(mode, func(t *testing.T) {
			var extra = []string{"-max-inbound", "9", "-idle", "180s", "-ttl", "5m", "-group", "group-a", "-audience", "server-a", "-upstream", "127.0.0.1:42"}
			withRecord := mode == "pin"
			if withRecord {
				extra = append(extra, "-tls", mode, "-pin-sha256", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
					"-pin-not-after", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10), "-record-dir", filepath.Join(t.TempDir(), "records"))
			}
			options := testOptions(t, extra...)
			var output bytes.Buffer
			start := time.Now().Unix()
			if err := serve(options, strings.NewReader("{\"channel_id\":\"p123\"}\n{\"channel_id\":\"p124\"}\n"), &output); err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(&output)
			var lastKey string
			for _, channel := range []string{"p123", "p124"} {
				var fields map[string]string
				if err := decoder.Decode(&fields); err != nil {
					t.Fatal("missing receipt")
				}
				name, key := channel+".json", fields["lookup_key"]
				if fields["channel_id"] != channel || fields["approval_ref"] != name || fields["invitation_ref"] != name || len(key) != 43 || key == lastKey {
					t.Fatal("wrong receipt identifiers or references")
				}
				lastKey = key
				approval := roleFile(t, options.dirs.approval, name)
				if !bytes.Equal(approval, roleFile(t, options.dirs.invitation, name)) || !isDirectV5(approval, channel) {
					t.Fatal("role artifacts do not match the issued Direct v5 channel")
				}
				var wire struct {
					Session struct {
						MaxInbound int   `json:"max_inbound_streams"`
						Idle       int   `json:"idle_timeout_seconds"`
						Expiry     int64 `json:"init_expire_at_unix_s"`
					} `json:"session"`
					Path struct {
						Group      string `json:"rendezvous_group_id"`
						Audience   string `json:"listener_audience"`
						Candidates []struct {
							URL string `json:"url"`
							TLS struct {
								Mode string `json:"mode"`
							} `json:"tls"`
						} `json:"candidates"`
					} `json:"path"`
				}
				if json.Unmarshal(approval, &wire) != nil || wire.Session.MaxInbound != 9 || wire.Session.Idle != 180 || wire.Session.Expiry < start+300 || wire.Session.Expiry > time.Now().Unix()+300 ||
					wire.Path.Group != "group-a" || wire.Path.Audience != "server-a" || len(wire.Path.Candidates) != 1 || wire.Path.Candidates[0].URL != "wss://example.com/flowersec/v5/direct" || wire.Path.Candidates[0].TLS.Mode != mode {
					t.Fatal("issued workload settings do not match requested settings")
				}
				if withRecord {
					if len(fields) != 5 || fields["record_ref"] != key+".json" {
						t.Fatal("unexpected record receipt fields")
					}
					encoded := roleFile(t, options.dirs.record, fields["record_ref"])
					record, err := controlplane.ParseAuthorizationRecord(encoded)
					if err != nil || record.LookupKey() != key {
						t.Fatal("record cannot be loaded by its lookup key")
					}
					var stored struct {
						Artifact string `json:"artifact_base64url"`
						Upstream string `json:"direct_upstream"`
					}
					if json.Unmarshal(encoded, &stored) != nil || stored.Artifact != base64.RawURLEncoding.EncodeToString(approval) || stored.Upstream != "127.0.0.1:42" {
						t.Fatal("record does not carry the matching artifact and upstream")
					}
				} else if len(fields) != 4 {
					t.Fatal("unexpected fields without record storage")
				}
			}
			if decoder.Decode(new(json.RawMessage)) != io.EOF {
				t.Fatal("unexpected additional output")
			}
		})
	}
}

func TestPartialPublicationCannotReissue(t *testing.T) {
	options := testOptions(t, "-record-dir", filepath.Join(t.TempDir(), "records"))
	if err := options.dirs.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(options.dirs.invitation); err != nil {
		t.Fatal(err)
	}
	if _, err := options.issue(controlplane.NewIssuer(), "p123"); err == nil {
		t.Fatal("expected invitation publication failure")
	}
	approval := roleFile(t, options.dirs.approval, "p123.json")
	var output bytes.Buffer
	if err := serve(options, strings.NewReader(`{"channel_id":"p123"}`), &output); err == nil || output.Len() != 0 {
		t.Fatal("retry succeeded or emitted a receipt")
	}
	parts, err := os.ReadDir(options.dirs.record)
	if err != nil || len(parts) != 1 || !bytes.Equal(approval, roleFile(t, options.dirs.approval, "p123.json")) {
		t.Fatal("retry changed server-side material")
	}
	if _, err := os.Lstat(filepath.Join(options.dirs.invitation, "p123.json")); !os.IsNotExist(err) {
		t.Fatal("partial issuance exposed a client invitation")
	}
}

func TestDuplicateAfterConsumptionAndNoOverwrite(t *testing.T) {
	options := testOptions(t)
	one := `{"channel_id":"p123"}`
	if err := serve(options, strings.NewReader(one), io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{options.dirs.approval, options.dirs.invitation} {
		original := roleFile(t, dir, "p123.json")
		if err := publish(dir, "p123.json", []byte("replacement")); err == nil || !bytes.Equal(original, roleFile(t, dir, "p123.json")) {
			t.Fatal("publication replaced a role file")
		}
		if err := os.Remove(filepath.Join(dir, "p123.json")); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := serve(options, strings.NewReader(one), &output); err == nil || output.Len() != 0 {
		t.Fatal("consumed channel was issued again")
	}
}

func TestFailClosedBoundaries(t *testing.T) {
	for _, line := range []string{`{"channel_id":"p1","channel_id":"p2"}`, `{"channel_id":"../p"}`, `{"channel_id":"p"} {}`, `{"channel_id":"p","key":"value"}`} {
		if _, err := parseChannel([]byte(line)); err == nil {
			t.Fatal("malformed request accepted")
		}
	}
	for _, pair := range []string{`"v":3,"profile":"flowersec/5"`, `"v":5,"profile":"flowersec/3"`} {
		if isDirectV5([]byte(`{`+pair+`,"session":{"channel_id":"p"},"path":{"kind":"direct"}}`), "p") {
			t.Fatal("wrong wire version or profile accepted")
		}
	}
	for _, extra := range [][]string{nil, {"-tls", "pin"}, {"-tls", "ca", "-pin-sha256", "bad"}} {
		args := []string{"-url", "wss://example.com/flowersec/v5/direct", "-approval-dir", "a", "-invitation-dir", "i"}
		if _, err := parseOptions(append(args, extra...), io.Discard); err == nil {
			t.Fatal("incomplete or contradictory TLS policy accepted")
		}
	}
	options := testOptions(t)
	if err := os.Mkdir(options.dirs.approval, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(options.dirs.approval, 0755); err != nil {
		t.Fatal(err)
	}
	if err := options.dirs.prepare(); err == nil {
		t.Fatal("public approval directory accepted")
	}
}
