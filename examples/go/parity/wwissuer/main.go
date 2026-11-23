package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	cp "github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

type request struct {
	Stage   string `json:"stage"`
	Channel string `json:"channel_id"`
}
type receipt struct {
	Stage   string `json:"stage"`
	Channel string `json:"channel_id"`
	Ref     string `json:"ref,omitempty"`
	Error   string `json:"error,omitempty"`
}
type installed struct {
	Channel string `json:"channel_id"`
	Key     string `json:"lookup_key"`
	Digest  string `json:"artifact_sha256"`
}
type waiting struct {
	first        cp.IssuedArtifact
	registration installed
}

type publicationPosition struct {
	mu      sync.Mutex
	issued  issuedGeneration
	pending *waiting
}

func confirmRegistration(directory string, want installed) error {
	file, err := os.Open(filepath.Join(directory, "approvals", want.Channel+".json"))
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 512 {
		return errors.New("invalid B registration")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 513))
	var ack installed
	if err != nil || json.Unmarshal(raw, &ack) != nil || ack != want {
		return errors.New("B registration does not confirm the issued invitation")
	}
	return nil
}

func publish(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if err = errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	if err = os.Link(f.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(dir)
}
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
func saveRecord(records string, artifact cp.IssuedArtifact) error {
	r := artifact.AuthorizationRecord()
	wire, err := r.Encode()
	if err != nil {
		return err
	}
	defer clear(wire)
	return publish(records, r.LookupKey()+".json", wire)
}
func run() error {
	var firstURL, secondURL, directory string
	flag.StringVar(&firstURL, "a", "", "first local ingress")
	flag.StringVar(&secondURL, "b", "", "second local ingress")
	flag.StringVar(&directory, "deployment", "", "private deployment directory")
	generations := flag.Bool("allow-generations", false, "allow consecutive replacements after both prior legs are released")
	overlap := flag.Bool("overlap-successors", false, "issue up to four independent second generations while their originals remain admitted")
	flag.Parse()
	if !filepath.IsAbs(directory) || flag.NArg() != 0 || *overlap && !*generations {
		return errors.New("private deployment required")
	}
	for _, name := range []string{"", "invitations", "records", "approvals"} {
		st, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || !st.IsDir() || st.Mode().Perm()&077 != 0 {
			return errors.New("private deployment directories required")
		}
	}
	first, err := cp.NewEndpointSet(cp.EndpointConfig{ID: "entry-a", URL: firstURL, TLS: cp.CAPolicy()})
	if err != nil {
		return err
	}
	second, err := cp.NewEndpointSet(cp.EndpointConfig{ID: "entry-b", URL: secondURL, TLS: cp.CAPolicy()})
	if err != nil {
		return err
	}
	const positions = 1000
	var publications [positions]publicationPosition
	var group sync.WaitGroup
	slots := make(chan struct{}, 8)
	successors := make(chan struct{}, 4)
	var output sync.Mutex
	var firstErr error
	operation := func(q request) (string, error) {
		index, generation, err := generationPosition(q.Channel, *generations)
		if err != nil {
			return "", errors.New("invalid channel")
		}
		position := &publications[index]
		dir := filepath.Join(directory, "invitations", q.Channel)
		records := filepath.Join(directory, "records")
		switch q.Stage {
		case "install_b":
			position.mu.Lock()
			if !position.issued.permits(directory, generation, *overlap) {
				position.mu.Unlock()
				return "", errors.New("duplicate or late B registration")
			}
			if *overlap && generation > 1 {
				select {
				case successors <- struct{}{}:
				default:
					position.mu.Unlock()
					return "", errors.New("all four successor positions have been claimed")
				}
			}
			position.issued = issuedGeneration{number: generation}
			position.mu.Unlock()
			pair, err := cp.NewIssuer().IssueTunnelPair(cp.TunnelIssueOptions{Session: cp.SessionOptions{ChannelID: q.Channel, ExpiresAt: time.Now().Add(2 * time.Minute)}, FirstEndpoints: first, SecondEndpoints: second, RendezvousGroupID: q.Channel, ListenerAudience: "parity", FirstEndpointID: "first", SecondEndpointID: "second"})
			if err != nil {
				return "", err
			}
			if err = os.Mkdir(dir, 0700); err != nil {
				return "", err
			}
			if err = saveRecord(records, pair.Second); err != nil {
				return "", err
			}
			wire := pair.Second.ArtifactJSON()
			defer clear(wire)
			digest := sha256.Sum256(wire)
			if err = publish(dir, "second.json", wire); err != nil {
				return "", err
			}
			if err = syncDir(filepath.Dir(dir)); err != nil {
				return "", err
			}
			position.mu.Lock()
			position.pending = &waiting{pair.First, installed{q.Channel, pair.Second.LookupKey(), base64.RawURLEncoding.EncodeToString(digest[:])}}
			if *generations {
				position.issued.keys = [2]string{pair.First.LookupKey(), pair.Second.LookupKey()}
			}
			position.mu.Unlock()
			return q.Channel + "/second.json", nil
		case "publish_a":
			position.mu.Lock()
			pair := position.pending
			position.mu.Unlock()
			if pair == nil || pair.registration.Channel != q.Channel {
				return "", errors.New("no pending A invitation for channel")
			}
			if err = confirmRegistration(directory, pair.registration); err != nil {
				return "", err
			}
			position.mu.Lock()
			if position.pending != pair {
				position.mu.Unlock()
				return "", errors.New("A invitation already claimed")
			}
			position.pending = nil
			position.mu.Unlock()
			if err = saveRecord(records, pair.first); err != nil {
				return "", err
			}
			wire := pair.first.ArtifactJSON()
			defer clear(wire)
			if err = publish(dir, "first.json", wire); err != nil {
				return "", err
			}
			if *generations {
				position.mu.Lock()
				position.issued.published = true
				position.mu.Unlock()
			}
			return q.Channel + "/first.json", nil
		default:
			return "", errors.New("unknown publication stage")
		}
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 512), 4096)
	encoder := json.NewEncoder(os.Stdout)
	for scan.Scan() {
		var q request
		if err = json.Unmarshal(scan.Bytes(), &q); err != nil {
			break
		}
		slots <- struct{}{}
		group.Add(1)
		go func(q request) {
			defer group.Done()
			defer func() { <-slots }()
			ref, err := operation(q)
			response := receipt{Stage: q.Stage, Channel: q.Channel, Ref: ref}
			output.Lock()
			defer output.Unlock()
			if err != nil {
				response.Error = err.Error()
			}
			if e := encoder.Encode(response); e != nil {
				firstErr = errors.Join(firstErr, e)
			}
		}(q)
	}
	group.Wait()
	return errors.Join(err, scan.Err(), firstErr)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
