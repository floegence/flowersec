package interopharness

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// BrowserRuntimeObservation is emitted by the actual TS browser host after
// navigation. It describes a runtime; it supplies no roots or qualification.
type BrowserRuntimeObservation struct {
	SchemaVersion int    `json:"schema_version"`
	RuntimeID     string `json:"runtime_id"`
	Origin        string `json:"origin"`
	Engine        string `json:"engine"`
	Version       string `json:"version"`
	UserAgent     string `json:"userAgent"`
}

// BrowserRunnerInstallationOwner belongs to the original deployment. Material
// issuance calls InstallOriginal before making acquisition/capacity bytes public.
// Startup opens only independently provisioned history; it never recreates it.
type BrowserRunnerInstallationOwner struct {
	mu                             sync.Mutex
	ManifestPath, HistoryDirectory string
	identity                       string
	maximum                        uint32
	records                        map[string]map[string]any
}

// ProvisionBrowserRunnerInstallation explicitly creates a fresh host history
// and empty installation file. The TS provisioning API uses exclusive creation
// and an independent SQLite journal with WAL and FULL synchronization. A restart
// must open its existing installation instead of invoking this provisioning API.
func ProvisionBrowserRunnerInstallation(ctx context.Context, node, sourceRoot, manifestPath, historyDirectory string, maximum uint32) (*BrowserRunnerInstallationOwner, error) {
	if ctx == nil || node == "" || !filepath.IsAbs(sourceRoot) || !filepath.IsAbs(manifestPath) || !filepath.IsAbs(historyDirectory) || maximum == 0 || maximum > 4096 || filepath.Clean(manifestPath) == filepath.Join(filepath.Clean(historyDirectory), "browser-history.sqlite") {
		return nil, errors.New("complete original browser installation paths and capacity are required")
	}
	if _, err := os.Lstat(manifestPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return nil, errors.New("browser installation already exists")
		}
		return nil, err
	}
	var identity [32]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return nil, err
	}
	defer clear(identity[:])
	identityHex := hex.EncodeToString(identity[:])
	payload, err := json.Marshal(struct{ Module, History, Identity string }{filepath.Join(sourceRoot, "flowersec-ts", "scripts", "browser-runner-installation.mjs"), historyDirectory, identityHex})
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	// The program is fixed; paths and identity enter through JSON stdin, never
	// executable shell interpolation or an acquired material projection.
	const program = `import {pathToFileURL} from 'node:url';let body='';for await(const part of process.stdin)body+=part;const q=JSON.parse(body);const m=await import(pathToFileURL(q.Module).href);await m.provisionBrowserRunnerHistory(q.History,q.Identity);`
	command := exec.CommandContext(ctx, node, "--input-type=module", "--eval", program)
	command.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err = command.Run(); err != nil {
		return nil, errors.Join(err, errors.New("explicit browser host history provisioning failed"))
	}
	owner := &BrowserRunnerInstallationOwner{ManifestPath: manifestPath, HistoryDirectory: historyDirectory, identity: identityHex, maximum: maximum, records: make(map[string]map[string]any, maximum)}
	wire, err := owner.manifest()
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	file, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err = writeBrowserInstallationFile(file, wire); err != nil {
		return nil, err
	}
	if err = syncBrowserInstallationDirectory(filepath.Dir(manifestPath)); err != nil {
		return nil, err
	}
	return owner, nil
}

// ObserveRuntime waits for this provisioned run's actual origin, version and UA.
// Callers must check them against their original native deployment policy before
// passing any declaration to InstallOriginal. Observation alone is not policy.
func (p *BrowserRunnerInstallationOwner) ObserveRuntime(ctx context.Context) (BrowserRuntimeObservation, error) {
	if p == nil || ctx == nil {
		return BrowserRuntimeObservation{}, errors.New("original browser installation owner is required")
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		file, err := os.Open(filepath.Join(p.HistoryDirectory, "browser-runtime.json"))
		if err == nil {
			wire, readErr := io.ReadAll(io.LimitReader(file, 65537))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil {
				return BrowserRuntimeObservation{}, errors.Join(readErr, closeErr)
			}
			if len(wire) == 0 || len(wire) > 65536 {
				clear(wire)
				return BrowserRuntimeObservation{}, errors.New("browser runtime observation exceeds its bound")
			}
			var observation BrowserRuntimeObservation
			decoder := json.NewDecoder(bytes.NewReader(wire))
			decoder.DisallowUnknownFields()
			decodeErr := decoder.Decode(&observation)
			var trailing any
			if decodeErr == nil && decoder.Decode(&trailing) != io.EOF {
				decodeErr = errors.New("trailing browser runtime observation")
			}
			clear(wire)
			origin, originErr := url.Parse(observation.Origin)
			runtimeID, idErr := hex.DecodeString(observation.RuntimeID)
			if decodeErr != nil || originErr != nil || origin.Scheme != "http" && origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || observation.SchemaVersion != 1 || idErr != nil || len(runtimeID) != 32 || hex.EncodeToString(runtimeID) != observation.RuntimeID || observation.Engine == "" || observation.Version == "" || observation.UserAgent == "" || len(observation.UserAgent) > 4096 {
				clear(runtimeID)
				return BrowserRuntimeObservation{}, errors.New("invalid original browser runtime observation")
			}
			clear(runtimeID)
			return observation, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return BrowserRuntimeObservation{}, err
		}
		select {
		case <-ctx.Done():
			return BrowserRuntimeObservation{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

// InstallOriginal copies retained original keys, root pins and TLS input before
// publication. Declaration contains independently installed application policy,
// actual native qualification, resource bounds and the current service target.
// This method deliberately supplies no default policy or qualification tuple.
func (p *BrowserRunnerInstallationOwner) InstallOriginal(ctx context.Context, wire string, original Material, trustPEM, originalOrigin string, observation BrowserRuntimeObservation, declaration map[string]any) error {
	if p == nil || ctx == nil || declaration == nil {
		return errors.New("original browser source installation is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	canonical, err := original.JSON()
	if err != nil {
		return err
	}
	if canonical != wire || original.Role != 0 || original.Source != "preauthorized_pool" || trustPEM == "" || len(trustPEM) > 1048576 || originalOrigin != observation.Origin {
		return errors.New("original browser source differs from its bound runtime installation")
	}
	if len(original.Tunnels) != 0 {
		configured, ok := declaration["pool_server_allow"]
		if !ok {
			return errors.New("original browser tunnel installation requires its pool server Allow policy")
		}
		encoded, err := json.Marshal(configured)
		if err != nil {
			return err
		}
		defer clear(encoded)
		if len(encoded) == 0 || len(encoded) > 1048576 {
			return errors.New("original browser pool server Allow installation exceeds its bound")
		}
		var allow BrowserPoolServerAllowInstallation
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&allow); err != nil {
			return err
		}
		if _, err := browserPoolServerAllowInstallation(&allow.Installation, &allow.Binding); err != nil {
			return err
		}
		decoderMap, err := protocolv4.NewDecoder(65536, 4096)
		if err != nil {
			return err
		}
		parent, err := decoderMap.DecodeMap(original.Artifact, "Artifact", protocolv4.DecodeContext{})
		if err != nil {
			return err
		}
		tenant, tenantOK := parent.Root().Named("Artifact", "tenant_id").Text()
		audience, audienceOK := parent.Root().Named("Artifact", "audience").Text()
		parent.Release()
		if !tenantOK || !audienceOK || tenant != allow.Installation.Tenant || audience != allow.Installation.Audience {
			return errors.New("original browser pool Allow installation differs from its retained parent")
		}
	}
	// Clone only the original host declaration. No acquisition bytes can select
	// its policy, store authority, transport qualification or resource geometry.
	template, err := json.Marshal(declaration)
	if err != nil {
		return err
	}
	defer clear(template)
	if len(template) == 0 || len(template) > 1048576 {
		return errors.New("browser source declaration exceeds its bound")
	}
	record := make(map[string]any)
	if err = json.Unmarshal(template, &record); err != nil {
		return err
	}
	deployment, ok := record["deployment"].(map[string]any)
	if !ok || deployment["applicationOrigin"] != originalOrigin {
		return errors.New("browser native declaration must bind the exact observed original origin")
	}
	if record["carrier"] == "webtransport" && deployment["userAgent"] != observation.UserAgent {
		return errors.New("WebTransport declaration differs from the observed browser UA")
	}
	if record["carrier"] != "wss" && record["carrier"] != "webtransport" {
		return errors.New("unsupported original browser carrier installation")
	}
	for _, field := range []string{"spend_authority", "issuer_key_id", "policy", "limits", "resource_limit", "tenant_id", "profile_revision", "service_namespace", "service_query_type", "service_query_digest", "service_schema_digest", "server_identity_digest", "max_message_bytes", "max_streams", "carrier_runtime_bytes", "provider_runtime_bytes", "provider_stream_bytes"} {
		if record[field] == nil {
			return errors.New("original browser source declaration is incomplete: " + field)
		}
	}
	limits, limitsOK := record["limits"].(map[string]any)
	resources, resourcesOK := record["resource_limit"].([]any)
	if !limitsOK || limits["maxGeneralOutstanding"] == nil || !resourcesOK || len(resources) != 11 {
		return errors.New("original browser resource declaration must include all dimensions and general outstanding capacity")
	}
	digest := sha256.Sum256([]byte(wire))
	key := hex.EncodeToString(digest[:])
	namespaces := append([]NamespaceRecord(nil), original.Namespaces...)
	for index := range namespaces {
		namespaces[index].RootKeyID = append([]byte(nil), namespaces[index].RootKeyID...)
		namespaces[index].RootPublicKey = append([]byte(nil), namespaces[index].RootPublicKey...)
	}
	record["material_sha256"] = key
	record["runtime_id"] = observation.RuntimeID
	record["identity_seed"] = append([]byte(nil), original.IdentitySeed...)
	record["dh_seed"] = append([]byte(nil), original.DHSeed...)
	record["namespaces"] = namespaces
	record["trust_pem"] = trustPEM
	record["application_origin"] = originalOrigin
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.records[key]; exists || len(p.records) >= int(p.maximum) {
		return errors.New("original browser installation position is already used or exhausted")
	}
	p.records[key] = record
	body, err := p.manifest()
	if err != nil {
		delete(p.records, key)
		return err
	}
	defer clear(body)
	if err = ctx.Err(); err != nil {
		delete(p.records, key)
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(p.ManifestPath), ".browser-installation-*")
	if err != nil {
		delete(p.records, key)
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err = temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		delete(p.records, key)
		return err
	}
	if err = writeBrowserInstallationFile(temporary, body); err != nil {
		delete(p.records, key)
		return err
	}
	if err = os.Rename(name, p.ManifestPath); err != nil {
		delete(p.records, key)
		return err
	}
	// Once rename occurred, even a sync failure permanently consumes this local
	// publication position; the caller must fail without delivering the material.
	return syncBrowserInstallationDirectory(filepath.Dir(p.ManifestPath))
}
func (p *BrowserRunnerInstallationOwner) manifest() ([]byte, error) {
	wire, err := json.Marshal(struct {
		SchemaVersion   int                       `json:"schema_version"`
		HistoryIdentity string                    `json:"history_identity"`
		Installations   map[string]map[string]any `json:"installations"`
	}{1, p.identity, p.records})
	if err != nil {
		return nil, err
	}
	if len(wire) > 16<<20 {
		clear(wire)
		return nil, errors.New("browser installation manifest exceeds its bound")
	}
	return wire, nil
}
func writeBrowserInstallationFile(file *os.File, wire []byte) error {
	n, err := file.Write(wire)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}
func syncBrowserInstallationDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
