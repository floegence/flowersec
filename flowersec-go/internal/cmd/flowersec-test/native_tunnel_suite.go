package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
)

// The test owns its independent original source installation until the real TS
// native process and all callbacks exit. It never imports a peer's Grants into
// relay authority or supplies a passing native qualification declaration.
func nativeTunnelEntry(id string) registeredTest {
	return registeredTest{ID: id, Suite: "acceptance", Timeout: 10 * time.Minute, Run: func(ctx context.Context, run runContext) (err error) {
		base := filepath.Dir(run.ResultPath)
		absolute, e := filepath.Abs(base)
		if e != nil {
			return e
		}
		root, e := filepath.Abs(run.Root)
		if e != nil {
			return e
		}
		for _, forbidden := range []string{root, os.TempDir(), "/tmp", "/private/tmp"} {
			relative, e := filepath.Rel(forbidden, absolute)
			if e == nil && relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				return errors.New("native suite installation must be outside repository and temporary roots")
			}
		}
		directory, e := os.MkdirTemp(absolute, "native-tunnel-")
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, os.Remove(directory)) }()
		installation, e := interopharness.PrepareNativeTunnelInstallation(ctx, directory, "https://client.example")
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, installation.Close()) }()
		return runCommand(ctx, run.Root, []string{"FLOWERSEC_NATIVE_TUNNEL_INSTALLATION=" + installation.Path()}, "node", "scripts/server-parity-native-addon.mjs", "--test-title", "pairs raw QUIC tunnel roles through original registered B and releases active-pair quota")
	}}
}
