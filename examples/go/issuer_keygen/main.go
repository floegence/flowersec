package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/floegence/flowersec/controlplane/issuer"
)

// issuer_keygen generates a tunnel issuer keyset file (kid -> ed25519 pubkey) for local testing.
//
// Notes:
//   - For the end-to-end scenarios in examples/README.md, you typically don't need this:
//     examples/go/controlplane_demo writes the keyset file automatically.
//   - Keep the generated file private if you also store the signing key material (this tool exports the public keyset
//     used by the tunnel; the signer keypair lives in-process in the controlplane demo).
func main() {
	var kid string
	var out string
	flag.StringVar(&kid, "kid", "k1", "issuer key id (kid)")
	flag.StringVar(&out, "out", "", "output file (default: stdout)")
	flag.Parse()

	ks, err := issuer.NewRandom(kid)
	if err != nil {
		log.Fatal(err)
	}
	b, err := ks.ExportTunnelKeyset()
	if err != nil {
		log.Fatal(err)
	}

	if out == "" {
		_, _ = os.Stdout.Write(b)
		if len(b) == 0 || b[len(b)-1] != '\n' {
			_, _ = fmt.Fprintln(os.Stdout)
		}
		return
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}
