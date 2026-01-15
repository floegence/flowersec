package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/flowersec/flowersec/controlplane/issuer"
)

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
