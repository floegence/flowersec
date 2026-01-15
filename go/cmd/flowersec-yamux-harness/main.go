package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/flowersec/flowersec/internal/yamuxinterop"
	hyamux "github.com/hashicorp/yamux"
)

func main() {
	var scenarioJSON string
	flag.StringVar(&scenarioJSON, "scenario", "", "scenario JSON payload")
	flag.Parse()

	if scenarioJSON == "" {
		log.Fatal("missing -scenario")
	}
	var scenario yamuxinterop.Scenario
	if err := json.Unmarshal([]byte(scenarioJSON), &scenario); err != nil {
		log.Fatal(err)
	}
	if err := scenario.Normalize(); err != nil {
		log.Fatal(err)
	}

	// This harness only accepts client-initiated streams.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	ready := map[string]any{
		"tcp_addr": ln.Addr().String(),
	}
	if err := json.NewEncoder(os.Stdout).Encode(ready); err != nil {
		log.Fatal(err)
	}

	conn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	cfg := hyamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.LogOutput = io.Discard
	if scenario.Scenario == yamuxinterop.ScenarioRstMidWriteGo {
		cfg.StreamCloseTimeout = 50 * time.Millisecond
	}
	sess, err := hyamux.Server(conn, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(scenario.DeadlineMs)*time.Millisecond)
	defer cancel()

	result, err := yamuxinterop.RunServer(ctx, sess, scenario)
	out := map[string]any{
		"result": result,
	}
	if err != nil {
		out["error"] = err.Error()
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		log.Fatal(err)
	}
}
