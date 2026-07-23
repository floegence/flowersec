package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Printf("flowersec-runtime: %v", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("flowersec-runtime", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "path to the runtime JSON configuration")
	showVersion := flags.Bool("version", false, "print build version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *showVersion {
		_, err := fmt.Printf("flowersec-runtime %s (%s, %s)\n", version, commit, date)
		return err
	}
	if *configPath == "" {
		return &ConfigError{Field: "config", Err: errors.New("-config is required")}
	}
	config, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	authorizer, err := newHTTPAuthorizationProvider(config.Authorization)
	if err != nil {
		return err
	}
	runtime, err := newRuntimeServer(config, authorizer, log.Default())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runtime.Serve(ctx)
}
