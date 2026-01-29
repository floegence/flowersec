package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type config struct {
	Listen string `json:"listen"`
	Origin string `json:"origin"`
	Routes []struct {
		Host            string `json:"host"`
		GrantClientFile string `json:"grant_client_file"`
	} `json:"routes"`
}

func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("config too large")
	}
	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Listen) == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	cfg.Origin = strings.TrimSpace(cfg.Origin)
	if cfg.Origin == "" {
		return nil, errors.New("missing origin in config")
	}
	originURL, err := url.Parse(cfg.Origin)
	if err != nil || originURL == nil {
		if err == nil {
			err = errors.New("invalid url")
		}
		return nil, fmt.Errorf("invalid origin: %w", err)
	}
	switch originURL.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("invalid origin scheme: %q", originURL.Scheme)
	}
	if originURL.Host == "" {
		return nil, errors.New("invalid origin: missing host")
	}
	if originURL.Path != "" && originURL.Path != "/" {
		return nil, errors.New("invalid origin: path must be empty")
	}
	if originURL.RawQuery != "" || originURL.Fragment != "" {
		return nil, errors.New("invalid origin: query/fragment not allowed")
	}
	originURL.Path = ""
	cfg.Origin = originURL.String()

	if len(cfg.Routes) == 0 {
		return nil, errors.New("missing routes in config")
	}
	seenHosts := make(map[string]struct{}, len(cfg.Routes))
	for i := range cfg.Routes {
		h := strings.ToLower(strings.TrimSpace(cfg.Routes[i].Host))
		if h == "" {
			return nil, errors.New("route host must be non-empty")
		}
		if strings.ContainsAny(h, " \t\r\n") || strings.Contains(h, "/") || strings.Contains(h, "://") {
			return nil, fmt.Errorf("invalid route host: %q", cfg.Routes[i].Host)
		}
		if _, dup := seenHosts[h]; dup {
			return nil, fmt.Errorf("duplicate route host: %q", h)
		}
		seenHosts[h] = struct{}{}
		cfg.Routes[i].Host = h

		f := strings.TrimSpace(cfg.Routes[i].GrantClientFile)
		if f == "" {
			return nil, fmt.Errorf("route %q missing grant_client_file", h)
		}
		cfg.Routes[i].GrantClientFile = f
	}
	return &cfg, nil
}
