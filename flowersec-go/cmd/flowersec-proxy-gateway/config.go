package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultListenAddr       = "127.0.0.1:0"
	maxConfigBytes          = 1 << 20
	defaultGrantExecTimeout = 10 * time.Second
)

type config struct {
	Listen string        `json:"listen"`
	Origin string        `json:"origin"`
	Routes []routeConfig `json:"routes"`
}

type routeConfig struct {
	Host  string            `json:"host"`
	Grant grantSourceConfig `json:"grant"`
}

type grantSourceConfig struct {
	File      string   `json:"file,omitempty"`
	Command   []string `json:"command,omitempty"`
	TimeoutMS int      `json:"timeout_ms,omitempty"`
}

func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfigBytes {
		return nil, errors.New("config too large")
	}

	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Listen) == "" {
		cfg.Listen = defaultListenAddr
	}

	origin, err := normalizeOrigin(cfg.Origin)
	if err != nil {
		return nil, err
	}
	cfg.Origin = origin

	if len(cfg.Routes) == 0 {
		return nil, errors.New("missing routes in config")
	}
	seenHosts := make(map[string]struct{}, len(cfg.Routes))
	for i := range cfg.Routes {
		host, err := canonicalHostKey(cfg.Routes[i].Host)
		if err != nil {
			return nil, fmt.Errorf("invalid route host %q: %w", cfg.Routes[i].Host, err)
		}
		if _, dup := seenHosts[host]; dup {
			return nil, fmt.Errorf("duplicate route host after canonicalization: %q", host)
		}
		seenHosts[host] = struct{}{}
		cfg.Routes[i].Host = host
		if err := cfg.Routes[i].Grant.normalize(); err != nil {
			return nil, fmt.Errorf("route %q invalid grant source: %w", host, err)
		}
	}

	return &cfg, nil
}

func normalizeOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("missing origin in config")
	}
	originURL, err := url.Parse(raw)
	if err != nil || originURL == nil {
		if err == nil {
			err = errors.New("invalid url")
		}
		return "", fmt.Errorf("invalid origin: %w", err)
	}
	switch originURL.Scheme {
	case "http", "https":
	default:
		return "", fmt.Errorf("invalid origin scheme: %q", originURL.Scheme)
	}
	if originURL.Host == "" {
		return "", errors.New("invalid origin: missing host")
	}
	if originURL.Path != "" && originURL.Path != "/" {
		return "", errors.New("invalid origin: path must be empty")
	}
	if originURL.RawQuery != "" || originURL.Fragment != "" {
		return "", errors.New("invalid origin: query/fragment not allowed")
	}
	originURL.Path = ""
	return originURL.String(), nil
}

func canonicalHostKey(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("host must be non-empty")
	}
	if strings.Contains(raw, "://") || strings.ContainsAny(raw, "/?#") {
		return "", errors.New("host must not include scheme or path")
	}
	parsed, err := url.Parse("//" + raw)
	if err != nil {
		return "", err
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return "", errors.New("missing host")
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return "", errors.New("host contains whitespace")
	}
	return host, nil
}

func (cfg *grantSourceConfig) normalize() error {
	cfg.File = strings.TrimSpace(cfg.File)
	if cfg.TimeoutMS < 0 {
		return errors.New("timeout_ms must be >= 0")
	}
	if len(cfg.Command) > 0 {
		trimmed := make([]string, 0, len(cfg.Command))
		for _, part := range cfg.Command {
			part = strings.TrimSpace(part)
			if part == "" {
				return errors.New("command entries must be non-empty")
			}
			trimmed = append(trimmed, part)
		}
		cfg.Command = trimmed
	}
	if cfg.File == "" && len(cfg.Command) == 0 {
		return errors.New("grant source must set either file or command")
	}
	if cfg.File != "" && len(cfg.Command) > 0 {
		return errors.New("grant source must not set both file and command")
	}
	return nil
}

func (cfg grantSourceConfig) timeout() time.Duration {
	if cfg.TimeoutMS > 0 {
		return time.Duration(cfg.TimeoutMS) * time.Millisecond
	}
	return defaultGrantExecTimeout
}
