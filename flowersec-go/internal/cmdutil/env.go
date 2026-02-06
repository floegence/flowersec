package cmdutil

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// EnvString returns the trimmed env value if present; otherwise it returns fallback.
func EnvString(key string, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// EnvBool parses a boolean env value; when unset or blank, it returns fallback.
func EnvBool(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, err
	}
	return v, nil
}

// EnvInt parses an integer env value; when unset or blank, it returns fallback.
func EnvInt(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	return v, nil
}

// EnvInt64 parses an int64 env value; when unset or blank, it returns fallback.
func EnvInt64(key string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	return v, nil
}

// EnvDuration parses a time.Duration env value; when unset or blank, it returns fallback.
func EnvDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	return d, nil
}

// SplitCSVEnv splits a comma-separated env value into trimmed parts.
func SplitCSVEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}
