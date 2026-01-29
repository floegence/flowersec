package proxy

import (
	"errors"
	"net/url"
	"strings"
)

func parseRequestPath(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("missing path")
	}
	if !strings.HasPrefix(raw, "/") {
		return nil, errors.New("path must start with /")
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return nil, errors.New("path contains whitespace")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return nil, err
	}
	// Reject absolute-form targets.
	if u.Scheme != "" || u.Host != "" {
		return nil, errors.New("path must not include scheme/host")
	}
	// url.ParseRequestURI may treat a path like "//x" as Path="//x"; reject to avoid ambiguity.
	if strings.HasPrefix(u.Path, "//") {
		return nil, errors.New("path must not start with //")
	}
	u.Fragment = ""
	return u, nil
}
