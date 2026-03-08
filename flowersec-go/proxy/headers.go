package proxy

import (
	"errors"
	"net/http"
	"strings"
)

var (
	defaultRequestHeaderAllowlist = map[string]struct{}{
		"accept":              {},
		"accept-language":     {},
		"cache-control":       {},
		"content-type":        {},
		"if-match":            {},
		"if-modified-since":   {},
		"if-none-match":       {},
		"if-unmodified-since": {},
		"pragma":              {},
		"range":               {},
		"x-requested-with":    {},
		// "cookie" is special-cased (runtime CookieJar only).
	}
	defaultResponseHeaderAllowlist = map[string]struct{}{
		"cache-control":       {},
		"content-disposition": {},
		"content-encoding":    {},
		"content-language":    {},
		"content-type":        {},
		"etag":                {},
		"expires":             {},
		"last-modified":       {},
		"location":            {},
		"pragma":              {},
		"set-cookie":          {},
		"vary":                {},
		"www-authenticate":    {},
	}
	defaultWSHeaderAllowlist = map[string]struct{}{
		"sec-websocket-protocol": {},
	}
)

func normalizeHeaderNameSet(names []string) (map[string]struct{}, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			return nil, errors.New("empty header name")
		}
		if !isValidHeaderName(n) {
			return nil, errors.New("invalid header name")
		}
		out[n] = struct{}{}
	}
	return out, nil
}

func isValidHeaderName(n string) bool {
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func isSafeHeaderValue(v string) bool {
	return !strings.ContainsAny(v, "\r\n")
}

func allowRequestHeader(name string, extra map[string]struct{}) bool {
	if _, ok := defaultRequestHeaderAllowlist[name]; ok {
		return true
	}
	if extra != nil {
		_, ok := extra[name]
		return ok
	}
	return false
}

func allowResponseHeader(name string, extra map[string]struct{}) bool {
	if _, ok := defaultResponseHeaderAllowlist[name]; ok {
		return true
	}
	if extra != nil {
		_, ok := extra[name]
		return ok
	}
	return false
}

func allowWSHeader(name string, extra map[string]struct{}) bool {
	if _, ok := defaultWSHeaderAllowlist[name]; ok {
		return true
	}
	if extra != nil {
		_, ok := extra[name]
		return ok
	}
	return false
}

func filterRequestHeaders(in []Header, cfg *compiledHeaderPolicy) http.Header {
	h := make(http.Header, len(in))
	for _, p := range in {
		name := strings.ToLower(strings.TrimSpace(p.Name))
		if name == "" || !isValidHeaderName(name) {
			continue
		}
		switch name {
		case "host", "authorization":
			continue
		}
		if !allowRequestHeader(name, cfg.extraReqHeaders) && name != "cookie" {
			continue
		}
		if !isSafeHeaderValue(p.Value) {
			continue
		}
		if name == "cookie" {
			v := filterCookieHeaderValue(p.Value, cfg)
			if v == "" {
				continue
			}
			h.Add("Cookie", v)
			continue
		}
		h.Add(http.CanonicalHeaderKey(name), p.Value)
	}
	return h
}

func filterResponseHeaders(in http.Header, cfg *compiledHeaderPolicy) []Header {
	var out []Header
	for k, vv := range in {
		name := strings.ToLower(strings.TrimSpace(k))
		if name == "" || !isValidHeaderName(name) {
			continue
		}
		if !allowResponseHeader(name, cfg.extraRespHeaders) {
			continue
		}
		for _, v := range vv {
			if !isSafeHeaderValue(v) {
				continue
			}
			out = append(out, Header{Name: name, Value: v})
		}
	}
	return out
}

func filterWSOpenHeaders(in []Header, cfg *compiledHeaderPolicy) http.Header {
	h := make(http.Header, len(in))
	for _, p := range in {
		name := strings.ToLower(strings.TrimSpace(p.Name))
		if name == "" || !isValidHeaderName(name) {
			continue
		}
		if name == "cookie" {
			if !isSafeHeaderValue(p.Value) {
				continue
			}
			v := filterCookieHeaderValue(p.Value, cfg)
			if v == "" {
				continue
			}
			h.Add("Cookie", v)
			continue
		}
		if !allowWSHeader(name, cfg.extraWSHeaders) {
			continue
		}
		if !isSafeHeaderValue(p.Value) {
			continue
		}
		h.Add(http.CanonicalHeaderKey(name), p.Value)
	}
	return h
}

func filterCookieHeaderValue(v string, cfg *compiledHeaderPolicy) string {
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ";")
	var kept []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		name, _, ok := strings.Cut(p, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || name == "" {
			continue
		}
		if _, forbidden := cfg.forbiddenCookieNames[name]; forbidden {
			continue
		}
		for _, pref := range cfg.forbiddenCookieNamePrefixes {
			if strings.HasPrefix(name, pref) {
				name = ""
				break
			}
		}
		if name == "" {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) == 0 {
		return ""
	}
	return strings.Join(kept, "; ")
}

func requestMetaHeadersFromHTTPHeader(in http.Header, cfg *compiledHeaderPolicy) []Header {
	out := make([]Header, 0, len(in))
	for k, vv := range in {
		name := strings.ToLower(strings.TrimSpace(k))
		if name == "" || !isValidHeaderName(name) {
			continue
		}
		switch name {
		case "host", "authorization":
			continue
		}
		if !allowRequestHeader(name, cfg.extraReqHeaders) && name != "cookie" {
			continue
		}
		for _, v := range vv {
			if !isSafeHeaderValue(v) {
				continue
			}
			if name == "cookie" {
				v = filterCookieHeaderValue(v, cfg)
				if v == "" {
					continue
				}
			}
			out = append(out, Header{Name: name, Value: v})
		}
	}
	return out
}

func wsOpenMetaHeadersFromHTTPHeader(in http.Header, cfg *compiledHeaderPolicy) []Header {
	out := make([]Header, 0, len(in))
	for k, vv := range in {
		name := strings.ToLower(strings.TrimSpace(k))
		if name == "" || !isValidHeaderName(name) {
			continue
		}
		if !allowWSHeader(name, cfg.extraWSHeaders) && name != "cookie" {
			continue
		}
		for _, v := range vv {
			if !isSafeHeaderValue(v) {
				continue
			}
			if name == "cookie" {
				v = filterCookieHeaderValue(v, cfg)
				if v == "" {
					continue
				}
			}
			out = append(out, Header{Name: name, Value: v})
		}
	}
	return out
}

func responseHeadersFromMeta(in []Header, cfg *compiledHeaderPolicy) http.Header {
	out := make(http.Header, len(in))
	for _, p := range in {
		name := strings.ToLower(strings.TrimSpace(p.Name))
		if name == "" || !isValidHeaderName(name) {
			continue
		}
		if !allowResponseHeader(name, cfg.extraRespHeaders) {
			continue
		}
		if !isSafeHeaderValue(p.Value) {
			continue
		}
		out.Add(http.CanonicalHeaderKey(name), p.Value)
	}
	return out
}
