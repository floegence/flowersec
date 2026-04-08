package proxy

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestProxyDoc_CoversStableHeaderPolicies(t *testing.T) {
	doc := readProxyDoc(t)

	var tokens []string
	tokens = append(tokens, mapKeys(defaultRequestHeaderAllowlist)...)
	tokens = append(tokens, mapKeys(defaultResponseHeaderAllowlist)...)
	tokens = append(tokens, mapKeys(defaultWSHeaderAllowlist)...)
	tokens = append(tokens, "cookie")
	sort.Strings(tokens)

	var missing []string
	for _, token := range tokens {
		if !strings.Contains(doc, "`"+token+"`") {
			missing = append(missing, token)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("docs/PROXY.md missing stable header policy tokens: %v", missing)
	}
}

func TestProxyDoc_CoversStableReasonTokens(t *testing.T) {
	doc := readProxyDoc(t)
	httpTokens := extractSwitchCaseTokens(t, "bridge_http.go", "proxyHTTPErrorToStatus")
	wsTokens := extractSwitchCaseTokens(t, "bridge_ws.go", "proxyWSErrorToStatus")

	var missing []string
	for _, token := range append(httpTokens, wsTokens...) {
		if !strings.Contains(doc, "`"+token+"`") {
			missing = append(missing, token)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("docs/PROXY.md missing stable reason tokens: %v", missing)
	}
}

func TestProxyHTTPErrorToStatus_StableMappings(t *testing.T) {
	tests := []struct {
		code       string
		wantStatus int
		wantMsg    string
	}{
		{code: "request_body_too_large", wantStatus: http.StatusRequestEntityTooLarge, wantMsg: "request body too large"},
		{code: "timeout", wantStatus: http.StatusGatewayTimeout, wantMsg: "upstream request timed out"},
		{code: "response_body_too_large", wantStatus: http.StatusBadGateway, wantMsg: "upstream response too large"},
		{code: "invalid_request_meta", wantStatus: http.StatusBadGateway, wantMsg: "upstream request invalid"},
		{code: "request_body_invalid", wantStatus: http.StatusBadGateway, wantMsg: "upstream request invalid"},
		{code: "upstream_dial_failed", wantStatus: http.StatusBadGateway, wantMsg: "upstream request failed"},
		{code: "upstream_request_failed", wantStatus: http.StatusBadGateway, wantMsg: "upstream request failed"},
		{code: "canceled", wantStatus: http.StatusBadGateway, wantMsg: "upstream request failed"},
		{code: "unknown", wantStatus: http.StatusBadGateway, wantMsg: "upstream request failed"},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			gotStatus, gotMsg := proxyHTTPErrorToStatus(tt.code)
			if gotStatus != tt.wantStatus || gotMsg != tt.wantMsg {
				t.Fatalf("proxyHTTPErrorToStatus(%q) = (%d, %q), want (%d, %q)", tt.code, gotStatus, gotMsg, tt.wantStatus, tt.wantMsg)
			}
		})
	}
}

func TestValidateHTTPResponseMeta_EnforcesStableContract(t *testing.T) {
	valid := HTTPResponseMeta{
		V:         ProtocolVersion,
		RequestID: "req-1",
		OK:        true,
		Status:    http.StatusOK,
	}
	if err := validateHTTPResponseMeta(valid, "req-1"); err != nil {
		t.Fatalf("validateHTTPResponseMeta(valid) = %v", err)
	}

	tests := []struct {
		name string
		meta HTTPResponseMeta
		want string
	}{
		{
			name: "bad version",
			meta: HTTPResponseMeta{V: 99, RequestID: "req-1", OK: true, Status: http.StatusOK},
			want: "unsupported v",
		},
		{
			name: "missing request id",
			meta: HTTPResponseMeta{V: ProtocolVersion, OK: true, Status: http.StatusOK},
			want: "missing request_id",
		},
		{
			name: "request id mismatch",
			meta: HTTPResponseMeta{V: ProtocolVersion, RequestID: "other", OK: true, Status: http.StatusOK},
			want: "request_id mismatch",
		},
		{
			name: "bad success status",
			meta: HTTPResponseMeta{V: ProtocolVersion, RequestID: "req-1", OK: true, Status: 0},
			want: "invalid status",
		},
		{
			name: "missing error",
			meta: HTTPResponseMeta{V: ProtocolVersion, RequestID: "req-1", OK: false},
			want: "missing error",
		},
		{
			name: "missing error code",
			meta: HTTPResponseMeta{V: ProtocolVersion, RequestID: "req-1", OK: false, Error: &Error{Message: "boom"}},
			want: "missing error code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHTTPResponseMeta(tt.meta, "req-1")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateHTTPResponseMeta(%s) error = %v, want substring %q", tt.name, err, tt.want)
			}
		})
	}
}

func TestProxyWSErrorToStatus_StableMappings(t *testing.T) {
	tests := []struct {
		code       string
		wantStatus int
		wantMsg    string
	}{
		{code: "timeout", wantStatus: http.StatusGatewayTimeout, wantMsg: "upstream ws open timed out"},
		{code: "upstream_ws_rejected", wantStatus: http.StatusBadGateway, wantMsg: "upstream ws open failed"},
		{code: "upstream_ws_dial_failed", wantStatus: http.StatusBadGateway, wantMsg: "upstream ws open failed"},
		{code: "canceled", wantStatus: http.StatusBadGateway, wantMsg: "upstream ws open failed"},
		{code: "invalid_ws_open_meta", wantStatus: http.StatusBadGateway, wantMsg: "upstream ws open invalid"},
		{code: "unknown", wantStatus: http.StatusBadGateway, wantMsg: "upstream ws open failed"},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			gotStatus, gotMsg := proxyWSErrorToStatus(tt.code)
			if gotStatus != tt.wantStatus || gotMsg != tt.wantMsg {
				t.Fatalf("proxyWSErrorToStatus(%q) = (%d, %q), want (%d, %q)", tt.code, gotStatus, gotMsg, tt.wantStatus, tt.wantMsg)
			}
		})
	}
}

func TestValidateWSOpenResp_EnforcesStableContract(t *testing.T) {
	valid := WSOpenResp{
		V:      ProtocolVersion,
		ConnID: "conn-1",
		OK:     true,
	}
	if err := validateWSOpenResp(valid, "conn-1"); err != nil {
		t.Fatalf("validateWSOpenResp(valid) = %v", err)
	}

	tests := []struct {
		name string
		resp WSOpenResp
		want string
	}{
		{
			name: "bad version",
			resp: WSOpenResp{V: 99, ConnID: "conn-1", OK: true},
			want: "unsupported version",
		},
		{
			name: "missing conn id",
			resp: WSOpenResp{V: ProtocolVersion, OK: true},
			want: "missing conn_id",
		},
		{
			name: "conn id mismatch",
			resp: WSOpenResp{V: ProtocolVersion, ConnID: "other", OK: true},
			want: "conn_id mismatch",
		},
		{
			name: "missing error",
			resp: WSOpenResp{V: ProtocolVersion, ConnID: "conn-1", OK: false},
			want: "missing error",
		},
		{
			name: "missing error code",
			resp: WSOpenResp{V: ProtocolVersion, ConnID: "conn-1", OK: false, Error: &Error{Message: "boom"}},
			want: "missing error code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWSOpenResp(tt.resp, "conn-1")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateWSOpenResp(%s) error = %v, want substring %q", tt.name, err, tt.want)
			}
		})
	}
}

func TestNormalizeHeaderNameSet_NormalizesAndRejectsInvalidNames(t *testing.T) {
	got, err := normalizeHeaderNameSet([]string{" Content-Type ", "x-demo", "content-type"})
	if err != nil {
		t.Fatalf("normalizeHeaderNameSet(valid) = %v", err)
	}
	want := map[string]struct{}{
		"content-type": {},
		"x-demo":       {},
	}
	if len(got) != len(want) {
		t.Fatalf("normalizeHeaderNameSet(valid) size = %d, want %d", len(got), len(want))
	}
	for key := range want {
		if _, ok := got[key]; !ok {
			t.Fatalf("normalizeHeaderNameSet(valid) missing %q", key)
		}
	}

	for _, tc := range []struct {
		name  string
		input []string
	}{
		{name: "empty", input: []string{"  "}},
		{name: "invalid rune", input: []string{"bad header"}},
		{name: "embedded newline", input: []string{"x-\n-test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := normalizeHeaderNameSet(tc.input); err == nil {
				t.Fatalf("normalizeHeaderNameSet(%v) expected error", tc.input)
			}
		})
	}
}

func readProxyDoc(t *testing.T) string {
	t.Helper()
	path := filepath.Join(repoRootFromPackage(t), "docs", "PROXY.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read PROXY.md: %v", err)
	}
	return string(b)
}

func repoRootFromPackage(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func extractSwitchCaseTokens(t *testing.T, fileName string, funcName string) []string {
	t.Helper()
	path := filepath.Join(filepath.Dir(packageFilePath(t)), fileName)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", fileName, err)
	}
	src := string(b)
	start := strings.Index(src, "func "+funcName+"(")
	if start < 0 {
		t.Fatalf("function %s not found in %s", funcName, fileName)
	}
	block := src[start:]
	if next := strings.Index(block[1:], "\nfunc "); next >= 0 {
		block = block[:next+1]
	}

	caseRe := regexp.MustCompile(`case\s+([^:]+):`)
	tokenRe := regexp.MustCompile(`"([^"]+)"`)
	seen := map[string]struct{}{}
	var out []string
	for _, match := range caseRe.FindAllStringSubmatch(block, -1) {
		for _, tokenMatch := range tokenRe.FindAllStringSubmatch(match[1], -1) {
			token := tokenMatch[1]
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			out = append(out, token)
		}
	}
	sort.Strings(out)
	return out
}

func packageFilePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return thisFile
}
