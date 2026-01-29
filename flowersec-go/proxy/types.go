package proxy

// Header is the lossless header representation used by flowersec-proxy meta messages.
//
// See docs/PROXY.md.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Error is the structured error used in flowersec-proxy response meta messages.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// HTTPRequestMeta is the JSON meta message for KindHTTP1 (client -> server).
type HTTPRequestMeta struct {
	V         int      `json:"v"`
	RequestID string   `json:"request_id"`
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Headers   []Header `json:"headers"`
	TimeoutMS int64    `json:"timeout_ms,omitempty"`
}

// HTTPResponseMeta is the JSON meta message for KindHTTP1 (server -> client).
type HTTPResponseMeta struct {
	V         int      `json:"v"`
	RequestID string   `json:"request_id"`
	OK        bool     `json:"ok"`
	Status    int      `json:"status,omitempty"`
	Headers   []Header `json:"headers,omitempty"`
	Error     *Error   `json:"error,omitempty"`
}

// WSOpenMeta is the JSON meta message for KindWS (client -> server).
type WSOpenMeta struct {
	V       int      `json:"v"`
	ConnID  string   `json:"conn_id"`
	Path    string   `json:"path"`
	Headers []Header `json:"headers"`
}

// WSOpenResp is the JSON meta message for KindWS (server -> client).
type WSOpenResp struct {
	V        int    `json:"v"`
	ConnID   string `json:"conn_id"`
	OK       bool   `json:"ok"`
	Protocol string `json:"protocol,omitempty"`
	Error    *Error `json:"error,omitempty"`
}
