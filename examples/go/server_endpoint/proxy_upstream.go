package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func proxyUpstreamOriginFromAttachOrigin(origin string) string {
	// The tunnel attach Origin allow-list supports values like "null". WebSocket dials to a local upstream
	// should still use a real http(s) origin string, so fall back to a safe default.
	origin = strings.TrimSpace(origin)
	u, err := url.Parse(origin)
	if err == nil && u != nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.RawQuery == "" && u.Fragment == "" {
		if u.Path == "" || u.Path == "/" {
			u.Path = ""
			return u.String()
		}
	}
	return "http://127.0.0.1"
}

func startProxyDemoUpstream(ctx context.Context, logger *log.Logger) (baseURL string, stop func(), err error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Flowersec Proxy Upstream Demo</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
      pre { background: #0b1020; color: #e8e8e8; padding: 12px; border-radius: 8px; overflow: auto; }
      button { padding: 8px 12px; margin-right: 8px; }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    </style>
  </head>
  <body>
    <h1>Flowersec Proxy Upstream Demo</h1>
    <p>This page is served from a local upstream HTTP server and fetched through <span class="mono">flowersec-proxy/http1</span>.</p>
    <p>WebSocket uses an absolute <span class="mono">ws://host/ws</span> URL and is rewritten to <span class="mono">flowersec-proxy/ws</span> by the injected patch.</p>

    <p>
      <button id="cookie">Set Cookie (proxied)</button>
      <button id="check">Check Cookie (proxied)</button>
      <button id="ws">Connect WebSocket (proxied)</button>
      <button id="send">Send WS Message</button>
    </p>

    <pre id="log"></pre>

    <script type="module">
      const $log = document.getElementById("log");
      function log(s) { $log.textContent += s + "\n"; }

      document.getElementById("cookie").addEventListener("click", async () => {
        const resp = await fetch("./api/set-cookie", { method: "POST" });
        log("set-cookie status=" + resp.status + " body=" + (await resp.text()));
      });

      document.getElementById("check").addEventListener("click", async () => {
        const resp = await fetch("./api/echo-cookie");
        log("echo-cookie status=" + resp.status + " body=" + (await resp.text()));
      });

      let ws = null;
      document.getElementById("ws").addEventListener("click", () => {
        const scheme = location.protocol === "https:" ? "wss" : "ws";
        const url = scheme + "://" + location.host + "/ws";
        ws = new WebSocket(url);
        ws.onopen = () => log("ws open: " + url);
        ws.onmessage = (ev) => log("ws message: " + String(ev.data));
        ws.onerror = (ev) => log("ws error");
        ws.onclose = (ev) => log("ws close: code=" + ev.code + " reason=" + ev.reason);
      });

      document.getElementById("send").addEventListener("click", () => {
        if (!ws) { log("ws not connected"); return; }
        ws.send("hello from browser " + Date.now());
      });
    </script>
  </body>
</html>`))
	})

	mux.HandleFunc("/api/set-cookie", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Cookie is meant to be stored in the proxy runtime CookieJar (not in browser cookies).
		w.Header().Add("set-cookie", "demo=1; Path=/; HttpOnly")
		w.Header().Set("content-type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	mux.HandleFunc("/api/echo-cookie", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json; charset=utf-8")
		c := r.Header.Get("cookie")
		_, _ = fmt.Fprintf(w, `{"cookie":%q}`, c)
	})

	upgrader := websocket.Upgrader{
		CheckOrigin: func(_r *http.Request) bool { return true },
	}
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			mt, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(mt, payload); err != nil {
				return
			}
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: mux}

	stopped := make(chan struct{})
	stop = func() {
		select {
		case <-stopped:
			return
		default:
		}
		ctxShutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctxShutdown)
		<-stopped
	}

	go func() {
		defer close(stopped)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("proxy demo upstream serve error: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		stop()
	}()

	return "http://" + ln.Addr().String(), stop, nil
}
