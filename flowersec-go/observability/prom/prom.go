package prom

import (
	"net/http"
	"time"

	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewRegistry returns a fresh Prometheus registry.
func NewRegistry() *prometheus.Registry {
	return prometheus.NewRegistry()
}

// Handler returns a Prometheus HTTP handler bound to the registry.
func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

// TunnelObserver exports tunnel metrics to Prometheus.
type TunnelObserver struct {
	connGauge      prometheus.Gauge
	channelGauge   prometheus.Gauge
	attachTotal    *prometheus.CounterVec
	replaceTotal   *prometheus.CounterVec
	closeTotal     *prometheus.CounterVec
	pairLatency    prometheus.Histogram
	encryptedTotal prometheus.Counter
}

// NewTunnelObserver registers tunnel metrics on the registry.
func NewTunnelObserver(reg *prometheus.Registry) *TunnelObserver {
	o := &TunnelObserver{
		connGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowersec_tunnel_connections",
			Help: "Current websocket connection count.",
		}),
		channelGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flowersec_tunnel_channels",
			Help: "Current active channel count.",
		}),
		attachTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowersec_tunnel_attach_total",
			Help: "Tunnel attach attempts by result and reason.",
		}, []string{"result", "reason"}),
		replaceTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowersec_tunnel_replace_total",
			Help: "Tunnel replace outcomes.",
		}, []string{"result"}),
		closeTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowersec_tunnel_close_total",
			Help: "Tunnel close reasons.",
		}, []string{"reason"}),
		pairLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "flowersec_tunnel_pair_latency_seconds",
			Help:    "Latency from first endpoint arrival to channel pairing.",
			Buckets: prometheus.DefBuckets,
		}),
		encryptedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowersec_tunnel_encrypted_total",
			Help: "Channels that reached encrypted record state.",
		}),
	}
	reg.MustRegister(
		o.connGauge,
		o.channelGauge,
		o.attachTotal,
		o.replaceTotal,
		o.closeTotal,
		o.pairLatency,
		o.encryptedTotal,
	)
	return o
}

func (o *TunnelObserver) ConnCount(n int64) {
	o.connGauge.Set(float64(n))
}

func (o *TunnelObserver) ChannelCount(n int) {
	o.channelGauge.Set(float64(n))
}

func (o *TunnelObserver) Attach(result observability.AttachResult, reason observability.AttachReason) {
	o.attachTotal.WithLabelValues(string(result), string(reason)).Inc()
}

func (o *TunnelObserver) Replace(result observability.ReplaceResult) {
	o.replaceTotal.WithLabelValues(string(result)).Inc()
}

func (o *TunnelObserver) Close(reason observability.CloseReason) {
	o.closeTotal.WithLabelValues(string(reason)).Inc()
}

func (o *TunnelObserver) PairLatency(d time.Duration) {
	o.pairLatency.Observe(d.Seconds())
}

func (o *TunnelObserver) Encrypted() {
	o.encryptedTotal.Inc()
}

// RPCObserver exports RPC metrics to Prometheus.
type RPCObserver struct {
	serverRequests    *prometheus.CounterVec
	frameErrors       *prometheus.CounterVec
	clientFrameErrors *prometheus.CounterVec
	clientCalls       *prometheus.CounterVec
	clientCallLatency prometheus.Histogram
	clientNotify      prometheus.Counter
}

// NewRPCObserver registers RPC metrics on the registry.
func NewRPCObserver(reg *prometheus.Registry) *RPCObserver {
	o := &RPCObserver{
		serverRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowersec_rpc_requests_total",
			Help: "RPC requests received by the server.",
		}, []string{"result"}),
		frameErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowersec_rpc_frame_errors_total",
			Help: "RPC server frame read/write errors.",
		}, []string{"direction"}),
		clientFrameErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowersec_rpc_client_frame_errors_total",
			Help: "RPC client frame read/write errors.",
		}, []string{"direction"}),
		clientCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flowersec_rpc_client_calls_total",
			Help: "RPC client call outcomes.",
		}, []string{"result"}),
		clientCallLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "flowersec_rpc_client_call_latency_seconds",
			Help:    "RPC client call latency.",
			Buckets: prometheus.DefBuckets,
		}),
		clientNotify: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flowersec_rpc_client_notify_total",
			Help: "RPC client notifications received.",
		}),
	}
	reg.MustRegister(
		o.serverRequests,
		o.frameErrors,
		o.clientFrameErrors,
		o.clientCalls,
		o.clientCallLatency,
		o.clientNotify,
	)
	return o
}

func (o *RPCObserver) ServerRequest(result observability.RPCResult) {
	o.serverRequests.WithLabelValues(string(result)).Inc()
}

func (o *RPCObserver) ServerFrameError(direction observability.RPCFrameDirection) {
	o.frameErrors.WithLabelValues(string(direction)).Inc()
}

func (o *RPCObserver) ClientFrameError(direction observability.RPCFrameDirection) {
	o.clientFrameErrors.WithLabelValues(string(direction)).Inc()
}

func (o *RPCObserver) ClientCall(result observability.RPCResult, d time.Duration) {
	o.clientCalls.WithLabelValues(string(result)).Inc()
	o.clientCallLatency.Observe(d.Seconds())
}

func (o *RPCObserver) ClientNotify() {
	o.clientNotify.Inc()
}
