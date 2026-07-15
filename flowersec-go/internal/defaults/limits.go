package defaults

import "time"

const (
	MaxHandshakePayloadBytes = 8 * 1024
	MaxRecordBytes           = 1024 * 1024
	OutboundRecordChunkBytes = 64 * 1024
	MaxOutboundBufferedBytes = 4 * 1024 * 1024

	YamuxMaxActiveStreams            = 64
	YamuxMaxInboundStreams           = 32
	YamuxMaxFrameBytes               = 256 * 1024
	YamuxPreferredOutboundFrameBytes = 64 * 1024
	YamuxMaxStreamReceiveBytes       = 256 * 1024
	YamuxMaxSessionReceiveBytes      = 16 * 1024 * 1024

	RPCMaxJSONFrameBytes      = 1024 * 1024
	RPCMaxConcurrentRequests  = 32
	RPCMaxQueuedRequests      = 128
	RPCMaxQueuedNotifications = 128

	ControlplaneMaxRequestBodyBytes  = 32 * 1024
	ControlplaneMaxResponseBodyBytes = 1024 * 1024

	ProxyMaxJSONFrameBytes = 1024 * 1024
	ProxyMaxChunkBytes     = 256 * 1024
	ProxyMaxBodyBytes      = 64 * 1024 * 1024
	ProxyMaxWSFrameBytes   = 1024 * 1024

	ReconnectMaxAttempts = 5
)

const (
	ProxyDefaultTimeout = 30 * time.Second
	ProxyMaxTimeout     = 5 * time.Minute

	ReconnectInitialDelay = 500 * time.Millisecond
	ReconnectMaxDelay     = 10 * time.Second
	ReconnectFactor       = 1.8
	ReconnectJitterRatio  = 0.2
)
