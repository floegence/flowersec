package serve

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/endpoint"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
)

// ServeTunnel connects to a tunnel as role=server and serves streams using srv.
func ServeTunnel(ctx context.Context, grant *controlv1.ChannelInitGrant, origin string, srv *Server, opts ...endpoint.ConnectOption) error {
	if srv == nil {
		return errors.New("missing server")
	}
	sess, err := endpoint.ConnectTunnel(ctx, grant, origin, opts...)
	if err != nil {
		return err
	}
	defer sess.Close()
	return srv.ServeSession(ctx, sess)
}
