package sessionv4

import (
	"context"
	"testing"
)

// PublicProxyTestStream uses real v4 establishment, records, admission and the
// original application executor. Only the application registration is supplied
// by the public-package test.
func PublicProxyTestStream(t *testing.T, registration RawStreamHandlerConfig) (*StreamOwnership, context.Context) {
	t.Helper()
	cores, _, _, ctx := handlerCorePair(t, "stream", func(int) RawStreamHandlerConfig { return registration }, nil)
	owner, err := cores[0].OpenStream(ctx, registration.Kind, []byte("proxy-test"), streamTestDeadline(t, cores[0].Engine()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = owner.Cancel()
		if err := owner.Release(); err != nil {
			t.Error(err)
		}
	})
	return owner, ctx
}
