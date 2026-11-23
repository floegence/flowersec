package artifactv3

import (
	"errors"
	"strings"
	"testing"
)

func TestArtifactRootPreflightPrecedesFieldDecoding(t *testing.T) {
	nested := func(depth int) string {
		return strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth)
	}
	for _, test := range []struct{ name, field, want string }{
		{"session", `"session":{"channel_id":"a","channel_id":"b"}`, `duplicate JSON field "channel_id"`},
		{"candidate TLS", `"path":{"candidates":[{"tls":{"mode":0,"m\u006fde":1}}]}`, `duplicate JSON field "mode"`},
		{"scope entry", `"scoped":[{"critical":false,"critical":true}]`, `duplicate JSON field "critical"`},
		{"scope payload", `"scoped":[{"payload":{"list":[{"a":1,"a":2}]}}]`, `duplicate JSON field "a"`},
		{"correlation", `"correlation":{"tags":[{"key":1,"key":2}]}`, `duplicate JSON field "key"`},
		{"depth at limit", `"scoped":` + nested(maxJSONPreflightDepth-1), "required top-level fields"},
		{"depth over limit", `"scoped":` + nested(maxJSONPreflightDepth), "JSON nesting is too deep"},
	} {
		t.Run(test.name, func(t *testing.T) {
			artifact, err := DecodeArtifactJSON(strings.NewReader(`{"v":0,` + test.field + `}`))
			if artifact != nil || !errors.Is(err, ErrInvalidArtifact) || err.Error() != ErrInvalidArtifact.Error()+": "+test.want {
				t.Fatalf("artifact = %v, error = %v; want invalid artifact: %s", artifact, err, test.want)
			}
		})
	}
}
