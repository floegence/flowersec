//go:build !linux

package linuxnetlab

import (
	"context"
	"errors"
)

func CompileDiagnosticBPFObject(context.Context, string) (string, error) {
	return "", errors.New("diagnostic BPF build requires Linux")
}
