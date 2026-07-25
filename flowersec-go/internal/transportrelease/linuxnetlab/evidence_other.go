//go:build !linux

package linuxnetlab

import (
	"context"
	"errors"
)

func (*Lab) FaultEvidence(context.Context) (KernelFaultEvidence, error) {
	return KernelFaultEvidence{}, errors.New("kernel fault evidence requires Linux")
}

func ReadFaultEvidence(context.Context, string, string) (KernelFaultEvidence, error) {
	return KernelFaultEvidence{}, errors.New("kernel fault evidence requires Linux")
}
