//go:build !linux

package linuxnetlab

import (
	"context"
	"errors"
)

func (*Lab) FaultObservation(context.Context) (KernelFaultObservation, error) {
	return KernelFaultObservation{}, errors.New("kernel fault observation requires Linux")
}

func ReadFaultObservation(context.Context, string, string) (KernelFaultObservation, error) {
	return KernelFaultObservation{}, errors.New("kernel fault observation requires Linux")
}
