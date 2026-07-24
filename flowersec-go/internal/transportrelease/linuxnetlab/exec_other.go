//go:build !linux

package linuxnetlab

import (
	"context"
	"errors"
)

type ExecRunner struct{}

func (ExecRunner) Run(context.Context, string, ...string) error {
	return errors.New("Linux network lab commands require Linux")
}

func (ExecRunner) InterfaceIndex(context.Context, string, string) (int, error) {
	return 0, errors.New("Linux network lab interface indexes require Linux")
}
