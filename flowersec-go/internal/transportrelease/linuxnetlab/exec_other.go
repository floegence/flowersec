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
