//go:build !linux

package linuxnetlab

import "errors"

func InNamespace(string, func() error) error {
	return errors.New("network namespaces require Linux")
}

func RequireCurrentNamespace(string) error {
	return errors.New("network namespaces require Linux")
}
