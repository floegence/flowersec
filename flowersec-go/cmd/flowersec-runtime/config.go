package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var ErrInvalidConfig = errors.New("invalid Flowersec runtime configuration")

type ConfigError struct {
	Field string
	Err   error
}

func (err *ConfigError) Error() string { return fmt.Sprintf("%s: %v", err.Field, err.Err) }
func (err *ConfigError) Unwrap() error { return ErrInvalidConfig }

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}
