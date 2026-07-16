package main

import "github.com/floegence/flowersec/flowersec-go/internal/interopprotocol"

func recordDiagnostic(values *[]interopprotocol.Diagnostic, caseName, path string) error {
	value, err := interopprotocol.DiagnosticFor(caseName, path)
	if err != nil {
		return err
	}
	*values = append(*values, value)
	return nil
}
