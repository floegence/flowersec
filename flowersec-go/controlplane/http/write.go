package controlplanehttp

import (
	"encoding/json"
	stdhttp "net/http"

	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

func WriteArtifactEnvelope(w stdhttp.ResponseWriter, artifact *protocolio.ConnectArtifact) error {
	return writeJSON(w, stdhttp.StatusOK, ArtifactEnvelope{ConnectArtifact: artifact})
}

func WriteErrorEnvelope(w stdhttp.ResponseWriter, status int, code, message string) error {
	return writeJSON(w, status, ErrorEnvelope{
		Error: ErrorBody{
			Code:    code,
			Message: message,
		},
	})
}

func writeJSON(w stdhttp.ResponseWriter, status int, value any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(value)
}

func writeRequestError(w stdhttp.ResponseWriter, err error) {
	reqErr, ok := err.(*RequestError)
	if !ok {
		_ = WriteErrorEnvelope(w, stdhttp.StatusInternalServerError, "internal_error", "internal controlplane error")
		return
	}
	status := reqErr.Status
	if status <= 0 {
		status = stdhttp.StatusInternalServerError
	}
	code := reqErr.Code
	if code == "" {
		code = "internal_error"
	}
	message := reqErr.Message
	if message == "" {
		message = "controlplane request failed"
	}
	_ = WriteErrorEnvelope(w, status, code, message)
}
