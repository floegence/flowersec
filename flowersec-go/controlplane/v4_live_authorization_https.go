package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type LiveServerAllowConfig = controlv4.LiveServerAllowConfig

type LiveAuthorizationMaterial = controlv4.LiveAuthorizationMaterial
type LiveAuthorizationAccess = controlv4.LiveAuthorizationAccess
type LiveAuthorizationHost = controlv4.LiveAuthorizationHost
type LiveAuthorizationHTTPSConfig = controlv4.LiveAuthorizationHTTPSConfig
type LiveAuthorizationHTTPSService = controlv4.LiveAuthorizationHTTPSService

func LiveAuthorizationHTTPSServiceCharges(c LiveAuthorizationHTTPSConfig) (service, spend, invoke, reader, read resourcev4.Vector, err error) {
	service, spend, invoke, reader, read, err = controlv4.LiveAuthorizationHTTPSServiceCharges(c)
	err = controlv4.PublicSpendQueryFailure(err)
	return
}

func NewLiveAuthorizationHTTPSService(c LiveAuthorizationHTTPSConfig, reservation, spend, invoke, reader, read, dependencies resourcev4.Reference) (*LiveAuthorizationHTTPSService, error) {
	service, err := controlv4.NewLiveAuthorizationHTTPSService(c, reservation, spend, invoke, reader, read, dependencies)
	return service, controlv4.PublicSpendQueryFailure(err)
}
