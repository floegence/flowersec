package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type V4LiveServerAllowConfig = controlv4.LiveServerAllowConfig

type V4LiveAuthorizationMaterial = controlv4.LiveAuthorizationMaterial
type V4LiveAuthorizationAccess = controlv4.LiveAuthorizationAccess
type V4LiveAuthorizationHost = controlv4.LiveAuthorizationHost
type V4LiveAuthorizationHTTPSConfig = controlv4.LiveAuthorizationHTTPSConfig
type V4LiveAuthorizationHTTPSService = controlv4.LiveAuthorizationHTTPSService

func V4LiveAuthorizationHTTPSServiceCharges(c V4LiveAuthorizationHTTPSConfig) (service, spend, invoke, reader, read resourcev4.Vector, err error) {
	service, spend, invoke, reader, read, err = controlv4.LiveAuthorizationHTTPSServiceCharges(c)
	err = controlv4.PublicSpendQueryFailure(err)
	return
}

func NewV4LiveAuthorizationHTTPSService(c V4LiveAuthorizationHTTPSConfig, reservation, spend, invoke, reader, read, dependencies resourcev4.Reference) (*V4LiveAuthorizationHTTPSService, error) {
	service, err := controlv4.NewLiveAuthorizationHTTPSService(c, reservation, spend, invoke, reader, read, dependencies)
	return service, controlv4.PublicSpendQueryFailure(err)
}
