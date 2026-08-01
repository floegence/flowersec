package main

import (
	"time"

	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

func webTransportExecutionPlan(plan transportrelease.ProfilePlan) transportrelease.ProfilePlan {
	cleanupLimit := carrierwt.ConnectionDrainTimeout() + time.Second
	cleanupSeconds := int((cleanupLimit + time.Second - 1) / time.Second)
	if plan.CleanupDeadlineSeconds < cleanupSeconds {
		plan.CleanupDeadlineSeconds = cleanupSeconds
	}
	return plan
}
