package performance

import (
	"time"

	carrierwt "github.com/floegence/flowersec/flowersec-go/v5/internal/carrier/webtransportv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/transporttest"
)

func webTransportExecutionPlan(plan transporttest.ProfilePlan) transporttest.ProfilePlan {
	cleanupLimit := carrierwt.ConnectionDrainTimeout() + time.Second
	cleanupSeconds := int((cleanupLimit + time.Second - 1) / time.Second)
	if plan.CleanupDeadlineSeconds < cleanupSeconds {
		plan.CleanupDeadlineSeconds = cleanupSeconds
	}
	return plan
}

func forcedBrowserWebTransportExecutionPlan(plan transporttest.ProfilePlan) transporttest.ProfilePlan {
	plan = webTransportExecutionPlan(plan)
	if plan.Cold.Operations < 1 || plan.Cold.MaxInflight < 1 {
		return plan
	}
	cleanupWaves := (plan.Cold.Operations + plan.Cold.MaxInflight - 1) / plan.Cold.MaxInflight
	phaseSeconds := cleanupWaves*plan.CleanupDeadlineSeconds + 1
	if plan.Cold.PhaseDeadlineSeconds < phaseSeconds {
		plan.Cold.PhaseDeadlineSeconds = phaseSeconds
	}
	return plan
}
