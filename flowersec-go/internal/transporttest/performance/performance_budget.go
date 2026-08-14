package performance

import (
	"os"
	"time"
)

const performanceBudgetEnvironmentName = "FLOWERSEC_PERFORMANCE_BUDGET"

func performanceBudgetScale() (float64, bool) {
	raw := os.Getenv(performanceBudgetEnvironmentName)
	if raw == "" {
		return 0, false
	}
	budget, err := time.ParseDuration(raw)
	if err != nil || budget < 5*time.Minute || budget > 24*time.Hour {
		return 0, false
	}
	scale := float64(budget) / float64(10*time.Minute)
	if scale > 5 {
		scale = 5
	}
	return scale, true
}

func scaledPerformanceDuration(base time.Duration) (time.Duration, bool) {
	scale, configured := performanceBudgetScale()
	if !configured {
		return 0, false
	}
	return time.Duration(float64(base) * scale).Round(10 * time.Millisecond), true
}
