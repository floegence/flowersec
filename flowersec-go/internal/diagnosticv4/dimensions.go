package diagnosticv4

// Dimensions describes the fixed marginal histogram indices. Returning arrays
// by value cannot let an operations reader mutate the diagnostic registry.
type Dimensions struct {
	State    [stateCount]string    `json:"state"`
	Phase    [phaseCount]string    `json:"phase"`
	Code     [codeCount]string     `json:"code"`
	Duration [durationCount]string `json:"duration"`
	Attempt  [attemptCount]string  `json:"attempt"`
}

func CounterDimensions() Dimensions {
	return Dimensions{states, phases, codes, durations, attempts}
}
