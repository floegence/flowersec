package sessionv4

// EngineeringOriginalLiveDeployment selects an independently installed pending
// live registry. Its fixture owns bootstrap services and original signing policy
// only; no activation plan, authorization, Grant or durable spend is created.
type EngineeringOriginalLiveDeployment interface{ AuthorityOriginalLiveDeployment() bool }

func engineeringOriginalLive(t AuthorityReporter) bool {
	owner, ok := t.(EngineeringOriginalLiveDeployment)
	return ok && owner.AuthorityOriginalLiveDeployment()
}
