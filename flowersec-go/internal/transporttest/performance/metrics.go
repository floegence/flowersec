package performance

type metrics struct {
	Records []metric
}

type metric struct {
	Name         string
	Value        float64
	Unit         string
	ConnectionID string
}

type configuration struct {
	Records []configurationValue
}

type configurationValue struct {
	Key   string
	Value string
}
