package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// Each ordinary view can retain its application origin and registration.
// Admission covers the original client's shared generic call table plus every
// distinct declared workload. Aliases of the same client/method do not create
// another physical capacity promise. Recipes and the generic table geometry
// are immutable for the binding lifetime; contract updates do not resize them.
func invocationViewReferenceCapacity(declarations []ServiceDependency) (uint32, error) {
	var calls uint32
	for i, declaration := range declarations {
		c := declaration.Client
		if c == nil {
			return 0, cryptov4.ErrConfiguration
		}
		first := true
		for _, earlier := range declarations[:i] {
			first = first && earlier.Client != c
		}
		c.mu.Lock()
		err := func() error {
			if c.closed || c.cleaned {
				return cryptov4.ErrClosed
			}
			if first {
				calls += uint32(len(c.calls))
			}
			for _, selected := range declaration.Methods {
				if selected.Method.Namespace != c.namespace {
					return rpcv4.ErrMethod
				}
				method, err := c.methodLocked(selected.Method.Type)
				if err != nil {
					return err
				}
				duplicate := false
				for _, earlier := range declarations[:i] {
					if earlier.Client != c {
						continue
					}
					for _, prior := range earlier.Methods {
						duplicate = duplicate || prior.Method == selected.Method
					}
				}
				if !duplicate {
					calls += uint32(method.workload.Calls)
				}
			}
			return nil
		}()
		c.mu.Unlock()
		if err != nil {
			return 0, err
		}
	}
	return 2 * calls, nil
}
