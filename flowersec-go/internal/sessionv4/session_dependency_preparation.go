package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"

const (
	unaryDependencyAdmission uint8 = iota
	streamDependencyAdmission
	notificationDependencyAdmission
)

// Each enabled declaration stores its temporary admission link in its own
// charged metadata. There is no extra registry or array for disabled methods.
// The original RPC batch serializes construction, transfer and cleanup.
type rpcDependencyPreparation struct {
	head     *invocationServices
	counts   [3]int
	prepared bool
}

func dependencyAdmissionCounts(c RPCServicesConfig) [3]int {
	return [3]int{len(c.Methods), len(c.StreamMethods), len(c.NotificationMethods)}
}

func dependencyAdmissionDeclarations(c RPCServicesConfig, kind uint8, index int) []ServiceDependency {
	switch kind {
	case unaryDependencyAdmission:
		return c.Methods[index].Dependencies
	case streamDependencyAdmission:
		return c.StreamMethods[index].Dependencies
	default:
		return c.NotificationMethods[index].Dependencies
	}
}

func (b *rpcServicesBatch) reserveDependencies(refs []resourcev4.Reference) (err error) {
	p := &b.dependencies
	if p.prepared {
		return p.check(b.config)
	}
	if !b.prepared || b.used || len(refs) != b.count {
		return resourcev4.ErrOwner
	}
	p.counts, p.prepared = dependencyAdmissionCounts(b.config), true
	defer func() {
		if err != nil {
			p.close()
		}
	}()
	for kind, count := range p.counts {
		backing := refs[rpcServicesDispatch]
		if kind == int(notificationDependencyAdmission) {
			backing = refs[rpcServicesNotifyDispatch]
		}
		for i := range count {
			declarations := dependencyAdmissionDeclarations(b.config, uint8(kind), i)
			if len(declarations) == 0 {
				continue
			}
			services, e := newInvocationServices(declarations, backing)
			if e != nil {
				return e
			}
			services.admissionKind, services.admissionIndex = uint8(kind), i
			services.admissionNext, p.head = p.head, services
		}
	}
	return nil
}

func (p *rpcDependencyPreparation) find(kind uint8, index int) **invocationServices {
	link := &p.head
	for *link != nil {
		if (*link).admissionKind == kind && (*link).admissionIndex == index {
			break
		}
		link = &(*link).admissionNext
	}
	return link
}

func (s *invocationServices) checkAdmissionDeclarationsLocked(declarations []ServiceDependency) error {
	if s.closed || s.sealed.Load() || s.visits != 0 || len(s.bindings) != len(declarations) {
		return resourcev4.ErrOwner
	}
	if err := s.backing.Check(); err != nil {
		return err
	}
	for i, declaration := range declarations {
		binding := &s.bindings[i]
		if binding.alias != declaration.Alias || binding.client != declaration.Client || len(binding.methods) != len(declaration.Methods) {
			return resourcev4.ErrOwner
		}
		if err := binding.borrow.Check(); err != nil {
			return err
		}
		for j, method := range declaration.Methods {
			if binding.methods[j] != method {
				return resourcev4.ErrOwner
			}
		}
	}
	return nil
}

func (p *rpcDependencyPreparation) check(c RPCServicesConfig) error {
	if !p.prepared || p.counts != dependencyAdmissionCounts(c) {
		return resourcev4.ErrOwner
	}
	for kind, count := range p.counts {
		for i := range count {
			declarations := dependencyAdmissionDeclarations(c, uint8(kind), i)
			services := *p.find(uint8(kind), i)
			if services == nil {
				if len(declarations) != 0 {
					return resourcev4.ErrOwner
				}
				continue
			}
			services.mu.Lock()
			err := services.checkAdmissionDeclarationsLocked(declarations)
			services.mu.Unlock()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *rpcDependencyPreparation) take(kind uint8, index int, declarations []ServiceDependency, backing resourcev4.Reference) (*invocationServices, error) {
	if p == nil {
		return newInvocationServices(declarations, backing)
	}
	if !p.prepared || int(kind) >= len(p.counts) || index < 0 || index >= p.counts[kind] {
		return nil, resourcev4.ErrOwner
	}
	link := p.find(kind, index)
	services := *link
	if services == nil {
		if len(declarations) != 0 {
			return nil, resourcev4.ErrOwner
		}
		return nil, nil
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if err := services.checkAdmissionDeclarationsLocked(declarations); err != nil {
		return nil, err
	}
	if err := services.backing.CheckBorrowedFrom(backing); err != nil {
		return nil, err
	}
	ref, err := services.backing.TakeBorrow()
	if err != nil {
		return nil, err
	}
	services.backing, services.primary = ref, backing
	*link = services.admissionNext
	services.admissionNext = nil
	return services, nil
}

func (p *rpcDependencyPreparation) close() {
	for p.head != nil {
		services := p.head
		p.head, services.admissionNext = services.admissionNext, nil
		services.close()
	}
	*p = rpcDependencyPreparation{}
}
