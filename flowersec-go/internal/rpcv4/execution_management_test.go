package rpcv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type managementAccess struct{ ref resourcev4.Reference }

func (a managementAccess) WithExecutionAccess(_ ExecutionTarget, fn func(resourcev4.Reference) error) error {
	return fn(a.ref)
}

func TestExecutionManagementSerialAndBoundedPending(t *testing.T) {
	r := executionRoot(t)
	clock := executionClock(t)
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{21}, Backing: [16]byte{22}, Kind: 11}
	vc := VolatileExecutionConfig{Root: r, Owner: owner, Clock: clock, Service: ExecutionService{"tenant", "audience", "files"}, CallerAuthorities: [][32]byte{{8}}, Records: 1, Active: 1, TaskCharge: resourcev4.Vector{resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}, RuntimeBytes: 1024, WorkRuntimeBytes: 1024, ResultRuntimeBytes: 1024}
	historyCharge, err := VolatileExecutionsCharge(vc)
	if err != nil {
		t.Fatal(err)
	}
	href, err := r.Reserve(owner, historyCharge)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewVolatileExecutions(vc, href)
	if err != nil {
		t.Fatal(err)
	}
	contCharge, _ := ExecutionContinuityCharge(512)
	contOwner := owner
	contOwner.Instance = [16]byte{23}
	contOwner.Backing = [16]byte{24}
	cm, err := r.Reserve(contOwner, contCharge)
	if err != nil {
		t.Fatal(err)
	}
	cont, err := h.Continuity(cm, 512)
	if err != nil {
		t.Fatal(err)
	}
	mgmtCharge, _ := ExecutionManagementCharge(2, 512)
	managementOwner := contOwner
	managementOwner.Instance = [16]byte{25}
	managementOwner.Backing = [16]byte{26}
	mm, err := r.Reserve(managementOwner, mgmtCharge)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewExecutionManagement(2, 512, mm)
	if err != nil {
		t.Fatal(err)
	}
	target := ExecutionTarget{Service: vc.Service, Caller: ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}, Operation: [32]byte{1}, RequestDigest: [32]byte{2}, ContractDigest: [32]byte{3}}
	got, err := m.Submit(context.Background(), ManagementRequest{Serial: 1, Target: target, History: h, Continuity: cont, Access: managementAccess{ref: cont.capture.backing}})
	if err != nil || got.Serial != 1 || got.Status != "not_found" || got.Observation.Reason != "not_registered" {
		t.Fatal(got, err)
	}
	if _, err := m.Submit(context.Background(), ManagementRequest{Serial: 3, Target: target, History: h, Continuity: cont, Access: managementAccess{ref: cont.capture.backing}}); !errors.Is(err, ErrAssociation) {
		t.Fatal(err)
	}
	got, err = m.Submit(context.Background(), ManagementRequest{Serial: 2, Target: target, History: h, Access: managementAccess{ref: cont.capture.backing}})
	if err != nil || got.Status != "history_unknown" || got.Observation.Found {
		t.Fatal("missing original continuity became trustworthy absence", got, err)
	}
	m.Close()
	cont.Close()
	h.Close()
	href.Release()
	cm.Release()
	if !m.CleanupComplete() {
		t.Fatal("management retained backing")
	}
}
