package flowersec

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type hostileControllerError []byte

func (hostileControllerError) Error() string { panic("application Error invoked") }
func (hostileControllerError) Is(error) bool { panic("application Is invoked") }
func (hostileControllerError) As(any) bool   { panic("application As invoked") }
func (hostileControllerError) Unwrap() error { panic("application Unwrap invoked") }

type typedNilControllerSource struct{}

func (*typedNilControllerSource) PrepareConnection(context.Context, ControllerRequest) (*ControllerPreparation, error) {
	panic("typed-nil Controller source was invoked")
}

func TestControllerRejectsTypedNilSourceBeforeAttempt(t *testing.T) {
	var source *typedNilControllerSource
	options := ControllerOptions{Source: source}
	if _, _, _, err := ControllerCharges(options); err == nil {
		t.Fatal("typed-nil Controller source accepted")
	}
	if _, err := (v4ControllerSource{source: source}).PrepareConnection(context.Background(), ControllerRequest{}); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("typed-nil Controller source reached provider", err)
	}
}

type typedNilAcceptedMaterialSource struct{}

func (*typedNilAcceptedMaterialSource) ResolveAcceptedMaterial(context.Context, []byte) (*ConnectionMaterial, InitialHello, error) {
	panic("typed-nil accepted material source was invoked")
}

func TestAcceptedMaterialSourceRejectsTypedNilBeforeProvider(t *testing.T) {
	var source *typedNilAcceptedMaterialSource
	if _, _, err := (v4AcceptedMaterialSource{source: source}).ResolveAcceptedMaterial(context.Background(), nil); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("typed-nil accepted material source reached provider", err)
	}
}

func TestControllerErrorsDoNotInvokeApplicationHooks(t *testing.T) {
	private := hostileControllerError("private provider detail")
	if err := v4ControllerError(private); err.Error() != "Flowersec session failed (code=operation_failed)" {
		t.Fatal("source detail escaped fixed projection")
	}
	if snapshot := v4ControllerSessionError(private); snapshot.Code() != SessionOperationFailed {
		t.Fatal("snapshot source detail escaped fixed projection")
	}
	if !errors.Is(v4ControllerError(context.Canceled), context.Canceled) || !errors.Is(v4ControllerError(context.DeadlineExceeded), context.DeadlineExceeded) {
		t.Fatal("cancellation/deadline identity lost")
	}
	for _, err := range []error{nil, ErrControllerBusy, ErrControllerInitialization, ErrRetirementCapacity} {
		if v4ControllerError(err) != err {
			t.Fatal("fixed Controller error identity lost")
		}
	}
}

func TestControllerDispatchRejectsOwnerlessInputs(t *testing.T) {
	controller := &ConnectionController{inner: &sessionv4.ConnectionController{}}
	for _, input := range []*OperationHandle{nil, {}, {inner: nil}} {
		result := controller.Dispatch(context.Background(), input)
		if !errors.Is(result.Err, ErrTransportUnavailable) {
			t.Fatalf("ownerless dispatch returned %v", result.Err)
		}
	}
	if result := controller.Dispatch(nil, &OperationHandle{inner: &sessionv4.UnaryOperation{}}); !errors.Is(result.Err, ErrTransportUnavailable) {
		t.Fatalf("nil context dispatch returned %v", result.Err)
	}
}
