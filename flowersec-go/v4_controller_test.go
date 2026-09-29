package flowersec

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

type hostileControllerError []byte

func (hostileControllerError) Error() string { panic("application Error invoked") }
func (hostileControllerError) Is(error) bool { panic("application Is invoked") }
func (hostileControllerError) As(any) bool   { panic("application As invoked") }
func (hostileControllerError) Unwrap() error { panic("application Unwrap invoked") }

type typedNilControllerSource struct{}

func (*typedNilControllerSource) PrepareConnection(context.Context, V4ControllerRequest) (*V4ControllerPreparation, error) {
	panic("typed-nil Controller source was invoked")
}

func TestV4ControllerRejectsTypedNilSourceBeforeAttempt(t *testing.T) {
	var source *typedNilControllerSource
	options := V4ControllerOptions{Source: source}
	if _, _, _, err := V4ControllerCharges(options); err == nil {
		t.Fatal("typed-nil Controller source accepted")
	}
	if _, err := (v4ControllerSource{source: source}).PrepareConnection(context.Background(), V4ControllerRequest{}); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("typed-nil Controller source reached provider", err)
	}
}

type typedNilAcceptedMaterialSource struct{}

func (*typedNilAcceptedMaterialSource) ResolveAcceptedMaterial(context.Context, []byte) (*ConnectionMaterial, V4InitialHello, error) {
	panic("typed-nil accepted material source was invoked")
}

func TestV4AcceptedMaterialSourceRejectsTypedNilBeforeProvider(t *testing.T) {
	var source *typedNilAcceptedMaterialSource
	if _, _, err := (v4AcceptedMaterialSource{source: source}).ResolveAcceptedMaterial(context.Background(), nil); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("typed-nil accepted material source reached provider", err)
	}
}

func TestV4ControllerErrorsDoNotInvokeApplicationHooks(t *testing.T) {
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
	for _, err := range []error{nil, ErrV4ControllerBusy, ErrV4ControllerInitialization, ErrV4RetirementCapacity} {
		if v4ControllerError(err) != err {
			t.Fatal("fixed Controller error identity lost")
		}
	}
}
