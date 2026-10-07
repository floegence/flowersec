package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestPublicFailuresDoNotExposeProviderDetails(t *testing.T) {
	secret := errors.New("private database path and authentication material")
	for _, tc := range []struct {
		cause              error
		issue, publication string
	}{
		{context.Canceled, "cancelled", "cancelled"},
		{context.DeadlineExceeded, "expired", "expired"},
		{timev4.ErrExpired, "expired", "expired"},
		{resourcev4.ErrCapacity, "capacity_exhausted", "capacity_exhausted"},
		{resourcev4.ErrClosed, "closed", "closed"},
		{resourcev4.ErrConfiguration, "configuration_invalid", "configuration_invalid"},
		{ledgerv4.ErrUnknown, "issuance_refused", "publication_unknown"},
		{ledgerv4.ErrConflict, "issuance_refused", "publication_conflict"},
		{ledgerv4.ErrFenced, "issuance_refused", "publication_conflict"},
		{ledgerv4.ErrCapacity, "issuance_refused", "capacity_exhausted"},
		{ledgerv4.ErrOwner, "issuance_refused", "closed"},
		{ledgerv4.ErrMissingPublication, "issuance_refused", "publication_unavailable"},
		{ledgerv4.ErrConfiguration, "issuance_refused", "configuration_invalid"},
		{secret, "issuance_refused", "publication_refused"},
	} {
		t.Run(tc.publication+"/"+tc.cause.Error(), func(t *testing.T) {
			wrapped := fmt.Errorf("%s: %w", secret, tc.cause)
			if got := v4IssueFailure(wrapped); got != IssueFailure(tc.issue) || got.Error() != tc.issue {
				t.Fatalf("issuance error escaped its public category: %v", got)
			}
			if got := v4PublicationFailure(wrapped); got != PublicationFailure(tc.publication) || got.Error() != tc.publication {
				t.Fatalf("publication error escaped its public category: %v", got)
			}
		})
	}
	if v4IssueFailure(nil) != nil || v4PublicationFailure(nil) != nil {
		t.Fatal("successful operation acquired a failure")
	}
	if got := v4PublicationFailure(ledgerv4.ErrStorageFormat); !errors.Is(got, ledgerv4.ErrStorageFormat) {
		t.Fatal("storage format incompatibility lost its explicit category", got)
	}
	format := &ledgerv4.StorageFormatError{}
	for _, cause := range []error{ledgerv4.ErrStorageFormat, format} {
		for _, wrapped := range []error{fmt.Errorf("%s: %w", secret, cause), errors.Join(secret, cause)} {
			got := v4PublicationFailure(wrapped)
			if got != cause || got.Error() != cause.Error() {
				t.Fatal("storage format error exposed provider wrapper", got)
			}
		}
	}
}

func TestUninitializedOwnersRefuseWorkWithoutPublishing(t *testing.T) {
	ctx := context.Background()
	for _, issuer := range []*DirectIssuer{nil, {}} {
		if n, err := issuer.IssueArtifactBytes(ctx, DirectIssueRequest{}, nil); n != 0 || err != IssueFailure("closed") {
			t.Fatal("uninitialized direct issuer published", n, err)
		}
		issuer.Close()
		if err := issuer.WaitCleanup(ctx); err != IssueFailure("closed") {
			t.Fatal(err)
		}
		if _, err := NewDirectIssueHTTPSService(issuer, DirectIssueHTTPSConfig{}, resourcev4.Reference{}, resourcev4.Reference{}); err != IssueFailure("closed") {
			t.Fatal(err)
		}
		if fmt.Sprint(issuer) != "DirectIssuer(<redacted>)" || fmt.Sprintf("%#v", issuer) != "DirectIssuer(<redacted>)" {
			t.Fatal("issuer diagnostic exposed state")
		}
	}
	for _, issuer := range []*ArtifactIssuer{nil, {}} {
		if n, err := issuer.IssueArtifactBytes(ctx, ArtifactIssueRequest{}, nil); n != 0 || err != IssueFailure("closed") {
			t.Fatal(n, err)
		}
		if _, n, err := issuer.NamespaceClosure(); n != 0 || err != IssueFailure("closed") {
			t.Fatal(n, err)
		}
		issuer.Close()
		if err := issuer.WaitCleanup(ctx); err != IssueFailure("closed") {
			t.Fatal(err)
		}
		if _, err := NewArtifactIssueHTTPSService(issuer, ArtifactIssueHTTPSConfig{}, resourcev4.Reference{}, resourcev4.Reference{}); err != IssueFailure("closed") {
			t.Fatal(err)
		}
		if fmt.Sprint(issuer) != "ArtifactIssuer(<redacted>)" || fmt.Sprintf("%#v", issuer) != "ArtifactIssuer(<redacted>)" {
			t.Fatal("issuer diagnostic exposed state")
		}
	}
	for _, store := range []*SQLitePublicationStore{nil, {}} {
		if n, err := store.ReplaceState(ctx, 0, nil); n != 0 || err != PublicationFailure("closed") {
			t.Fatal(n, err)
		}
		if v, n, h, err := store.ReadPublished(ctx, nil, [32]byte{}, nil, nil); v != (NamespacePublicationVersion{}) || n != 0 || h != 0 || err != PublicationFailure("closed") {
			t.Fatal(v, n, h, err)
		}
		store.Close()
		if err := store.WaitCleanup(ctx); err != PublicationFailure("closed") {
			t.Fatal(err)
		}
		if err := store.Retire(); err != PublicationFailure("closed") {
			t.Fatal(err)
		}
		if _, err := NewNamespaceHTTPSService(store, NamespaceHTTPSConfig{}, resourcev4.Reference{}, resourcev4.Reference{}); err != PublicationFailure("configuration_invalid") {
			t.Fatal(err)
		}
		if fmt.Sprint(store) != "SQLitePublicationStore(<redacted>)" || fmt.Sprintf("%#v", store) != "SQLitePublicationStore(<redacted>)" {
			t.Fatal("store diagnostic exposed state")
		}
	}
	for _, publisher := range []*NamespacePublisher{nil, {}} {
		if v, err := publisher.Publish(ctx); v != (NamespacePublicationVersion{}) || err != PublicationFailure("closed") {
			t.Fatal(v, err)
		}
		publisher.Close()
		if err := publisher.WaitCleanup(ctx); err != PublicationFailure("closed") {
			t.Fatal(err)
		}
		if fmt.Sprint(publisher) != "NamespacePublisher(<redacted>)" || fmt.Sprintf("%#v", publisher) != "NamespacePublisher(<redacted>)" {
			t.Fatal("publisher diagnostic exposed state")
		}
	}
	for _, service := range []*NamespaceHTTPSService{nil, {}} {
		response := httptest.NewRecorder()
		service.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/head", nil))
		if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 {
			t.Fatal("uninitialized namespace service served content")
		}
		service.Close()
		if err := service.WaitCleanup(ctx); err != PublicationFailure("closed") {
			t.Fatal(err)
		}
	}
	for _, service := range []*SpendReceiptService{nil, {}} {
		if r, err := service.QuerySpendReceipt(ctx, nil, nil); r != (SpendReceipt{}) || err != SpendQueryFailure("unavailable") {
			t.Fatal(r, err)
		}
		if n, err := service.QuerySpendReceiptBytes(ctx, nil, nil, nil); n != 0 || err != SpendQueryFailure("unavailable") {
			t.Fatal(n, err)
		}
		service.Close()
		if err := service.WaitCleanup(ctx); err != SpendQueryFailure("unavailable") {
			t.Fatal(err)
		}
	}
	for _, service := range []*LiveRelayRegistrationService{nil, {}} {
		if r, err := service.CaptureRelayLeg(ctx, nil, nil, ledgerv4.SQLiteIdentity{}, nil, 0, resourcev4.Reference{}, resourcev4.Reference{}); r != nil || err != SpendQueryFailure("unavailable") {
			t.Fatal(r, err)
		}
		service.Close()
		if err := service.WaitCleanup(ctx); err != SpendQueryFailure("unavailable") {
			t.Fatal(err)
		}
	}
}

func TestPublicConstructorsRequireIndependentConfiguration(t *testing.T) {
	ctx, ref := context.Background(), resourcev4.Reference{}
	checks := []struct {
		name string
		run  func() error
	}{
		{"direct issuer charge", func() error { _, e := DirectIssuerCharge(DirectIssuerConfig{}); return e }},
		{"direct issuer", func() error { _, e := NewDirectIssuer(DirectIssuerConfig{}, ref, ref); return e }},
		{"artifact issuer charge", func() error { _, e := ArtifactIssuerCharge(ArtifactIssuerConfig{}); return e }},
		{"artifact issuer", func() error { _, e := NewArtifactIssuer(ArtifactIssuerConfig{}, ref, ref); return e }},
		{"direct HTTPS charge", func() error { _, e := DirectIssueHTTPSServiceCharge(DirectIssueHTTPSConfig{}); return e }},
		{"artifact HTTPS charge", func() error { _, e := ArtifactIssueHTTPSServiceCharge(ArtifactIssueHTTPSConfig{}); return e }},
		{"durable issuer charge", func() error { _, e := SQLiteDirectIssueCharge(SQLiteDirectIssueConfig{}); return e }},
		{"durable issuer", func() error {
			_, e := NewSQLiteDirectIssueAuthority(ctx, nil, SQLiteDirectIssueConfig{}, ref, ref)
			return e
		}},
		{"artifact host charge", func() error { _, _, e := LiveArtifactHostCharges(LiveArtifactHostConfig{}); return e }},
		{"artifact host", func() error { _, e := NewLiveArtifactHost(LiveArtifactHostConfig{}, ref, nil, ref); return e }},
		{"publication charge", func() error {
			_, _, _, e := SQLitePublicationStoreCharges(ledgerv4.SQLiteLimits{}, SQLitePublicationConfig{})
			return e
		}},
		{"create publication", func() error {
			_, e := CreateSQLitePublicationStore(ctx, nil, ledgerv4.SQLiteIdentity{}, nil, SQLitePublicationConfig{}, ref, ref, ref, ref)
			return e
		}},
		{"open publication", func() error {
			_, e := OpenSQLitePublicationStore(ctx, nil, ledgerv4.SQLiteIdentity{}, nil, SQLitePublicationConfig{}, ref, ref, ref, ref)
			return e
		}},
		{"publisher charge", func() error { _, _, e := NamespacePublisherCharges(NamespacePublisherConfig{}); return e }},
		{"publisher", func() error { _, e := NewNamespacePublisher(NamespacePublisherConfig{}, ref, ref, ref); return e }},
		{"namespace HTTPS charge", func() error { _, e := NamespaceHTTPSServiceCharge(NamespaceHTTPSConfig{}); return e }},
		{"spend service", func() error { _, e := NewSpendReceiptService(SpendReceiptServiceConfig{}, ref, ref, ref); return e }},
		{"relay service", func() error {
			_, e := NewLiveRelayRegistrationService(SpendReceiptServiceConfig{}, ref, ref, ref)
			return e
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			err := check.run()
			if err == nil {
				t.Fatal("unconfigured public authority accepted work")
			}
			switch err.(type) {
			case IssueFailure, PublicationFailure, SpendQueryFailure:
			default:
				t.Fatalf("internal provider error escaped: %T %v", err, err)
			}
		})
	}
	for _, ctx := range []context.Context{nil, context.Background(), context.WithValue(context.Background(), "client_identity", [32]byte{1})} {
		if identity, ok := AuthenticatedDirectIssueClient(ctx); ok || identity != ([32]byte{}) {
			t.Fatal("caller context conferred authenticated identity")
		}
		if identity, ok := AuthenticatedArtifactIssueClient(ctx); ok || identity != ([32]byte{}) {
			t.Fatal("caller context conferred authenticated identity")
		}
	}
}
