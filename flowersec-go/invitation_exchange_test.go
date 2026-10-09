package flowersec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
)

func TestInvitationCodeCanonicalizationAndRedaction(t *testing.T) {
	code, err := flowersec.NewInvitationCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(code.Text()) != 26 {
		t.Fatal("invitation code must contain 128 bits in 26 Base32 characters")
	}
	formatted := strings.ToLower(code.Text()[:5] + "-" + code.Text()[5:10] + " " + code.Text()[10:])
	parsed, err := flowersec.ParseInvitationCode(formatted)
	if err != nil || parsed.Text() != code.Text() || parsed.LookupID() != code.LookupID() {
		t.Fatal("formatted code did not preserve its identity")
	}
	encoded, err := json.Marshal(code)
	if err != nil {
		t.Fatal(err)
	}
	for _, representation := range []string{fmt.Sprint(code), fmt.Sprintf("%#v", code), string(encoded)} {
		if strings.Contains(representation, code.Text()) {
			t.Fatal("ordinary representations expose the invitation secret")
		}
	}
	for _, invalid := range []string{"", strings.Repeat("Z", 26), strings.Repeat("I", 26), code.Text() + "A", code.Text()[:25]} {
		if _, err := flowersec.ParseInvitationCode(invalid); err == nil {
			t.Fatal("invalid code accepted")
		}
	}
}

func TestInvitationCodeDerivationIsStableAndDomainBound(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	one, err := flowersec.DeriveInvitationCode(key, "invitation-one")
	if err != nil {
		t.Fatal(err)
	}
	again, err := flowersec.DeriveInvitationCode(key, "invitation-one")
	if err != nil || one.Text() != again.Text() {
		t.Fatal("durable issuance cannot recover its original code")
	}
	two, err := flowersec.DeriveInvitationCode(key, "invitation-two")
	if err != nil || one.Text() == two.Text() {
		t.Fatal("invitation identifiers must have independent credentials")
	}
	if _, err := flowersec.DeriveInvitationCode([]byte("weak"), "invitation-one"); err == nil {
		t.Fatal("weak issuance secret accepted")
	}
}

func invitationServer(t *testing.T, code flowersec.InvitationCode, describe func(context.Context, string) ([]byte, error)) *httptest.Server {
	t.Helper()
	handler, err := flowersec.NewInvitationExchangeHandler(flowersec.InvitationExchangeHandlerOptions{
		Purpose: "test.runtime-enrollment", Timeout: time.Second, MaxConcurrent: 2,
		Lookup: func(_ context.Context, id string) (flowersec.InvitationCode, error) {
			if id != code.LookupID() {
				return flowersec.InvitationCode{}, errors.New("unknown invitation")
			}
			return code, nil
		}, Describe: describe,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS, _ = acceptorListenerTLS(t)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestInvitationExchangeAuthenticatesBeforeDeliveringDescriptor(t *testing.T) {
	code, _ := flowersec.NewInvitationCode()
	var described atomic.Int32
	server := invitationServer(t, code, func(_ context.Context, id string) ([]byte, error) {
		described.Add(1)
		if id != code.LookupID() {
			t.Fatal("descriptor lookup changed identity")
		}
		return []byte(`{"gateway":"office","tls_root":"authenticated"}`), nil
	})
	options := flowersec.InvitationExchangeOptions{URL: "wss" + strings.TrimPrefix(server.URL, "https") + "/enroll", Purpose: "test.runtime-enrollment", Code: code}
	result, err := flowersec.ExchangeInvitation(context.Background(), options)
	if err != nil || string(result) != `{"gateway":"office","tls_root":"authenticated"}` {
		t.Fatalf("authenticated self-signed exchange failed: %v", err)
	}
	if described.Load() != 1 {
		t.Fatal("descriptor was not delivered exactly once")
	}
	wrong, _ := flowersec.NewInvitationCode()
	options.Code = wrong
	if _, err := flowersec.ExchangeInvitation(context.Background(), options); err == nil {
		t.Fatal("wrong credential accepted")
	}
	options.Code, options.Purpose = code, "test.desktop-access"
	if _, err := flowersec.ExchangeInvitation(context.Background(), options); err == nil {
		t.Fatal("cross-purpose handshake accepted")
	}
	if described.Load() != 1 {
		t.Fatal("unauthenticated peer reached the product descriptor")
	}
}

func TestInvitationExchangePreservesTypedRejectionAndCancellation(t *testing.T) {
	code, _ := flowersec.NewInvitationCode()
	server := invitationServer(t, code, func(context.Context, string) ([]byte, error) {
		return nil, flowersec.RejectInvitationExchange("INVITATION_EXPIRED")
	})
	options := flowersec.InvitationExchangeOptions{URL: "wss" + strings.TrimPrefix(server.URL, "https") + "/enroll", Purpose: "test.runtime-enrollment", Code: code}
	_, err := flowersec.ExchangeInvitation(context.Background(), options)
	var exchangeError *flowersec.InvitationExchangeError
	if !errors.As(err, &exchangeError) || exchangeError.Code != "INVITATION_EXPIRED" {
		t.Fatal("authenticated rejection lost its stable reason")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := flowersec.ExchangeInvitation(ctx, options); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not preserved")
	}
	options.URL = strings.Replace(options.URL, "wss:", "ws:", 1)
	if _, err := flowersec.ExchangeInvitation(context.Background(), options); err == nil {
		t.Fatal("plaintext downgrade accepted")
	}
	request := httptest.NewRequest(http.MethodGet, "https://gateway/enroll", nil)
	request.Header.Set("Origin", "https://untrusted.example")
	recorder := httptest.NewRecorder()
	server.Config.Handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatal("browser enrollment request accepted")
	}
}

func TestInvitationExchangeRedactsApplicationFailure(t *testing.T) {
	code, _ := flowersec.NewInvitationCode()
	server := invitationServer(t, code, func(context.Context, string) ([]byte, error) {
		return []byte(code.Text()), errors.New("private detail " + code.Text())
	})
	_, err := flowersec.ExchangeInvitation(context.Background(), flowersec.InvitationExchangeOptions{
		URL: "wss" + strings.TrimPrefix(server.URL, "https"), Purpose: "test.runtime-enrollment", Code: code,
	})
	var rejection *flowersec.InvitationExchangeError
	if !errors.As(err, &rejection) || rejection.Code != "INVITATION_REJECTED" || strings.Contains(err.Error(), code.Text()) {
		t.Fatal("application failure leaked private details")
	}
}
