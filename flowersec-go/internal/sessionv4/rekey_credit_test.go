package sessionv4

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func newTestRekeyClock(t *testing.T, rate RekeyClockRate, source func() (RekeyClockSample, error)) *timev4.Clock {
	t.Helper()
	clock, err := timev4.NewClock(timev4.Profile{Rate: rate, MaxWidthMS: 2000, MaxAgeMS: 3600000, MaxRoundTripMS: 1000}, source)
	if err != nil {
		t.Fatal(err)
	}
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 100000, UpperMS: 100000}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	return clock
}

func testCredit(t *testing.T, role protocolv4.Direction) (*RekeyCredit, *RekeyClockSample) {
	t.Helper()
	now := &RekeyClockSample{Incarnation: [16]byte{7}}
	clock := newTestRekeyClock(t, RekeyClockRate{Numerator: 1, Denominator: 10000, QuantizationMS: 2}, func() (RekeyClockSample, error) { return *now, nil })
	e := newOpenEndpointClock(t, role, 2, 2, 1, clock)
	c, err := NewRekeyCredit(e.admission, RekeyEnvelope{Burst: 2, RefillMS: 30000, RequestStartMS: 5000}, 0, 3600000, clock)
	if err != nil {
		t.Fatal(err)
	}
	return c, now
}

func chargeRound(t *testing.T, c *RekeyCredit) *RekeyCharge {
	t.Helper()
	r, err := c.Prepare(c.epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Init(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRekeyCreditOriginalBalanceAcrossRounds(t *testing.T) {
	c, now := testCredit(t, protocolv4.ClientToServer)
	r := chargeRound(t, c)
	if r.post != 30000 || c.base != 60000 {
		t.Fatal("INIT changed base or mischarged")
	}
	now.Milliseconds = 90000
	if got, err := c.Available(); err != nil || got != 30000 {
		t.Fatal("round time replenished credit", got, err)
	}
	if err := r.Cancel(); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("charged round cancelled", err)
	}
	if err := r.Init(); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("duplicate INIT", err)
	}
	if err := r.Ack(); err != nil {
		t.Fatal(err)
	}
	if c.base != 30000 || c.anchor.Milliseconds != 90000 {
		t.Fatal("ACK reset credit")
	}
	now.Milliseconds = 91003
	first, err := c.Available()
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := c.Available()
		if err != nil || again != first {
			t.Fatal("peek refilled twice", again, err)
		}
	}
	r, err = c.Prepare(1)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Cancel(); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Available(); err != nil || got != first {
		t.Fatal("cancel changed anchor", got, err)
	}
	r = chargeRound(t, c)
	if r.post != first-30000 {
		t.Fatal("fractional balance lost", r.post, first)
	}
	if err = r.Ack(); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Prepare(2); !errors.Is(err, ErrRekeyCredit) {
		t.Fatal("unfunded freeze admitted", err)
	}
	if c.active != nil {
		t.Fatal("unfunded prepare took owner")
	}
	now.Milliseconds += 15010
	r = chargeRound(t, c)
	if r.post == 0 {
		t.Fatal("partial credit discarded")
	}
}

func TestRekeyCreditContinuityAndSessionOwnership(t *testing.T) {
	c, now := testCredit(t, protocolv4.ServerToClient)
	if _, err := NewRekeyCredit(c.admission, c.envelope, 0, 3600000, c.clock); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("created fresh bucket on same Session", err)
	}
	r := chargeRound(t, c)
	if err := r.Ack(); err != nil {
		t.Fatal(err)
	}
	now.Incarnation[0]++
	if _, err := c.Available(); !errors.Is(err, ErrTimeContinuity) {
		t.Fatal("restarted clock accepted", err)
	}
	now.Incarnation[0]--
	if _, err := c.Prepare(1); !errors.Is(err, ErrTimeContinuity) {
		t.Fatal("old incarnation revived", err)
	}
	if c.base != 30000 {
		t.Fatal("continuity failure reset balance")
	}
}

func TestRekeyCreditCausalResponseEnclosure(t *testing.T) {
	c, cn := testCredit(t, protocolv4.ClientToServer)
	s, sn := testCredit(t, protocolv4.ServerToClient)
	// Separate original monotonic clocks; server ACK happens first and its
	// next authenticated INIT happens last. Network compression never reverses
	// this enclosure, and each side retains its own partial balance.
	for round := range 30 {
		cn.Milliseconds += 20000
		sn.Milliseconds += 20002
		cr := chargeRound(t, c)
		sr := chargeRound(t, s)
		if sr.post < cr.post {
			t.Fatal("server rejected legal client credit", round, sr.post, cr.post)
		}
		sn.Milliseconds += 8
		if err := sr.Ack(); err != nil {
			t.Fatal(err)
		}
		cn.Milliseconds += 10
		if err := cr.Ack(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRekeyCreditConcurrentOriginalGate(t *testing.T) {
	c, _ := testCredit(t, protocolv4.ClientToServer)
	r, err := c.Prepare(0)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		wg.Go(func() { results <- r.Init() })
	}
	wg.Wait()
	close(results)
	committed := 0
	for err := range results {
		if err == nil {
			committed++
		} else if !errors.Is(err, cryptov4.ErrTransition) {
			t.Fatal(err)
		}
	}
	if committed != 1 || r.post != 30000 {
		t.Fatal("duplicate charge", committed, r.post)
	}
	results = make(chan error, 16)
	for range 16 {
		wg.Go(func() { results <- r.Ack() })
	}
	wg.Wait()
	close(results)
	completed := 0
	for err := range results {
		if err == nil {
			completed++
		} else if !errors.Is(err, cryptov4.ErrTransition) {
			t.Fatal(err)
		}
	}
	if completed != 1 || c.epoch != 1 || c.base != 30000 {
		t.Fatal("duplicate completion", completed, c.epoch, c.base)
	}
}

func TestRekeyServiceAndCreditSharedArithmetic(t *testing.T) {
	var corpus struct {
		Schema  string `json:"schema_revision"`
		Vectors []struct {
			ID, Profile, Operation string
			Input                  map[string]string
			Expected               map[string]json.RawMessage
			Error                  string `json:"expected_error"`
		}
	}
	raw, err := os.ReadFile("../../../testdata/transport_v4/rekey_credit.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile("../../../testdata/transport_v4/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Revision string `json:"schema_revision"`
		SHA      string `json:"schema_sha256"`
	}
	if err = json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != manifest.Revision || manifest.SHA != protocolv4.SchemaSHA256 {
		t.Fatal("schema drift")
	}
	for _, v := range corpus.Vectors {
		// Canonical decimal parsing and wire scalar widths are covered by the
		// original decoder suite. This runtime takes already typed local values.
		if v.Operation == "initial_credit" || v.Error != "" && v.Operation != "service" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			n := func(key string) uint64 {
				value, err := strconv.ParseUint(v.Input[key], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			want := func(key string) uint64 {
				var s string
				if err := json.Unmarshal(v.Expected[key], &s); err != nil {
					t.Fatal(err)
				}
				value, err := strconv.ParseUint(s, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			envelope := RekeyEnvelope{Burst: uint16(n("burst_rounds")), RefillMS: uint32(n("refill_period_ms"))}
			rate := RekeyClockRate{Numerator: n("rate_numerator"), Denominator: n("rate_denominator"), QuantizationMS: n("quantization_ms")}
			if v.Operation == "service" {
				envelope.RequestStartMS = uint32(n("request_start_budget_ms"))
				actual, err := AdmitRekeyService(v.Profile, envelope, rate, n("issued_at_ms"), n("session_not_after_ms"))
				if v.Error != "" {
					if !errors.Is(err, cryptov4.ErrConfiguration) {
						t.Fatal(actual, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if actual != (RekeyServiceBound{want("service_ms"), want("error_allowance_ms"), want("denominator_ms"), want("capacity_credit"), want("max_rounds"), want("required_epochs")}) {
					t.Fatal(actual)
				}
				return
			}
			role := protocolv4.ClientToServer
			if v.Operation == "server_credit" {
				role = protocolv4.ServerToClient
			}
			c := &RekeyCredit{envelope: envelope, rate: rate, base: n("base_credit"), bound: RekeyServiceBound{Capacity: uint64(envelope.Burst) * uint64(envelope.RefillMS)}, hasAnchor: true, role: role}
			actual, err := c.available(timev4.Sample{Mark: timev4.Mark{Tick: RekeyClockSample{Milliseconds: n("delta_ms")}}})
			if err != nil || actual != want("available_credit") {
				t.Fatal(actual, err)
			}
		})
	}
}
