package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCounterAndHistogramRendering(t *testing.T) {
	r := New()
	r.Inc(`sunder_requests_total{handler="lookup",code="200"}`)
	r.Inc(`sunder_requests_total{handler="lookup",code="200"}`)
	r.Observe(`sunder_request_seconds{handler="lookup"}`, 0.004)
	r.Observe(`sunder_request_seconds{handler="lookup"}`, 3.0) // beyond last bucket

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		`sunder_requests_total{handler="lookup",code="200"} 2`,
		`# TYPE sunder_requests_total counter`,
		`# TYPE sunder_request_seconds histogram`,
		`sunder_request_seconds_bucket{handler="lookup",le="0.005"} 1`,
		`sunder_request_seconds_bucket{handler="lookup",le="+Inf"} 2`,
		`sunder_request_seconds_count{handler="lookup"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in output:\n%s", want, body)
		}
	}
}

func TestSplitSeries(t *testing.T) {
	if n, l := splitSeries(`requests{path="/v1/lookup"}`); n != "requests" || l != `path="/v1/lookup"` {
		t.Fatalf("labeled: %q %q", n, l)
	}
	if n, l := splitSeries("plain"); n != "plain" || l != "" {
		t.Fatalf("plain: %q %q", n, l)
	}
}

func TestGaugeRendersCurrentValue(t *testing.T) {
	r := New()
	r.Set("sunder_audit_unsealed_rows", 42)
	r.Set("sunder_audit_unsealed_rows", 7) // last write wins: a level, not a sum
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, nil)
	body := rec.Body.String()
	if !strings.Contains(body, "# TYPE sunder_audit_unsealed_rows gauge") {
		t.Fatalf("missing gauge TYPE line:\n%s", body)
	}
	if !strings.Contains(body, "sunder_audit_unsealed_rows 7") {
		t.Fatalf("gauge must render its latest value:\n%s", body)
	}
	if strings.Contains(body, "sunder_audit_unsealed_rows 42") {
		t.Fatal("stale gauge value must not accumulate")
	}
}
