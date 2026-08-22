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
