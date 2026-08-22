// Package metrics is a minimal Prometheus text-format registry.
//
// Hand-rolled instead of prometheus/client_golang to keep the dependency
// tree small (the "stdlib first" policy): the service needs counters and
// one latency histogram shape, nothing more.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
)

var buckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5}

type histogram struct {
	counts []uint64 // one per bucket, cumulative semantics applied at render time
	sum    float64
	total  uint64
}

// Registry collects counters and latency histograms; safe for concurrent use.
type Registry struct {
	mu       sync.Mutex
	counters map[string]uint64
	hists    map[string]*histogram
}

func New() *Registry {
	return &Registry{counters: map[string]uint64{}, hists: map[string]*histogram{}}
}

// Inc increments a counter. series is the full name with labels,
// e.g. `sunder_requests_total{handler="lookup",code="200"}`.
func (r *Registry) Inc(series string) {
	r.mu.Lock()
	r.counters[series]++
	r.mu.Unlock()
}

// Observe records one duration (seconds) into the named histogram,
// e.g. base `sunder_request_seconds{handler="lookup"}`.
func (r *Registry) Observe(base string, seconds float64) {
	r.mu.Lock()
	h := r.hists[base]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(buckets))}
		r.hists[base] = h
	}
	for i, b := range buckets {
		if seconds <= b {
			h.counts[i]++
			break
		}
	}
	h.sum += seconds
	h.total++
	r.mu.Unlock()
}

// splitSeries separates `name{labels}` into name and `label="x",` prefix form.
func splitSeries(series string) (name, labels string) {
	for i, ch := range series {
		if ch == '{' {
			return series[:i], series[i+1 : len(series)-1]
		}
	}
	return series, ""
}

// ServeHTTP renders the registry in Prometheus text exposition format.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	names := make([]string, 0, len(r.counters))
	for k := range r.counters {
		names = append(names, k)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	for _, series := range names {
		name, _ := splitSeries(series)
		if !seen[name] {
			fmt.Fprintf(w, "# TYPE %s counter\n", name)
			seen[name] = true
		}
		fmt.Fprintf(w, "%s %d\n", series, r.counters[series])
	}

	hnames := make([]string, 0, len(r.hists))
	for k := range r.hists {
		hnames = append(hnames, k)
	}
	sort.Strings(hnames)
	for _, series := range hnames {
		h := r.hists[series]
		name, labels := splitSeries(series)
		if !seen[name] {
			fmt.Fprintf(w, "# TYPE %s histogram\n", name)
			seen[name] = true
		}
		sep := ""
		if labels != "" {
			sep = ","
		}
		var cum uint64
		for i, b := range buckets {
			cum += h.counts[i]
			fmt.Fprintf(w, "%s_bucket{%s%sle=\"%g\"} %d\n", name, labels, sep, b, cum)
		}
		fmt.Fprintf(w, "%s_bucket{%s%sle=\"+Inf\"} %d\n", name, labels, sep, h.total)
		fmt.Fprintf(w, "%s_sum{%s} %g\n", name, labels, h.sum)
		fmt.Fprintf(w, "%s_count{%s} %d\n", name, labels, h.total)
	}
}
