// Package debugsrv serves net/http/pprof on a separate listener.
//
// It is a separate package, not a function in internal/api, and that is
// deliberate. The route guards in internal/api walk every Handle/HandleFunc
// in that package with go/ast and fail on any pattern that is not a plain
// "METHOD /path" literal - because a carve-out by shape was once shown to
// hide a real route from both guards. pprof registers five method-less
// patterns, so putting them in internal/api would have meant relaxing that
// rule. Moving the listener out keeps the API surface exactly as strict as
// it was, and makes the separation a real one rather than an exception:
// these handlers are not part of the API and never share its mux, its
// middleware, its authentication or its rate limiting.
package debugsrv

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// Start serves pprof on addr and returns immediately. An empty addr does
// nothing at all, which is the default and the only correct production
// value: these handlers expose stack traces, heap contents and the process
// command line, and /debug/pprof/profile burns CPU for as long as a caller
// asks it to. Bind it to loopback or a pod-local address and reach it
// through a port-forward.
//
// It exists because a stall could not be diagnosed. Writes collapsed from
// 516 rps at c=8 to 18 rps at c=32 on a 26.9M-contact dataset, and every
// database measurement said the database was innocent: zero active queries,
// zero ungranted locks, twelve connections held idle-in-transaction for
// ninety seconds while requests timed out. That localises the problem to the
// server process and then stops, because there was no way to ask the process
// what its goroutines were doing. SIGQUIT answers that once, by killing the
// server - which is not an option on the instance actually misbehaving.
func Start(ctx context.Context, addr string, log *slog.Logger) error {
	if addr == "" {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("debug listener on %s: %w", addr, err)
	}
	// No WriteTimeout: /debug/pprof/profile blocks for its sample duration
	// (30s by default), and a write timeout would truncate every profile.
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Warn("pprof debug listener is ENABLED - it exposes stack traces, heap contents and the "+
		"command line, and must not be reachable from outside the host or pod",
		"addr", ln.Addr().String())
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Error("debug listener", "err", err.Error())
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	return nil
}
