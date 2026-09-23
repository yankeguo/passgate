package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	listen := envOr("PASSGATE_LISTEN", ":8080")
	upstream := envOr("PASSGATE_UPSTREAM", "")
	dataDir := envOr("PASSGATE_DATA_DIR", "./data")
	sessionTTL := durationEnvOr("PASSGATE_SESSION_TTL", 168*time.Hour)
	origin := envOr("PASSGATE_ORIGIN", "")
	title := envOr("PASSGATE_TITLE", defaultTitle)

	flag.StringVar(&listen, "listen", listen, "http listen address")
	flag.StringVar(&upstream, "upstream", upstream, "upstream service URL to proxy to (required)")
	flag.StringVar(&dataDir, "data-dir", dataDir, "directory for gate state (credential, signing secret)")
	flag.DurationVar(&sessionTTL, "session-ttl", sessionTTL, "how long a successful passkey verification stays valid")
	flag.StringVar(&origin, "origin", origin, "pin the externally visible origin (e.g. https://gate.example.com); derived per request if empty")
	flag.StringVar(&title, "title", title, "gate page title shown in the browser tab and header")
	flag.Parse()

	if upstream == "" {
		log.Fatal("upstream is required: set PASSGATE_UPSTREAM or pass -upstream")
	}
	upstreamURL, err := url.Parse(upstream)
	if err != nil || upstreamURL.Scheme == "" || upstreamURL.Host == "" {
		log.Fatalf("invalid upstream URL %q", upstream)
	}

	store, err := OpenStore(dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}

	gate := NewGate(store, sessionTTL, origin, title)
	// No server-side timeouts: the gate must be a transparent proxy, so
	// slow requests and long-lived connections (SSE, WebSocket, big
	// uploads) are never cut short here. Timeout policy is left to the
	// client and the upstream.
	srv := &http.Server{
		Addr:    listen,
		Handler: NewServer(gate, newProxy(upstreamURL)).Handler(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Println("listening on", listen, "→", upstreamURL)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Println("exited with error:", err)
			os.Exit(1)
		}
		return
	case <-ctx.Done():
		log.Println("shutting down")
	}

	// Unregister the signal handler so a second SIGINT/SIGTERM terminates
	// immediately, then wait for in-flight requests with no deadline.
	stop()
	if err := srv.Shutdown(context.Background()); err != nil {
		log.Println("shutdown:", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func durationEnvOr(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		log.Printf("invalid duration %s=%q, using %s", key, v, fallback)
	}
	return fallback
}
