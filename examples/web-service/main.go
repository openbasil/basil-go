// Command web-service is a minimal HTTP token service that never holds a
// signing key: POST /token asks the local Basil broker to mint a short-lived
// JWT under the catalog key named by BASIL_SIGNING_KEY_ID.
//
// The broker attests THIS process by its kernel-verified uid (SO_PEERCRED),
// and policy grants it exactly `mint` + `get_public_key` on that key. There
// is no key file, no JWT_SECRET env var, nothing in process memory to leak.
// run.sh proves the flip side too: even a plain read of the same key under
// the same uid is denied.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/openbasil/basil-go/basil"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	socket := envOr("BASIL_SOCKET", "/tmp/basil-web-go/agent.sock")
	bind := envOr("BIND_ADDR", "127.0.0.1:8096")
	keyID := envOr("BASIL_SIGNING_KEY_ID", "web.signing_key")

	// The socket path is the service's ONLY crypto wiring. Dial is lazy: an
	// unreachable broker surfaces on the first RPC, not here.
	client, err := basil.Dial(socket)
	if err != nil {
		log.Fatalf("dial broker at %s: %v", socket, err)
	}
	defer client.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	// POST /token: the broker builds and signs the JWT in place and returns
	// only the compact token. Policy — not application code — decides whether
	// this process may mint under keyID.
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		cred, err := client.MintJwt(ctx, basil.JwtRequest{
			KeyID:   keyID,
			Subject: "web-service-go-demo",
			TTL:     5 * time.Minute, // expires on its own: a lease, not a secret
			Claims:  map[string]string{"scope": "demo"},
		})
		if err != nil {
			// Any broker refusal (policy deny, agent down) is a plain 502:
			// the service has no fallback key to sign with.
			http.Error(w, "mint refused: "+err.Error(), http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, cred.Token)
	})

	log.Printf("listening on http://%s (broker: %s)", bind, socket)
	log.Fatal(http.ListenAndServe(bind, mux))
}
