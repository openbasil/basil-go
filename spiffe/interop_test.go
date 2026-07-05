package spiffe_test

import (
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/openbasil/basil-go/spiffe"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// TestInteropSPIFFE fetches and uses real SVIDs from a live, spiffe-enabled
// basil-agent over its Unix socket. It is gated on BASIL_SOCKET and skips when
// unset, so a normal `go test ./...` stays self-contained.
//
// Boot a spiffe-enabled agent and run it with the existing harness, which boots
// a dev backend, provisions the SPIFFE issuers (catalog keys spiffe.x509_issuer
// + spiffe.jwt_issuer, trust domain example.org), and runs every `Interop`
// test against the agent socket:
//
//	scripts/interop-agent.sh
//
// or point it at an already-running spiffe-enabled agent:
//
//	BASIL_SOCKET=/path/to/agent.sock go test -run Interop ./spiffe/...
//
// Override the expected trust domain / requested audience with
// BASIL_SPIFFE_TRUST_DOMAIN and BASIL_SPIFFE_AUDIENCE.
func TestInteropSPIFFE(t *testing.T) {
	socket := os.Getenv("BASIL_SOCKET")
	if socket == "" {
		t.Skip("BASIL_SOCKET not set; skipping live SPIFFE Workload API interop test")
	}
	tdName := os.Getenv("BASIL_SPIFFE_TRUST_DOMAIN")
	if tdName == "" {
		tdName = "example.org"
	}
	audience := os.Getenv("BASIL_SPIFFE_AUDIENCE")
	if audience == "" {
		audience = "spiffe://example.org/basil-go-interop"
	}
	td := spiffeid.RequireTrustDomainFromString(tdName)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := spiffe.Dial(ctx, socket, spiffe.WithTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("dial %q: %v", socket, err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// --- X.509-SVID: the workload's own identity, key included. ---
	svid, err := c.FetchX509SVID(ctx)
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	if svid.ID.TrustDomain() != td {
		t.Errorf("x509 svid trust domain = %s, want %s", svid.ID.TrustDomain(), td)
	}
	if svid.ID.Path() == "" {
		t.Error("x509 svid SPIFFE ID has an empty (root) path")
	}
	if len(svid.Certificates) == 0 {
		t.Fatal("x509 svid returned no certificates")
	}
	if svid.PrivateKey == nil {
		t.Error("x509 svid returned no private key (a workload must receive its own SVID key)")
	}
	leaf := svid.Certificates[0]
	if !leaf.NotAfter.After(time.Now()) {
		t.Errorf("x509 svid leaf already expired at %v", leaf.NotAfter)
	}
	// Cross-check: the leaf's sole URI SAN matches the parsed SPIFFE ID.
	if got := uriSAN(leaf); got != svid.ID.String() {
		t.Errorf("leaf URI SAN = %q, want %q", got, svid.ID.String())
	}
	t.Logf("x509-svid id=%s chain=%d notAfter=%s", svid.ID, len(svid.Certificates), leaf.NotAfter.Format(time.RFC3339))

	// --- X.509 trust bundle for the trust domain. ---
	x509Set, err := c.FetchX509Bundles(ctx)
	if err != nil {
		t.Fatalf("FetchX509Bundles: %v", err)
	}
	if b, err := x509Set.GetX509BundleForTrustDomain(td); err != nil {
		t.Errorf("no x509 bundle for %s: %v", td, err)
	} else if len(b.X509Authorities()) == 0 {
		t.Errorf("x509 bundle for %s has no authorities", td)
	}

	// --- JWT-SVID for a requested audience, then validate it. ---
	jwtSVID, err := c.FetchJWTSVID(ctx, audience)
	if err != nil {
		t.Fatalf("FetchJWTSVID: %v", err)
	}
	if jwtSVID.ID.TrustDomain() != td {
		t.Errorf("jwt svid trust domain = %s, want %s", jwtSVID.ID.TrustDomain(), td)
	}
	if jwtSVID.Marshal() == "" {
		t.Error("jwt svid token is empty")
	}
	if !containsString(jwtSVID.Audience, audience) {
		t.Errorf("jwt svid audience %v missing %q", jwtSVID.Audience, audience)
	}
	t.Logf("jwt-svid id=%s aud=%v expiry=%s", jwtSVID.ID, jwtSVID.Audience, jwtSVID.Expiry.Format(time.RFC3339))

	validated, err := c.ValidateJWTSVID(ctx, jwtSVID.Marshal(), audience)
	if err != nil {
		t.Fatalf("ValidateJWTSVID: %v", err)
	}
	if validated.ID != jwtSVID.ID {
		t.Errorf("validated id = %s, want %s", validated.ID, jwtSVID.ID)
	}

	// --- JWT trust bundle (JWKS) for offline validation. ---
	jwtSet, err := c.FetchJWTBundles(ctx)
	if err != nil {
		t.Fatalf("FetchJWTBundles: %v", err)
	}
	if b, err := jwtSet.GetJWTBundleForTrustDomain(td); err != nil {
		t.Errorf("no jwt bundle for %s: %v", td, err)
	} else if len(b.JWTAuthorities()) == 0 {
		t.Errorf("jwt bundle for %s has no authorities", td)
	}
}

func uriSAN(cert *x509.Certificate) string {
	if len(cert.URIs) == 0 {
		return ""
	}
	return cert.URIs[0].String()
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
