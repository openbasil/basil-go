package basil_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"testing"
	"time"

	"github.com/openbasil/basil-go/basil"
)

// TestInteropSignVerify round-trips sign/verify/get-public-key against a live
// basil-agent. It is gated on the BASIL_SOCKET environment variable and skips
// when unset, so a normal `go test ./...` stays self-contained.
//
// Boot an agent and run it with:
//
//	scripts/interop-agent.sh
//
// or point it at an already-running agent:
//
//	BASIL_SOCKET=/path/to/agent.sock \
//	  BASIL_KEY_ID=web.tls.signing_key go test -run Interop ./...
func TestInteropSignVerify(t *testing.T) {
	socket := os.Getenv("BASIL_SOCKET")
	if socket == "" {
		t.Skip("BASIL_SOCKET not set; skipping live-agent interop test")
	}
	keyID := os.Getenv("BASIL_KEY_ID")
	if keyID == "" {
		keyID = "web.tls.signing_key"
	}

	client, err := basil.Dial(socket, basil.WithTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("dial %q: %v", socket, err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	message := []byte("basil-go interop round trip")

	pub, err := client.GetPublicKey(ctx, keyID, nil)
	if err != nil {
		t.Fatalf("get public key: %v", err)
	}
	if len(pub.Bytes) == 0 {
		t.Fatal("broker returned an empty public key")
	}
	t.Logf("key %s: type=%s version=%d public=%d bytes", pub.KeyID, pub.KeyType, pub.Version, len(pub.Bytes))

	sig, err := client.Sign(ctx, keyID, message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("broker returned an empty signature")
	}

	ok, err := client.Verify(ctx, keyID, message, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("broker rejected a signature it just produced")
	}

	// Negative: a tampered message must not verify.
	tampered := append(bytes.Clone(message), '!')
	bad, err := client.Verify(ctx, keyID, tampered, sig)
	if err != nil {
		t.Fatalf("verify (tampered): %v", err)
	}
	if bad {
		t.Fatal("broker accepted a signature over a tampered message")
	}

	// Cross-implementation proof: when the key is raw Ed25519, the Go standard
	// library verifies the broker-produced signature against the fetched public
	// key with no help from the broker.
	if pub.KeyType == basil.KeyTypeEd25519 && len(pub.Bytes) == ed25519.PublicKeySize {
		if !ed25519.Verify(ed25519.PublicKey(pub.Bytes), message, sig) {
			t.Fatal("crypto/ed25519 failed to verify a broker Ed25519 signature")
		}
		t.Log("crypto/ed25519 independently verified the broker signature")
	}
}
