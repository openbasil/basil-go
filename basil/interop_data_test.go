package basil_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/openbasil/basil-go/basil"
)

// The data-plane interop tests round-trip AEAD / secrets / status / certificate
// issuance against a live basil-agent. They are gated on BASIL_SOCKET and skip
// when it is unset, so a normal `go test ./...` stays self-contained. Boot an
// agent (which provisions all the fixtures these tests use) with:
//
//	scripts/interop-agent.sh
//
// The default catalog ids match scripts/prefill-test-store.sh; override them via
// the BASIL_*_ID environment variables to point at a different catalog.

func interopDial(t *testing.T) *basil.Client {
	t.Helper()
	socket := os.Getenv("BASIL_SOCKET")
	if socket == "" {
		t.Skip("BASIL_SOCKET not set; skipping live-agent interop test")
	}
	client, err := basil.Dial(socket, basil.WithTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("dial %q: %v", socket, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// TestInteropStatus calls AdminService.Status and asserts the broker reports a
// backend, a build version, and a wire protocol version.
func TestInteropStatus(t *testing.T) {
	client := interopDial(t)

	st, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	t.Logf("status: backend=%q version=%q protocol=%d", st.Backend, st.Version, st.Protocol)
	if st.Backend == "" {
		t.Error("status returned an empty backend")
	}
	if st.Version == "" {
		t.Error("status returned an empty version")
	}
	if st.Protocol == 0 {
		t.Error("status returned protocol 0")
	}

	// Health is the cheap liveness signal and must agree on the version.
	h, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if !h.Alive {
		t.Error("health reported not alive")
	}
	if h.Version != st.Version {
		t.Errorf("health version %q != status version %q", h.Version, st.Version)
	}
}

// TestInteropAEAD round-trips AEAD encrypt/decrypt against the live broker: the
// broker owns the nonce, so the client supplies only plaintext + optional AAD
// and gets back a self-describing ciphertext envelope.
func TestInteropAEAD(t *testing.T) {
	client := interopDial(t)
	keyID := envOr("BASIL_AEAD_KEY_ID", "app.aead")
	ctx := context.Background()
	plaintext := []byte("basil-go aead interop round trip")
	aad := []byte("interop-context")

	ct, err := client.Encrypt(ctx, keyID, basil.AeadAlgorithmAES256GCM, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// The envelope nonce can be empty when the backend (e.g. Vault/OpenBao
	// transit) embeds the nonce inside the ciphertext blob; the round-trip
	// below is the real correctness proof.
	if len(ct.Bytes) == 0 {
		t.Fatalf("broker returned an empty ciphertext: %+v", ct)
	}
	t.Logf("ciphertext: alg=%s keyVersion=%d nonce=%d bytes=%d", ct.Algorithm, ct.KeyVersion, len(ct.Nonce), len(ct.Bytes))

	got, err := client.Decrypt(ctx, keyID, ct, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypt = %q, want %q", got, plaintext)
	}

	// Negative: decrypting with the wrong AAD must fail (the tag binds the AAD).
	if _, err := client.Decrypt(ctx, keyID, ct, []byte("wrong-context")); err == nil {
		t.Fatal("decrypt accepted a mismatched AAD")
	}
}

// TestInteropSecret reads a pre-filled KV secret and proves a write creates a
// new version. (RotateSecret is not exercised here: a plain value secret has no
// generate recipe (the broker directs callers to set a new value instead), so
// rotate applies only to keys, which the RotateSecret unit test covers.)
func TestInteropSecret(t *testing.T) {
	client := interopDial(t)
	secretID := envOr("BASIL_SECRET_ID", "app.db_password")
	ctx := context.Background()

	sec, err := client.GetSecret(ctx, secretID, nil)
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if len(sec.Value) == 0 {
		t.Fatal("broker returned an empty secret value")
	}
	t.Logf("secret %s: version=%d bytes=%d", secretID, sec.Version, len(sec.Value))

	set, err := client.SetSecret(ctx, secretID, []byte("basil-go-interop-rotated"))
	if err != nil {
		t.Fatalf("set secret: %v", err)
	}
	if set <= sec.Version {
		t.Errorf("set version %d did not advance past %d", set, sec.Version)
	}

	// The new version reads back as what we wrote.
	got, err := client.GetSecret(ctx, secretID, &set)
	if err != nil {
		t.Fatalf("get secret (v%d): %v", set, err)
	}
	if string(got.Value) != "basil-go-interop-rotated" {
		t.Errorf("secret v%d = %q, want the value we set", set, got.Value)
	}
}

// TestInteropIssueCertificate issues an X.509 leaf from the broker's PKI issue
// role and asserts a leaf certificate and its private key come back.
func TestInteropIssueCertificate(t *testing.T) {
	client := interopDial(t)
	issuer := envOr("BASIL_CERT_ISSUER_ID", "web.tls.cert_issuer")

	cert, err := client.IssueCertificate(context.Background(), basil.CertificateRequest{
		IssuerKeyID: issuer,
		CommonName:  "svc.example.org",
		DNSSANs:     []string{"svc.example.org"},
		TTL:         time.Hour,
	})
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	if len(cert.CertChainDER) == 0 || len(cert.CertChainDER[0]) == 0 {
		t.Fatal("broker returned an empty certificate chain")
	}
	if len(cert.PrivateKeyDER) == 0 {
		t.Fatal("broker returned an empty leaf private key")
	}
	t.Logf("issued leaf: chain=%d certs, privateKey=%d bytes, caChain=%d",
		len(cert.CertChainDER), len(cert.PrivateKeyDER), len(cert.CAChainDER))
}
