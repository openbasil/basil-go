// Command secrets-and-aead tours Basil's KV + AEAD data plane over the Go
// client: it cycles a versioned KV-v2 secret (set / get / rotate) and encrypts
// and decrypts a payload under a broker-owned AEAD key, including an
// additional-authenticated-data (AAD) mismatch that must fail closed.
//
// Every operation is brokered: the secret bytes and the encryption key stay in
// the vault, and the broker owns the AEAD nonce so a caller cannot choose or
// reuse it. The program prints one machine-checkable `PASS ...` line per proven
// property and exits non-zero on the first failure; run.sh asserts on those
// lines.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/openbasil/basil-go/basil"
)

// config is the example's environment-driven wiring. run.sh sets every value;
// the defaults keep `go run .` usable against a hand-booted agent.
type config struct {
	socket    string
	secretID  string
	aeadKeyID string
}

func loadConfig() config {
	return config{
		socket:    envOr("BASIL_SOCKET", "/tmp/basil-secrets-aead/agent.sock"),
		secretID:  envOr("BASIL_SECRET_ID", "app.session_token"),
		aeadKeyID: envOr("BASIL_AEAD_KEY_ID", "app.aead"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := run(loadConfig()); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	client, err := basil.Dial(cfg.socket)
	if err != nil {
		return fmt.Errorf("dial broker at %s: %w", cfg.socket, err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := secretVersionCycle(ctx, client, cfg.secretID); err != nil {
		return err
	}
	return aeadRoundTripWithAAD(ctx, client, cfg.aeadKeyID)
}

// secretVersionCycle proves the KV-v2 version ladder: two distinct writes bump
// the version and read back verbatim, then a broker-side rotate mints a fresh
// generated value at a strictly higher version.
func secretVersionCycle(ctx context.Context, client *basil.Client, secretID string) error {
	first := []byte("session-token-alpha")
	v1, err := client.SetSecret(ctx, secretID, first)
	if err != nil {
		return fmt.Errorf("set %s (first): %w", secretID, err)
	}
	fmt.Printf("PASS set %s version=%d\n", secretID, v1)

	got1, err := client.GetSecret(ctx, secretID, nil)
	if err != nil {
		return fmt.Errorf("get %s (after first set): %w", secretID, err)
	}
	if !bytes.Equal(got1.Value, first) {
		return fmt.Errorf("get %s returned %q, want %q", secretID, got1.Value, first)
	}
	if got1.Version != v1 {
		return fmt.Errorf("get %s version=%d, want %d", secretID, got1.Version, v1)
	}
	fmt.Printf("PASS get %s roundtrip version=%d\n", secretID, got1.Version)

	second := []byte("session-token-bravo")
	v2, err := client.SetSecret(ctx, secretID, second)
	if err != nil {
		return fmt.Errorf("set %s (second): %w", secretID, err)
	}
	if v2 <= v1 {
		return fmt.Errorf("second set version=%d did not advance past %d", v2, v1)
	}
	fmt.Printf("PASS set %s version=%d\n", secretID, v2)

	v3, err := client.RotateSecret(ctx, secretID)
	if err != nil {
		return fmt.Errorf("rotate %s: %w", secretID, err)
	}
	if v3 <= v2 {
		return fmt.Errorf("rotate version=%d did not advance past %d", v3, v2)
	}
	fmt.Printf("PASS rotate %s version=%d\n", secretID, v3)

	got3, err := client.GetSecret(ctx, secretID, nil)
	if err != nil {
		return fmt.Errorf("get %s (after rotate): %w", secretID, err)
	}
	if got3.Version != v3 {
		return fmt.Errorf("latest version=%d after rotate, want %d", got3.Version, v3)
	}
	if bytes.Equal(got3.Value, second) {
		return errors.New("rotate returned the previous value; expected a freshly generated secret")
	}
	fmt.Printf("PASS version cycle %d<%d<%d rotated-value-differs\n", v1, v2, v3)
	return nil
}

// aeadRoundTripWithAAD encrypts under a broker-owned AEAD key with bound AAD,
// decrypts with the matching AAD, then proves that decrypting with a different
// AAD fails closed. The broker generates the nonce; the caller never supplies
// one.
func aeadRoundTripWithAAD(ctx context.Context, client *basil.Client, keyID string) error {
	plaintext := []byte("telemetry: cpu=0.42 mem=0.71 region=eu-west-1")
	aad := []byte("tenant=acme,stream=telemetry")

	ct, err := client.Encrypt(ctx, keyID, basil.AeadAlgorithmAES256GCM, plaintext, aad)
	if err != nil {
		return fmt.Errorf("encrypt with %s: %w", keyID, err)
	}
	if len(ct.Bytes) == 0 {
		return errors.New("broker returned an empty ciphertext")
	}
	// The nonce is broker-owned; depending on the backend it rides inside the
	// self-describing ciphertext rather than the separate Nonce field. Either
	// way the caller round-trips the whole Ciphertext unchanged.
	fmt.Printf("PASS encrypt %s alg=%s ciphertext_len=%d\n", keyID, ct.Algorithm, len(ct.Bytes))

	recovered, err := client.Decrypt(ctx, keyID, ct, aad)
	if err != nil {
		return fmt.Errorf("decrypt with matching AAD: %w", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		return fmt.Errorf("decrypt returned %q, want %q", recovered, plaintext)
	}
	fmt.Println("PASS decrypt roundtrip matching-aad")

	wrongAAD := []byte("tenant=evil,stream=telemetry")
	if _, err := client.Decrypt(ctx, keyID, ct, wrongAAD); err == nil {
		return errors.New("decrypt with mismatched AAD succeeded; expected authentication failure")
	}
	fmt.Println("PASS decrypt rejected mismatched-aad")
	return nil
}
