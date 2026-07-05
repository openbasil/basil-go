// Command cose-nats-telemetry shows two services exchanging COSE-signed
// telemetry over NATS using nothing but Basil-minted leases and in-place
// signatures. No NKey seed and no signing key ever leaves the vault.
//
// It runs in two modes so run.sh can wire an operator-mode nats-server between
// them:
//
//	EXAMPLE_MODE=provision  Mint the operator -> account -> user NATS credential
//	                        chain via the Go client and emit the JWTs the
//	                        nats-server memory resolver needs.
//	EXAMPLE_MODE=telemetry  Connect with the minted user JWT (the server nonce is
//	                        signed in place by the broker), publish a bare
//	                        COSE_Sign1 telemetry message signed by a broker-backed
//	                        remote signer, verify it on the subscriber against the
//	                        broker's published public key, and prove a tampered
//	                        message is rejected.
//
// Every step prints a machine-checkable `PASS ...` line; the program exits
// non-zero on the first failure.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/openbasil/basil-go/basil"
	cose "github.com/veraison/go-cose"
)

// Catalog key names and the NATS subject, fixed by run.sh's provisioning.
const (
	operatorKeyID = "nats.operator"
	accountKeyID  = "nats.account"
	userKeyID     = "nats.user"
	coseKeyID     = "telemetry.sign"
	subject       = "telemetry.metrics"
)

type config struct {
	mode        string
	socket      string
	natsURL     string
	fixturesDir string
}

func loadConfig() config {
	return config{
		mode:        os.Getenv("EXAMPLE_MODE"),
		socket:      envOr("BASIL_SOCKET", "/tmp/basil-cose-nats/agent.sock"),
		natsURL:     envOr("BASIL_NATS_URL", "nats://127.0.0.1:4250"),
		fixturesDir: envOr("NATS_FIXTURES_DIR", "/tmp/basil-cose-nats/fixtures"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	cfg := loadConfig()
	var err error
	switch cfg.mode {
	case "provision":
		err = provision(cfg)
	case "telemetry":
		err = telemetry(cfg)
	default:
		err = fmt.Errorf("set EXAMPLE_MODE to provision or telemetry, got %q", cfg.mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

// provision mints the operator -> account -> user chain and writes the artifacts
// the nats-server operator config + memory resolver need. The operator and
// account identities are catalog NKeys the broker signs with in place; the
// public halves are derived here from the broker's published raw keys.
func provision(cfg config) error {
	client, err := basil.Dial(cfg.socket)
	if err != nil {
		return fmt.Errorf("dial broker at %s: %w", cfg.socket, err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	operatorPub, err := publicNKey(ctx, client, operatorKeyID, nkeys.PrefixByteOperator)
	if err != nil {
		return err
	}
	accountPub, err := publicNKey(ctx, client, accountKeyID, nkeys.PrefixByteAccount)
	if err != nil {
		return err
	}
	userPub, err := publicNKey(ctx, client, userKeyID, nkeys.PrefixByteUser)
	if err != nil {
		return err
	}

	operatorJWT, err := client.MintNatsOperator(ctx, basil.NatsOperatorRequest{
		KeyID: operatorKeyID,
		Name:  "basil-telemetry-operator",
	})
	if err != nil {
		return fmt.Errorf("mint operator JWT: %w", err)
	}
	// The account JWT is signed in place by the operator key. This example uses
	// SignNatsJwt so it can pin an explicit limits block; MintNatsAccount now
	// defaults to unlimited limits. See the README's "Rough edge" note.
	accountJWT, err := client.SignNatsJwt(ctx, basil.NatsJwtRequest{
		KeyID:        operatorKeyID,
		ExpectedType: basil.NatsJwtTypeAccount,
		Claims: map[string]any{
			"sub":  accountPub,
			"name": "TELEMETRY",
			"nats": map[string]any{
				"type":    "account",
				"version": 2,
				"limits": map[string]any{
					"subs":      -1,
					"data":      -1,
					"payload":   -1,
					"conn":      -1,
					"leaf":      -1,
					"imports":   -1,
					"exports":   -1,
					"wildcards": true,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("sign account JWT: %w", err)
	}
	userJWT, err := client.MintNatsUser(ctx, basil.NatsUserRequest{
		KeyID:           accountKeyID,
		SubjectUserNKey: userPub,
		Name:            "telemetry-workload",
		TTL:             10 * time.Minute,
		PubAllow:        []string{"telemetry.>"},
		SubAllow:        []string{"telemetry.>"},
	})
	if err != nil {
		return fmt.Errorf("mint user JWT: %w", err)
	}

	if err := os.MkdirAll(cfg.fixturesDir, 0o700); err != nil {
		return err
	}
	writes := map[string]string{
		"operator.jwt": operatorJWT.Token,
		"account.jwt":  accountJWT.Token,
		"account.nkey": accountPub,
		"user.jwt":     userJWT.Token,
	}
	for name, content := range writes {
		if err := os.WriteFile(filepath.Join(cfg.fixturesDir, name), []byte(content), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	fmt.Printf("PASS minted operator O=%s...\n", short(operatorPub))
	fmt.Printf("PASS minted account A=%s... (lease exp=%s)\n", short(accountPub), expiry(accountJWT))
	fmt.Printf("PASS minted user U=%s... (lease exp=%s)\n", short(userPub), expiry(userJWT))
	return nil
}

// telemetry connects two authenticated NATS clients (a publisher and a
// subscriber), each using the minted user JWT with the server nonce signed in
// place by the broker, and exchanges a COSE_Sign1 telemetry message signed by a
// broker-backed remote signer.
func telemetry(cfg config) error {
	client, err := basil.Dial(cfg.socket)
	if err != nil {
		return fmt.Errorf("dial broker at %s: %w", cfg.socket, err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	userJWT, err := os.ReadFile(filepath.Join(cfg.fixturesDir, "user.jwt"))
	if err != nil {
		return fmt.Errorf("read minted user JWT: %w", err)
	}

	subConn, err := connectNATS(cfg.natsURL, string(userJWT), client)
	if err != nil {
		return fmt.Errorf("subscriber connect: %w", err)
	}
	defer subConn.Close()
	pubConn, err := connectNATS(cfg.natsURL, string(userJWT), client)
	if err != nil {
		return fmt.Errorf("publisher connect: %w", err)
	}
	defer pubConn.Close()
	fmt.Println("PASS nats connect authenticated via minted user JWT + in-place nonce signing")

	sub, err := subConn.SubscribeSync(subject)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	if err := subConn.Flush(); err != nil {
		return err
	}

	payload := []byte(`{"service":"checkout","region":"eu-west-1","cpu":0.42,"rps":1287}`)
	signed, err := signTelemetry(ctx, client, payload)
	if err != nil {
		return fmt.Errorf("COSE sign: %w", err)
	}
	fmt.Printf("PASS cose_sign1 built bytes=%d\n", len(signed))

	// Fetch the broker's published public key once; the subscriber verifies
	// every message against it. The private half never leaves the vault.
	pub, err := client.GetPublicKey(ctx, coseKeyID, nil)
	if err != nil {
		return fmt.Errorf("fetch COSE public key: %w", err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, ed25519.PublicKey(pub.Bytes))
	if err != nil {
		return fmt.Errorf("build verifier: %w", err)
	}

	// Good message: publish, receive, verify, assert payload equality.
	if err := pubConn.Publish(subject, signed); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	if err := pubConn.Flush(); err != nil {
		return err
	}
	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		return fmt.Errorf("receive telemetry: %w", err)
	}
	gotPayload, err := verifyTelemetry(msg.Data, verifier)
	if err != nil {
		return fmt.Errorf("verify received telemetry: %w", err)
	}
	if string(gotPayload) != string(payload) {
		return fmt.Errorf("payload mismatch: got %q want %q", gotPayload, payload)
	}
	fmt.Println("PASS subscriber verified cose_sign1 and payload matches")

	// Tampered message: flip one byte, publish, receive, assert verify fails.
	tampered := make([]byte, len(signed))
	copy(tampered, signed)
	tampered[len(tampered)-1] ^= 0x01 // last signature byte
	if err := pubConn.Publish(subject, tampered); err != nil {
		return fmt.Errorf("publish tampered: %w", err)
	}
	if err := pubConn.Flush(); err != nil {
		return err
	}
	badMsg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		return fmt.Errorf("receive tampered telemetry: %w", err)
	}
	if _, err := verifyTelemetry(badMsg.Data, verifier); err == nil {
		return errors.New("subscriber accepted a tampered COSE_Sign1")
	}
	fmt.Println("PASS subscriber rejected tampered cose_sign1")
	return nil
}

// --- COSE remote signer over the broker ------------------------------------

// brokerCOSESigner adapts the broker's in-place signing to go-cose's Signer
// interface: go-cose hands it the COSE ToBeSigned bytes and the broker returns a
// raw EdDSA signature over them. The Ed25519 private key stays in the vault.
type brokerCOSESigner struct {
	ctx    context.Context
	client *basil.Client
	keyID  string
}

func (s *brokerCOSESigner) Algorithm() cose.Algorithm { return cose.AlgorithmEdDSA }

func (s *brokerCOSESigner) Sign(_ io.Reader, content []byte) ([]byte, error) {
	return s.client.Sign(s.ctx, s.keyID, content)
}

func signTelemetry(ctx context.Context, client *basil.Client, payload []byte) ([]byte, error) {
	signer := &brokerCOSESigner{ctx: ctx, client: client, keyID: coseKeyID}
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: cose.AlgorithmEdDSA,
			cose.HeaderLabelKeyID:     []byte(coseKeyID),
		},
	}
	return cose.Sign1(rand.Reader, signer, headers, payload, nil)
}

func verifyTelemetry(taggedCOSE []byte, verifier cose.Verifier) ([]byte, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(taggedCOSE); err != nil {
		return nil, err
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, err
	}
	return msg.Payload, nil
}

// --- NATS auth with in-place nonce signing ---------------------------------

// connectNATS opens a NATS connection using the minted user JWT. The server
// nonce is routed through the broker's Sign RPC on the user's catalog NKey, so
// the seed never leaves the vault; the broker's raw Ed25519 signature is exactly
// what the NATS handshake expects.
func connectNATS(url, userJWT string, client *basil.Client) (*nats.Conn, error) {
	userCB := func() (string, error) { return userJWT, nil }
	sigCB := func(nonce []byte) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return client.Sign(ctx, userKeyID, nonce)
	}
	return nats.Connect(url,
		nats.UserJWT(userCB, sigCB),
		nats.Name("basil-cose-nats-telemetry"),
		nats.MaxReconnects(3),
		nats.Timeout(5*time.Second),
	)
}

// --- small helpers ----------------------------------------------------------

// publicNKey fetches a catalog key's raw Ed25519 public half from the broker and
// encodes it as the NATS public NKey for the given role.
func publicNKey(ctx context.Context, client *basil.Client, keyID string, prefix nkeys.PrefixByte) (string, error) {
	pub, err := client.GetPublicKey(ctx, keyID, nil)
	if err != nil {
		return "", fmt.Errorf("get public key %s: %w", keyID, err)
	}
	encoded, err := nkeys.Encode(prefix, pub.Bytes)
	if err != nil {
		return "", fmt.Errorf("encode NKey for %s: %w", keyID, err)
	}
	return string(encoded), nil
}

func short(nkey string) string {
	if len(nkey) <= 12 {
		return nkey
	}
	return nkey[:12]
}

func expiry(c *basil.Credential) string {
	if c.ExpiresAt.IsZero() {
		return "never"
	}
	return c.ExpiresAt.UTC().Format(time.RFC3339)
}
