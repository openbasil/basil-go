package basil_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openbasil/basil-go/basil"
	"google.golang.org/grpc/codes"
)

// ExampleClient demonstrates the full sign / verify / public-key round trip
// against a broker listening on a Unix socket.
func ExampleClient() {
	client, err := basil.Dial("/run/basil/broker.sock")
	if err != nil {
		panic(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const keyID = "app.signing"
	message := []byte("release v1.2.3")

	sig, err := client.Sign(ctx, keyID, message)
	if err != nil {
		panic(err)
	}

	ok, err := client.Verify(ctx, keyID, message, sig)
	if err != nil {
		panic(err)
	}
	fmt.Println("valid:", ok)
}

// ExampleClient_Encrypt round-trips a payload through the broker's AEAD: the
// broker owns the nonce, so the caller supplies only plaintext plus optional
// AAD and gets back a self-describing ciphertext to round-trip to Decrypt.
func ExampleClient_Encrypt() {
	client, err := basil.Dial("/run/basil/broker.sock")
	if err != nil {
		panic(err)
	}
	defer client.Close()

	ctx := context.Background()
	const keyID = "app.aead"
	aad := []byte("tenant=acme") // bound, not encrypted; supply verbatim to Decrypt

	ct, err := client.Encrypt(ctx, keyID, basil.AeadAlgorithmAES256GCM, []byte("card-number"), aad)
	if err != nil {
		panic(err)
	}

	plaintext, err := client.Decrypt(ctx, keyID, ct, aad)
	if err != nil {
		panic(err)
	}
	fmt.Printf("recovered %d bytes\n", len(plaintext))
}

// ExampleClient_MintJwt mints a short-lived JWT signed in place by a catalog
// key, with caller-supplied extra claims.
func ExampleClient_MintJwt() {
	client, err := basil.Dial("/run/basil/broker.sock")
	if err != nil {
		panic(err)
	}
	defer client.Close()

	cred, err := client.MintJwt(context.Background(), basil.JwtRequest{
		KeyID:   "app.signing",
		Subject: "svc-a",
		TTL:     15 * time.Minute,
		Claims:  map[string]any{"scope": "orders:read"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("token expires at", cred.ExpiresAt)
}

// ExampleClient_Status reports the broker's backend, version, and protocol.
func ExampleClient_Status() {
	client, err := basil.Dial("/run/basil/broker.sock")
	if err != nil {
		panic(err)
	}
	defer client.Close()

	st, err := client.Status(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Printf("broker %s on %s (protocol v%d)\n", st.Version, st.Backend, st.Protocol)
}

// ExampleAsStatusError shows how to branch on the broker's machine-readable
// reason when an RPC is denied.
func ExampleAsStatusError() {
	var err error // an error returned by a Client method
	if se, ok := basil.AsStatusError(err); ok {
		switch {
		case se.Code == codes.PermissionDenied && se.Reason == "UNAUTHORIZED":
			fmt.Println("policy denied", se.Op)
		case errors.Is(err, context.DeadlineExceeded):
			fmt.Println("timed out")
		default:
			fmt.Println("broker error:", se.Reason)
		}
	}
}
