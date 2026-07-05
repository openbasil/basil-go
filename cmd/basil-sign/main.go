// Command basil-sign is a small example client for the Basil broker.
//
// It connects to a broker over its Unix-domain socket, signs a message with a
// catalog key, verifies the signature, and prints the key's public half:
//
//	basil-sign -socket /run/basil/broker.sock -key app.signing -message "hello"
//
// It exists to demonstrate the github.com/openbasil/basil-go/basil API; real
// programs import the package directly.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/openbasil/basil-go/basil"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "basil-sign:", err)
		os.Exit(1)
	}
}

func run() error {
	socket := flag.String("socket", "", "path to the basil broker Unix socket (required)")
	keyID := flag.String("key", "", "catalog key id to sign with (required)")
	message := flag.String("message", "hello from basil-go", "message to sign")
	timeout := flag.Duration("timeout", 10*time.Second, "overall deadline")
	flag.Parse()

	if *socket == "" || *keyID == "" {
		flag.Usage()
		return errors.New("both -socket and -key are required")
	}

	client, err := basil.Dial(*socket)
	if err != nil {
		return err
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	pub, err := client.GetPublicKey(ctx, *keyID, nil)
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}
	fmt.Printf("key %s: type=%s version=%d public=%s\n",
		pub.KeyID, pub.KeyType, pub.Version, base64.StdEncoding.EncodeToString(pub.Bytes))

	sig, err := client.Sign(ctx, *keyID, []byte(*message))
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	fmt.Printf("signature: %s\n", base64.StdEncoding.EncodeToString(sig))

	ok, err := client.Verify(ctx, *keyID, []byte(*message), sig)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	fmt.Printf("verify: %t\n", ok)
	if !ok {
		return errors.New("broker rejected a signature it just produced")
	}
	return nil
}
