package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/openbasil/basil-go/sealedinvocation"
)

const (
	defaultRequestBody  = "sealed-cose round-trip request"
	defaultResponseBody = "sealed-cose round-trip response"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	natsURL := requiredEnv("BASIL_NATS_URL")
	subject := requiredEnv("BASIL_NATS_SUBJECT")
	requestRecipientPublic, err := hexEnv("BASIL_REQUEST_RECIPIENT_PUBLIC_HEX")
	if err != nil {
		return err
	}
	brokerPublic, err := hexEnv("BASIL_BROKER_SIGNING_PUBLIC_HEX")
	if err != nil {
		return err
	}
	clientSeed := bytes.Repeat([]byte{7}, 32)
	responsePrivate := bytes.Repeat([]byte{0x22}, 32)

	request, err := sealedinvocation.BuildRequest(sealedinvocation.RequestParams{
		ContentType:     "application/basil.go-nats-bridge-request",
		Plaintext:       []byte(defaultRequestBody),
		Issuer:          "go-client",
		IssuedAt:        time.Now(),
		TTL:             2 * time.Minute,
		MessageID:       []byte("go-nats-bridge-request"),
		SenderKeyID:     "client.signing",
		SenderSeed:      clientSeed,
		RecipientKeyID:  "request.sealing",
		RecipientPublic: requestRecipientPublic,
		ResponseKeyID:   "response.sealing",
	})
	if err != nil {
		return err
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		return fmt.Errorf("connect NATS: %w", err)
	}
	defer nc.Close()
	reply, err := requestWithRetry(nc, subject, request.Message)
	if err != nil {
		return err
	}
	if values := reply.Header.Values("Basil-Bridge-Error"); len(values) != 0 {
		detail := reply.Header.Get("Basil-Bridge-Message")
		return fmt.Errorf("bridge error: %s: %s: %s", strings.Join(values, "; "), detail, string(reply.Data))
	}
	opened, err := sealedinvocation.OpenResponse(sealedinvocation.ResponseParams{
		Message:             reply.Data,
		Request:             request.Message,
		RequestMessageID:    request.MessageID,
		ExpectedContentType: "application/basil.go-nats-bridge-response",
		Now:                 time.Now(),
		BrokerKeyID:         "broker.signing",
		BrokerPublic:        ed25519.PublicKey(brokerPublic),
		RecipientKeyID:      "response.sealing",
		RecipientPrivate:    responsePrivate,
	})
	if err != nil {
		return err
	}
	if string(opened.Plaintext) != defaultResponseBody {
		return fmt.Errorf("response plaintext %q, want %q", opened.Plaintext, defaultResponseBody)
	}
	fmt.Println("go nats cose courier interop ok")
	return nil
}

func requestWithRetry(nc *nats.Conn, subject string, payload []byte) (*nats.Msg, error) {
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		reply, err := nc.Request(subject, payload, 2*time.Second)
		if err == nil {
			return reply, nil
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	return nil, fmt.Errorf("NATS request never received bridge response: %w", lastErr)
}

func requiredEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		fmt.Fprintf(os.Stderr, "%s is required\n", key)
		os.Exit(2)
	}
	return value
}

func hexEnv(key string) ([]byte, error) {
	value := requiredEnv(key)
	out, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not hex: %w", key, err)
	}
	return out, nil
}
