package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/nats-io/nats.go"
	"github.com/openbasil/basil-go/basil"
	"github.com/openbasil/basil-go/sealedinvocation"
)

const (
	signRequestContentType  = "application/basil.sign-request"
	signResponseContentType = "application/basil.sign-response"
	defaultRequestBody      = "sealed-cose round-trip request"
	brokerAudience          = "basil://example/nats-cose-courier"
	clientSubject           = "go.client"
	requestSealingKeyID     = "broker.request"
	targetSigningKeyID      = "workload.signing"
	statusOK                = 1
)

type signInvocationRequest struct {
	KeyID     string `cbor:"1,keyasint"`
	Message   []byte `cbor:"2,keyasint"`
	Algorithm int32  `cbor:"3,keyasint"`
}

type signInvocationResponse struct {
	Status           invocationStatus `cbor:"1,keyasint"`
	PolicyGeneration uint64           `cbor:"2,keyasint"`
	Signature        []byte           `cbor:"3,keyasint"`
}

type invocationStatus struct {
	Code      uint64  `cbor:"1,keyasint"`
	Reason    string  `cbor:"2,keyasint"`
	Message   *string `cbor:"3,keyasint"`
	Retryable bool    `cbor:"4,keyasint"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if os.Getenv("EXAMPLE_MODE") == "fixtures" {
		printFixtures()
		return nil
	}
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
	targetSigningPublic, err := hexEnv("BASIL_TARGET_SIGNING_PUBLIC_HEX")
	if err != nil {
		return err
	}
	clientSeed := bytes.Repeat([]byte{7}, 32)
	responsePrivate := bytes.Repeat([]byte{0x22}, 32)
	requestBody, err := cbor.Marshal(signInvocationRequest{
		KeyID:     targetSigningKeyID,
		Message:   []byte(defaultRequestBody),
		Algorithm: int32(basil.SigningAlgorithmEd25519),
	})
	if err != nil {
		return fmt.Errorf("encode sign invocation body: %w", err)
	}

	request, err := sealedinvocation.BuildRequest(sealedinvocation.RequestParams{
		ContentType:     signRequestContentType,
		Plaintext:       requestBody,
		Issuer:          clientSubject,
		Audience:        brokerAudience,
		IssuedAt:        time.Now(),
		TTL:             2 * time.Minute,
		MessageID:       []byte("go-nats-bridge-request"),
		SenderKeyID:     "client.signing",
		SenderSeed:      clientSeed,
		RecipientKeyID:  requestSealingKeyID,
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
		ExpectedContentType: signResponseContentType,
		Now:                 time.Now(),
		BrokerKeyID:         "broker.signing",
		BrokerPublic:        ed25519.PublicKey(brokerPublic),
		RecipientKeyID:      "response.sealing",
		RecipientPrivate:    responsePrivate,
	})
	if err != nil {
		return err
	}
	var response signInvocationResponse
	if err := cbor.Unmarshal(opened.Plaintext, &response); err != nil {
		return fmt.Errorf("decode sign invocation response: %w", err)
	}
	if response.Status.Code != statusOK {
		return fmt.Errorf("sign invocation status %d %s", response.Status.Code, response.Status.Reason)
	}
	if !ed25519.Verify(ed25519.PublicKey(targetSigningPublic), []byte(defaultRequestBody), response.Signature) {
		return fmt.Errorf("broker returned an invalid signature")
	}
	fmt.Printf("PASS sealed sign invocation via basil-nats-bridge key=%s policy_generation=%d signature_len=%d\n",
		targetSigningKeyID, response.PolicyGeneration, len(response.Signature))
	return nil
}

func printFixtures() {
	clientPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	clientPublic := clientPrivate.Public().(ed25519.PublicKey)
	brokerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	brokerPublic := brokerPrivate.Public().(ed25519.PublicKey)
	targetPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, 32))
	targetPublic := targetPrivate.Public().(ed25519.PublicKey)
	requestPrivate := bytes.Repeat([]byte{0x11}, 32)
	requestPublic, err := sealedinvocation.X25519Public(requestPrivate)
	if err != nil {
		panic(err)
	}
	responsePrivate := bytes.Repeat([]byte{0x22}, 32)
	responsePublic, err := sealedinvocation.X25519Public(responsePrivate)
	if err != nil {
		panic(err)
	}
	printAssignment("CLIENT_SIGNING_PUBLIC_B64", base64.RawURLEncoding.EncodeToString(clientPublic))
	printAssignment("BROKER_SIGNING_PRIVATE_B64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	printAssignment("BROKER_SIGNING_PUBLIC_B64", base64.StdEncoding.EncodeToString(brokerPublic))
	printAssignment("BROKER_SIGNING_PUBLIC_HEX", hex.EncodeToString(brokerPublic))
	printAssignment("TARGET_SIGNING_PRIVATE_B64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32)))
	printAssignment("TARGET_SIGNING_PUBLIC_B64", base64.StdEncoding.EncodeToString(targetPublic))
	printAssignment("TARGET_SIGNING_PUBLIC_HEX", hex.EncodeToString(targetPublic))
	printAssignment("REQUEST_SEALING_PRIVATE_B64", base64.StdEncoding.EncodeToString(requestPrivate))
	printAssignment("REQUEST_SEALING_PUBLIC_B64", base64.StdEncoding.EncodeToString(requestPublic))
	printAssignment("REQUEST_SEALING_PUBLIC_HEX", hex.EncodeToString(requestPublic))
	printAssignment("RESPONSE_SEALING_PRIVATE_B64", base64.StdEncoding.EncodeToString(responsePrivate))
	printAssignment("RESPONSE_SEALING_PUBLIC_B64", base64.StdEncoding.EncodeToString(responsePublic))
}

func printAssignment(name, value string) {
	fmt.Printf("%s='%s'\n", name, value)
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
