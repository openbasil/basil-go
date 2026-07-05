package sealedinvocation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha3"
	"testing"
	"time"
)

func repeatedByte(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestBuildRequestAndOpenResponse(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clientSeed := repeatedByte(0x11)
	brokerSeed := repeatedByte(0x22)
	requestPrivate := repeatedByte(0x33)
	responsePrivate := repeatedByte(0x44)

	requestPublic, err := X25519Public(requestPrivate)
	if err != nil {
		t.Fatalf("request public: %v", err)
	}
	responsePublic, err := X25519Public(responsePrivate)
	if err != nil {
		t.Fatalf("response public: %v", err)
	}

	request, err := BuildRequest(RequestParams{
		ContentType:     "application/basil.go-test-request",
		Plaintext:       []byte("go sealed request"),
		Issuer:          "client",
		IssuedAt:        now,
		TTL:             2 * time.Minute,
		MessageID:       []byte("request-1"),
		SenderKeyID:     "client.signing",
		SenderSeed:      clientSeed,
		RecipientKeyID:  "request.sealing",
		RecipientPublic: requestPublic,
		ResponseKeyID:   "response.sealing",
	})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	requestHash := sha3.Sum256(request.Message)
	response, err := buildSealed(
		"application/basil.go-test-response",
		[]byte("go sealed response"),
		claims{
			issuer:      "broker",
			issuedAt:    now.Unix(),
			expiresAt:   now.Add(2 * time.Minute).Unix(),
			messageID:   []byte("response-1"),
			senderKeyID: "broker.signing",
			inReplyTo:   request.MessageID,
			requestHash: requestHash[:],
		},
		"broker.signing",
		brokerSeed,
		"response.sealing",
		responsePublic,
	)
	if err != nil {
		t.Fatalf("build response: %v", err)
	}
	brokerPublic := ed25519.NewKeyFromSeed(brokerSeed).Public().(ed25519.PublicKey)
	opened, err := OpenResponse(ResponseParams{
		Message:             response,
		Request:             request.Message,
		RequestMessageID:    request.MessageID,
		ExpectedContentType: "application/basil.go-test-response",
		Now:                 now,
		BrokerKeyID:         "broker.signing",
		BrokerPublic:        brokerPublic,
		RecipientKeyID:      "response.sealing",
		RecipientPrivate:    responsePrivate,
	})
	if err != nil {
		t.Fatalf("open response: %v", err)
	}
	if !bytes.Equal(opened.Plaintext, []byte("go sealed response")) {
		t.Fatalf("plaintext = %q", opened.Plaintext)
	}
}
