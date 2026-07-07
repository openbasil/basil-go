package sealedinvocation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha3"
	"slices"
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
	fixture := responseFixture(t)
	opened, err := OpenResponse(fixture.params)
	if err != nil {
		t.Fatalf("open response: %v", err)
	}
	if !bytes.Equal(opened.Plaintext, []byte("go sealed response")) {
		t.Fatalf("plaintext = %q", opened.Plaintext)
	}
}

func TestOpenResponseRejectsInvalidResponses(t *testing.T) {
	fixture := responseFixture(t)
	tests := []struct {
		name string
		edit func(*ResponseParams)
	}{
		{
			name: "malformed-cbor",
			edit: func(p *ResponseParams) {
				p.Message = []byte{0xff}
			},
		},
		{
			name: "wrong-broker-kid",
			edit: func(p *ResponseParams) {
				p.BrokerKeyID = "wrong.signing"
			},
		},
		{
			name: "wrong-request-id",
			edit: func(p *ResponseParams) {
				p.RequestMessageID = []byte("other-request")
			},
		},
		{
			name: "wrong-request-hash",
			edit: func(p *ResponseParams) {
				p.Request = append([]byte(nil), p.Request...)
				p.Request[0] ^= 1
			},
		},
		{
			name: "expired",
			edit: func(p *ResponseParams) {
				p.Now = fixture.now.Add(4 * time.Minute)
			},
		},
		{
			name: "ttl-too-long",
			edit: func(p *ResponseParams) {
				p.MaxTTL = time.Minute
			},
		},
		{
			name: "wrong-content-type",
			edit: func(p *ResponseParams) {
				p.ExpectedContentType = "application/other"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := fixture.params
			tt.edit(&params)
			if _, err := OpenResponse(params); err == nil {
				t.Fatalf("OpenResponse succeeded")
			}
		})
	}
}

type testResponseFixture struct {
	now    time.Time
	params ResponseParams
}

func responseFixture(t *testing.T) testResponseFixture {
	t.Helper()
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
	return testResponseFixture{
		now: now,
		params: ResponseParams{
			Message:             response,
			Request:             request.Message,
			RequestMessageID:    request.MessageID,
			ExpectedContentType: "application/basil.go-test-response",
			Now:                 now,
			BrokerKeyID:         "broker.signing",
			BrokerPublic:        brokerPublic,
			RecipientKeyID:      "response.sealing",
			RecipientPrivate:    responsePrivate,
		},
	}
}

func TestParseEncryptProtectedCritEnforcement(t *testing.T) {
	claimSet := claims{
		issuer:      "broker",
		issuedAt:    1_800_000_000,
		expiresAt:   1_800_000_120,
		messageID:   []byte("response-1"),
		senderKeyID: "broker.signing",
		inReplyTo:   []byte("request-1"),
		requestHash: repeatedByte(0x55),
	}
	valid, err := encryptProtected("application/test", claimSet)
	if err != nil {
		t.Fatalf("encrypt protected: %v", err)
	}
	if _, err := parseEncryptProtected(valid); err != nil {
		t.Fatalf("parse valid protected: %v", err)
	}

	rewriteCrit := func(t *testing.T, crit any) []byte {
		t.Helper()
		var m map[int64]any
		if err := decMode.Unmarshal(valid, &m); err != nil {
			t.Fatalf("decode protected: %v", err)
		}
		if crit == nil {
			delete(m, labelCrit)
		} else {
			m[labelCrit] = crit
		}
		out, err := encMode.Marshal(m)
		if err != nil {
			t.Fatalf("re-encode protected: %v", err)
		}
		return out
	}

	understood := critLabels(claimSet)
	reversed := slices.Clone(understood)
	slices.Reverse(reversed)
	tests := []struct {
		name string
		crit any
	}{
		{name: "missing-crit", crit: nil},
		{name: "empty-crit", crit: []int64{}},
		{name: "unknown-critical-label", crit: append(slices.Clone(understood), -99)},
		{name: "incomplete-crit", crit: understood[:len(understood)-1]},
		{name: "non-canonical-order", crit: reversed},
		{name: "text-crit-label", crit: []any{"content"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseEncryptProtected(rewriteCrit(t, tt.crit)); err == nil {
				t.Fatalf("parseEncryptProtected accepted %s", tt.name)
			}
		})
	}
}
