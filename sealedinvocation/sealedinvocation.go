// Package sealedinvocation builds and opens Basil COSE sealed invocation
// messages without contacting a broker.
package sealedinvocation

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
)

const (
	labelInReplyTo       int64 = -70001
	labelRequestHash     int64 = -70002
	labelSenderKeyID     int64 = -70003
	labelResponseKeyID   int64 = -70004
	labelResponseSubject int64 = -70005

	labelAlg       int64 = 1
	labelCrit      int64 = 2
	labelContent   int64 = 3
	labelKid       int64 = 4
	labelIV        int64 = 5
	labelCWTClaims int64 = 15
	labelEphemeral int64 = -1

	cwtIssuer    int64 = 1
	cwtAudience  int64 = 3
	cwtExpiresAt int64 = 4
	cwtIssuedAt  int64 = 6
	cwtID        int64 = 7

	tagSign1   uint64 = 18
	tagEncrypt uint64 = 96

	algEdDSA       int64 = -8
	algA256GCM     int64 = 3
	algECDHESHKDF  int64 = -25
	nonceLen             = 12
	x25519Len            = 32
	ed25519SeedLen       = 32
)

var encMode cbor.EncMode
var decMode cbor.DecMode

func init() {
	var err error
	encMode, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	decMode, err = cbor.DecOptions{}.DecMode()
	if err != nil {
		panic(err)
	}
}

// RequestParams names the inputs for a sealed invocation request.
type RequestParams struct {
	// ContentType is the encrypted plaintext media type.
	ContentType string
	// Plaintext is the CBOR invocation body or test payload to seal.
	Plaintext []byte
	// Issuer is the optional CWT issuer.
	Issuer string
	// Audience is the optional CWT audience.
	Audience string
	// IssuedAt is the CWT iat value. Zero uses time.Now.
	IssuedAt time.Time
	// TTL is the request validity period. Zero uses two minutes.
	TTL time.Duration
	// MessageID is the sender-unique CWT cti value.
	MessageID []byte
	// SenderKeyID is the Ed25519 signing key id.
	SenderKeyID string
	// SenderSeed is the 32-byte Ed25519 signing seed.
	SenderSeed []byte
	// RecipientKeyID is the broker request X25519 recipient key id.
	RecipientKeyID string
	// RecipientPublic is the broker request X25519 public key.
	RecipientPublic []byte
	// ResponseKeyID is the client response X25519 recipient key id.
	ResponseKeyID string
	// ResponseSubject is the optional NATS subject for a response.
	ResponseSubject string
}

// Request is a sealed invocation request plus its correlation fields.
type Request struct {
	// Message is the complete tagged COSE_Sign1 request.
	Message []byte
	// MessageID is the CWT cti carried by Message.
	MessageID []byte
}

// ResponseParams names the inputs for verifying and opening a response.
type ResponseParams struct {
	// Message is the complete tagged COSE_Sign1 response.
	Message []byte
	// Request is the complete tagged request bytes the response answers.
	Request []byte
	// RequestMessageID is the request CWT cti expected in the in-reply-to claim.
	RequestMessageID []byte
	// ExpectedContentType is optional; when set, the response content type must match.
	ExpectedContentType string
	// Now is the validation time. Zero uses time.Now.
	Now time.Time
	// MaxClockSkew is the tolerated clock skew. Zero uses one minute.
	MaxClockSkew time.Duration
	// MaxTTL is the maximum exp-iat span. Zero uses five minutes.
	MaxTTL time.Duration
	// BrokerKeyID is the expected broker Ed25519 signing key id.
	BrokerKeyID string
	// BrokerPublic is the broker Ed25519 public key.
	BrokerPublic []byte
	// RecipientKeyID is the client response X25519 recipient key id.
	RecipientKeyID string
	// RecipientPrivate is the client response X25519 private key.
	RecipientPrivate []byte
}

// Response is a verified and opened sealed invocation response.
type Response struct {
	// Plaintext is the decrypted response body.
	Plaintext []byte
	// ContentType is the encrypted response content type.
	ContentType string
}

type claims struct {
	issuer          string
	audience        string
	expiresAt       int64
	issuedAt        int64
	messageID       []byte
	senderKeyID     string
	responseKeyID   string
	responseSubject string
	inReplyTo       []byte
	requestHash     []byte
}

type encryptedMessage struct {
	protected          []byte
	contentType        string
	claims             claims
	iv                 []byte
	ciphertext         []byte
	recipientProtected []byte
	recipientKeyID     string
	ephemeralX         []byte
}

type coseEncrypt struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int64]any
	Ciphertext  []byte
	Recipients  []coseRecipient
}

type coseRecipient struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int64]any
	Ciphertext  any
}

type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int64]any
	Payload     []byte
	Signature   []byte
}

// BuildRequest builds a Basil sealed invocation request.
func BuildRequest(params RequestParams) (*Request, error) {
	if len(params.MessageID) == 0 || len(params.MessageID) > 64 {
		return nil, fmt.Errorf("sealed invocation: message id must be 1..64 bytes")
	}
	issuedAt := params.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	ttl := params.TTL
	if ttl == 0 {
		ttl = 2 * time.Minute
	}
	claimSet := claims{
		issuer:          params.Issuer,
		audience:        params.Audience,
		issuedAt:        issuedAt.Unix(),
		expiresAt:       issuedAt.Add(ttl).Unix(),
		messageID:       append([]byte(nil), params.MessageID...),
		senderKeyID:     params.SenderKeyID,
		responseKeyID:   params.ResponseKeyID,
		responseSubject: params.ResponseSubject,
	}
	msg, err := buildSealed(params.ContentType, params.Plaintext, claimSet, params.SenderKeyID, params.SenderSeed, params.RecipientKeyID, params.RecipientPublic)
	if err != nil {
		return nil, err
	}
	return &Request{Message: msg, MessageID: append([]byte(nil), params.MessageID...)}, nil
}

// OpenResponse verifies a broker-signed response, checks response correlation,
// and opens it with the caller's X25519 response key.
func OpenResponse(params ResponseParams) (*Response, error) {
	now := params.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := params.MaxClockSkew
	if skew == 0 {
		skew = time.Minute
	}
	maxTTL := params.MaxTTL
	if maxTTL == 0 {
		maxTTL = 5 * time.Minute
	}
	sign1, kid, err := verifySign1(params.Message, params.BrokerKeyID, params.BrokerPublic)
	if err != nil {
		return nil, err
	}
	enc, err := decodeEncrypt(sign1.Payload)
	if err != nil {
		return nil, err
	}
	if enc.claims.senderKeyID != kid {
		return nil, fmt.Errorf("sealed invocation: response sender key %q does not match outer kid %q", enc.claims.senderKeyID, kid)
	}
	if !bytes.Equal(enc.claims.inReplyTo, params.RequestMessageID) {
		return nil, fmt.Errorf("sealed invocation: response in-reply-to mismatch")
	}
	requestHash := sha3.Sum256(params.Request)
	if !bytes.Equal(enc.claims.requestHash, requestHash[:]) {
		return nil, fmt.Errorf("sealed invocation: response request hash mismatch")
	}
	if err := validateResponseClaims(enc.claims, now, skew, maxTTL); err != nil {
		return nil, err
	}
	if params.ExpectedContentType != "" && enc.contentType != params.ExpectedContentType {
		return nil, fmt.Errorf("sealed invocation: response content type %q, want %q", enc.contentType, params.ExpectedContentType)
	}
	plaintext, err := openEncrypt(enc, params.RecipientKeyID, params.RecipientPrivate)
	if err != nil {
		return nil, err
	}
	return &Response{Plaintext: plaintext, ContentType: enc.contentType}, nil
}

// X25519Public derives an X25519 public key from a 32-byte private key.
func X25519Public(private []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: X25519 private key: %w", err)
	}
	return priv.PublicKey().Bytes(), nil
}

func buildSealed(contentType string, plaintext []byte, claimSet claims, signingKeyID string, signingSeed []byte, recipientKeyID string, recipientPublic []byte) ([]byte, error) {
	if len(signingSeed) != ed25519SeedLen {
		return nil, fmt.Errorf("sealed invocation: Ed25519 seed must be %d bytes", ed25519SeedLen)
	}
	if len(recipientPublic) != x25519Len {
		return nil, fmt.Errorf("sealed invocation: X25519 public key must be %d bytes", x25519Len)
	}
	encryptBytes, err := buildEncrypt(contentType, plaintext, claimSet, recipientKeyID, recipientPublic)
	if err != nil {
		return nil, err
	}
	protected, err := encMode.Marshal(map[int64]any{
		labelAlg: algEdDSA,
		labelKid: []byte(signingKeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: encode Sign1 protected: %w", err)
	}
	sigStructure, err := sigStructure(protected, nil, encryptBytes)
	if err != nil {
		return nil, err
	}
	private := ed25519.NewKeyFromSeed(signingSeed)
	signature := ed25519.Sign(private, sigStructure)
	return encMode.Marshal(cbor.Tag{
		Number: tagSign1,
		Content: []any{
			protected,
			map[int64]any{},
			encryptBytes,
			signature,
		},
	})
}

func buildEncrypt(contentType string, plaintext []byte, claimSet claims, recipientKeyID string, recipientPublic []byte) ([]byte, error) {
	ephemeralRaw := make([]byte, x25519Len)
	if _, err := rand.Read(ephemeralRaw); err != nil {
		return nil, fmt.Errorf("sealed invocation: random ephemeral key: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("sealed invocation: random nonce: %w", err)
	}
	ephemeral, err := ecdh.X25519().NewPrivateKey(ephemeralRaw)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: ephemeral key: %w", err)
	}
	recipient, err := ecdh.X25519().NewPublicKey(recipientPublic)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: recipient public key: %w", err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: ECDH: %w", err)
	}
	recipientProtected, err := encMode.Marshal(map[int64]any{labelAlg: algECDHESHKDF})
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: encode recipient protected: %w", err)
	}
	info, err := kdfContext(algA256GCM, recipientProtected)
	if err != nil {
		return nil, err
	}
	reader := hkdf.New(sha256.New, shared, nil, info)
	cek := make([]byte, 32)
	if _, err := io.ReadFull(reader, cek); err != nil {
		return nil, fmt.Errorf("sealed invocation: HKDF: %w", err)
	}
	protected, err := encryptProtected(contentType, claimSet)
	if err != nil {
		return nil, err
	}
	aad, err := encStructure(protected, nil)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: AES key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: AES-GCM: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return encMode.Marshal(cbor.Tag{
		Number: tagEncrypt,
		Content: []any{
			protected,
			map[int64]any{labelIV: nonce},
			ciphertext,
			[]any{
				[]any{
					recipientProtected,
					map[int64]any{
						labelKid: []byte(recipientKeyID),
						labelEphemeral: map[int64]any{
							1:  int64(1),
							-1: int64(4),
							-2: ephemeral.PublicKey().Bytes(),
						},
					},
					nil,
				},
			},
		},
	})
}

func encryptProtected(contentType string, claimSet claims) ([]byte, error) {
	m := map[int64]any{
		labelAlg:     algA256GCM,
		labelCrit:    critLabels(claimSet),
		labelContent: contentType,
		labelCWTClaims: map[int64]any{
			cwtIssuedAt: claimSet.issuedAt,
			cwtID:       claimSet.messageID,
		},
	}
	if claimSet.issuer != "" {
		m[labelCWTClaims].(map[int64]any)[cwtIssuer] = claimSet.issuer
	}
	if claimSet.audience != "" {
		m[labelCWTClaims].(map[int64]any)[cwtAudience] = claimSet.audience
	}
	if claimSet.expiresAt != 0 {
		m[labelCWTClaims].(map[int64]any)[cwtExpiresAt] = claimSet.expiresAt
	}
	if claimSet.inReplyTo != nil {
		m[labelInReplyTo] = claimSet.inReplyTo
	}
	if claimSet.requestHash != nil {
		m[labelRequestHash] = claimSet.requestHash
	}
	if claimSet.senderKeyID != "" {
		m[labelSenderKeyID] = []byte(claimSet.senderKeyID)
	}
	if claimSet.responseKeyID != "" {
		m[labelResponseKeyID] = claimSet.responseKeyID
	}
	if claimSet.responseSubject != "" {
		m[labelResponseSubject] = claimSet.responseSubject
	}
	return encMode.Marshal(m)
}

func critLabels(claimSet claims) []int64 {
	labels := []int64{labelContent, labelCWTClaims}
	if claimSet.inReplyTo != nil {
		labels = append(labels, labelInReplyTo)
	}
	if claimSet.requestHash != nil {
		labels = append(labels, labelRequestHash)
	}
	if claimSet.senderKeyID != "" {
		labels = append(labels, labelSenderKeyID)
	}
	if claimSet.responseKeyID != "" {
		labels = append(labels, labelResponseKeyID)
	}
	if claimSet.responseSubject != "" {
		labels = append(labels, labelResponseSubject)
	}
	return labels
}

func verifySign1(message []byte, expectedKid string, public []byte) (*coseSign1, string, error) {
	var tag cbor.Tag
	if err := decMode.Unmarshal(message, &tag); err != nil {
		return nil, "", fmt.Errorf("sealed invocation: decode Sign1 tag: %w", err)
	}
	if tag.Number != tagSign1 {
		return nil, "", fmt.Errorf("sealed invocation: Sign1 tag %d, want %d", tag.Number, tagSign1)
	}
	body, err := encMode.Marshal(tag.Content)
	if err != nil {
		return nil, "", fmt.Errorf("sealed invocation: re-encode Sign1 body: %w", err)
	}
	var sign1 coseSign1
	if err := decMode.Unmarshal(body, &sign1); err != nil {
		return nil, "", fmt.Errorf("sealed invocation: decode Sign1 body: %w", err)
	}
	var protected map[int64]any
	if err := decMode.Unmarshal(sign1.Protected, &protected); err != nil {
		return nil, "", fmt.Errorf("sealed invocation: decode Sign1 protected: %w", err)
	}
	alg, ok := int64Value(protected[labelAlg])
	if !ok || alg != algEdDSA {
		return nil, "", fmt.Errorf("sealed invocation: Sign1 alg mismatch")
	}
	kidBytes, ok := protected[labelKid].([]byte)
	if !ok {
		return nil, "", fmt.Errorf("sealed invocation: missing Sign1 kid")
	}
	kid := string(kidBytes)
	if kid != expectedKid {
		return nil, "", fmt.Errorf("sealed invocation: Sign1 kid %q, want %q", kid, expectedKid)
	}
	sigStructure, err := sigStructure(sign1.Protected, nil, sign1.Payload)
	if err != nil {
		return nil, "", err
	}
	if !ed25519.Verify(ed25519.PublicKey(public), sigStructure, sign1.Signature) {
		return nil, "", fmt.Errorf("sealed invocation: invalid Sign1 signature")
	}
	return &sign1, kid, nil
}

func decodeEncrypt(message []byte) (*encryptedMessage, error) {
	var tag cbor.Tag
	if err := decMode.Unmarshal(message, &tag); err != nil {
		return nil, fmt.Errorf("sealed invocation: decode Encrypt tag: %w", err)
	}
	if tag.Number != tagEncrypt {
		return nil, fmt.Errorf("sealed invocation: Encrypt tag %d, want %d", tag.Number, tagEncrypt)
	}
	body, err := encMode.Marshal(tag.Content)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: re-encode Encrypt body: %w", err)
	}
	var enc coseEncrypt
	if err := decMode.Unmarshal(body, &enc); err != nil {
		return nil, fmt.Errorf("sealed invocation: decode Encrypt body: %w", err)
	}
	if len(enc.Recipients) != 1 {
		return nil, fmt.Errorf("sealed invocation: recipient count %d, want 1", len(enc.Recipients))
	}
	protected, err := parseEncryptProtected(enc.Protected)
	if err != nil {
		return nil, err
	}
	iv, ok := enc.Unprotected[labelIV].([]byte)
	if !ok || len(iv) != nonceLen {
		return nil, fmt.Errorf("sealed invocation: invalid Encrypt nonce")
	}
	recipient := enc.Recipients[0]
	recipientProtected, err := parseRecipientProtected(recipient.Protected)
	if err != nil {
		return nil, err
	}
	kidBytes, ok := recipient.Unprotected[labelKid].([]byte)
	if !ok {
		return nil, fmt.Errorf("sealed invocation: missing recipient kid")
	}
	ephemeralMap, ok := asMap(recipient.Unprotected[labelEphemeral])
	if !ok {
		return nil, fmt.Errorf("sealed invocation: missing ephemeral key")
	}
	ephemeral, ok := ephemeralMap[int64(-2)].([]byte)
	if !ok || len(ephemeral) != x25519Len {
		return nil, fmt.Errorf("sealed invocation: invalid ephemeral public key")
	}
	return &encryptedMessage{
		protected:          enc.Protected,
		contentType:        protected.contentType,
		claims:             protected.claims,
		iv:                 iv,
		ciphertext:         enc.Ciphertext,
		recipientProtected: recipientProtected,
		recipientKeyID:     string(kidBytes),
		ephemeralX:         ephemeral,
	}, nil
}

type parsedProtected struct {
	contentType string
	claims      claims
}

func parseEncryptProtected(raw []byte) (*parsedProtected, error) {
	var m map[int64]any
	if err := decMode.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("sealed invocation: decode Encrypt protected: %w", err)
	}
	alg, ok := int64Value(m[labelAlg])
	if !ok || alg != algA256GCM {
		return nil, fmt.Errorf("sealed invocation: Encrypt alg mismatch")
	}
	contentType, ok := m[labelContent].(string)
	if !ok || contentType == "" {
		return nil, fmt.Errorf("sealed invocation: missing content type")
	}
	cwt, ok := asMap(m[labelCWTClaims])
	if !ok {
		return nil, fmt.Errorf("sealed invocation: missing CWT claims")
	}
	parsed := claims{}
	if issuer, ok := cwt[cwtIssuer].(string); ok {
		parsed.issuer = issuer
	}
	if audience, ok := cwt[cwtAudience].(string); ok {
		parsed.audience = audience
	}
	if exp, ok := int64Value(cwt[cwtExpiresAt]); ok {
		parsed.expiresAt = exp
	}
	iat, ok := int64Value(cwt[cwtIssuedAt])
	if !ok {
		return nil, fmt.Errorf("sealed invocation: missing iat")
	}
	parsed.issuedAt = iat
	id, ok := cwt[cwtID].([]byte)
	if !ok {
		return nil, fmt.Errorf("sealed invocation: missing cti")
	}
	parsed.messageID = id
	if value, ok := m[labelInReplyTo].([]byte); ok {
		parsed.inReplyTo = value
	}
	if value, ok := m[labelRequestHash].([]byte); ok {
		parsed.requestHash = value
	}
	if value, ok := m[labelSenderKeyID].([]byte); ok {
		parsed.senderKeyID = string(value)
	}
	if value, ok := m[labelResponseKeyID].(string); ok {
		parsed.responseKeyID = value
	}
	if value, ok := m[labelResponseSubject].(string); ok {
		parsed.responseSubject = value
	}
	return &parsedProtected{contentType: contentType, claims: parsed}, nil
}

func parseRecipientProtected(raw []byte) ([]byte, error) {
	var m map[int64]any
	if err := decMode.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("sealed invocation: decode recipient protected: %w", err)
	}
	alg, ok := int64Value(m[labelAlg])
	if !ok || alg != algECDHESHKDF {
		return nil, fmt.Errorf("sealed invocation: recipient alg mismatch")
	}
	return raw, nil
}

func openEncrypt(enc *encryptedMessage, recipientKeyID string, recipientPrivate []byte) ([]byte, error) {
	if enc.recipientKeyID != recipientKeyID {
		return nil, fmt.Errorf("sealed invocation: recipient kid %q, want %q", enc.recipientKeyID, recipientKeyID)
	}
	private, err := ecdh.X25519().NewPrivateKey(recipientPrivate)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: X25519 private key: %w", err)
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(enc.ephemeralX)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: X25519 ephemeral key: %w", err)
	}
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: ECDH: %w", err)
	}
	info, err := kdfContext(algA256GCM, enc.recipientProtected)
	if err != nil {
		return nil, err
	}
	reader := hkdf.New(sha256.New, shared, nil, info)
	cek := make([]byte, 32)
	if _, err := io.ReadFull(reader, cek); err != nil {
		return nil, fmt.Errorf("sealed invocation: HKDF: %w", err)
	}
	aad, err := encStructure(enc.protected, nil)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: AES key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: AES-GCM: %w", err)
	}
	plaintext, err := aead.Open(nil, enc.iv, enc.ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: open failed")
	}
	return plaintext, nil
}

func validateResponseClaims(claimSet claims, now time.Time, skew, maxTTL time.Duration) error {
	nowUnix := now.Unix()
	skewSeconds := int64(skew.Seconds())
	if claimSet.issuedAt > nowUnix+skewSeconds {
		return fmt.Errorf("sealed invocation: response issued in the future")
	}
	if claimSet.expiresAt <= claimSet.issuedAt {
		return fmt.Errorf("sealed invocation: response has non-positive ttl")
	}
	if claimSet.expiresAt-claimSet.issuedAt > int64(maxTTL.Seconds()) {
		return fmt.Errorf("sealed invocation: response ttl too long")
	}
	if nowUnix > claimSet.expiresAt+skewSeconds {
		return fmt.Errorf("sealed invocation: response expired")
	}
	if claimSet.inReplyTo == nil || claimSet.requestHash == nil {
		return fmt.Errorf("sealed invocation: response claims missing correlation")
	}
	if claimSet.responseKeyID != "" || claimSet.responseSubject != "" {
		return fmt.Errorf("sealed invocation: response carries request-only claims")
	}
	return nil
}

func sigStructure(protected, externalAAD, payload []byte) ([]byte, error) {
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	out, err := encMode.Marshal([]any{"Signature1", protected, externalAAD, payload})
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: encode Sig_structure: %w", err)
	}
	return out, nil
}

func encStructure(protected, externalAAD []byte) ([]byte, error) {
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	out, err := encMode.Marshal([]any{"Encrypt", protected, externalAAD})
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: encode Enc_structure: %w", err)
	}
	return out, nil
}

func kdfContext(alg int64, recipientProtected []byte) ([]byte, error) {
	out, err := encMode.Marshal([]any{
		alg,
		[]any{nil, nil, nil},
		[]any{nil, nil, nil},
		[]any{uint64(256), recipientProtected},
	})
	if err != nil {
		return nil, fmt.Errorf("sealed invocation: encode KDF context: %w", err)
	}
	return out, nil
}

func int64Value(value any) (int64, bool) {
	switch v := value.(type) {
	case int64:
		return v, true
	case uint64:
		if v <= uint64(^uint64(0)>>1) {
			return int64(v), true
		}
	}
	return 0, false
}

func asMap(value any) (map[int64]any, bool) {
	if m, ok := value.(map[int64]any); ok {
		return m, true
	}
	raw, err := encMode.Marshal(value)
	if err != nil {
		return nil, false
	}
	var out map[int64]any
	if err := decMode.Unmarshal(raw, &out); err != nil {
		return nil, false
	}
	return out, true
}
