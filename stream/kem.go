package stream

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/openbasil/basil-go/basil"
)

// kemEnvelopeLabel is the HKDF info label for the CEK-wrap envelope. It must
// match basil-core's ml_kem_envelope so a broker can open a CEK wrapped here.
var kemEnvelopeLabel = []byte("basil-ml-kem-envelope-v1")

// envTokenAES256GCM is the AEAD token bound into the KEM HKDF info. The CEK wrap
// always uses AES-256-GCM.
var envTokenAES256GCM = []byte("aes-256-gcm")

// KEMEnvelope is the KEM-wrapped content-encryption key carried once in an
// ML-KEM stream header.
type KEMEnvelope struct {
	// EncapsulatedKey is the ML-KEM ciphertext.
	EncapsulatedKey []byte
	// Nonce is the AEAD nonce used to seal the CEK.
	Nonce [NonceLen]byte
	// Ciphertext is the AEAD ciphertext (the wrapped CEK plus its tag).
	Ciphertext []byte
}

// CEKRecovery recovers the content-encryption key from a stream's ML-KEM
// envelope, exactly once per stream. Implementations must fail closed on any
// error.
type CEKRecovery interface {
	// RecoverCEK recovers the wrapped CEK from env, authenticating aad. It
	// returns a 32-byte key on success.
	RecoverCEK(ctx context.Context, env *KEMEnvelope, aad []byte) ([]byte, error)
}

// LocalSeedCEKRecovery recovers the CEK by decapsulating locally with a raw
// ML-KEM seed. It bypasses the broker and is intended for tests and tools that
// legitimately hold the seed; production decryptors should prefer
// [BrokerCEKRecovery].
type LocalSeedCEKRecovery struct {
	seed  []byte
	suite Suite
}

// NewLocalSeedCEKRecovery builds a local recovery seam from a raw ML-KEM seed
// (the FIPS-203 d||z seed; 64 bytes for every parameter set).
func NewLocalSeedCEKRecovery(seed []byte, suite Suite) *LocalSeedCEKRecovery {
	return &LocalSeedCEKRecovery{seed: seed, suite: suite}
}

// RecoverCEK implements [CEKRecovery]. The context is unused (no broker is
// contacted).
func (l *LocalSeedCEKRecovery) RecoverCEK(_ context.Context, env *KEMEnvelope, aad []byte) ([]byte, error) {
	return openCEKLocal(l.seed, uint8(l.suite), env, aad)
}

// BrokerCEKRecovery recovers the CEK through the broker's UnwrapEnvelope RPC.
// The ML-KEM decapsulation key stays custodied in the broker; only the broker
// can recover the shared secret. Encryption needs only the public key and never
// contacts the broker.
type BrokerCEKRecovery struct {
	client *basil.Client
	keyID  string
	suite  Suite
}

// NewBrokerCEKRecovery builds a broker-backed recovery seam for the sealing key
// keyID. suite must match the container's ML-KEM parameter set.
func NewBrokerCEKRecovery(client *basil.Client, keyID string, suite Suite) *BrokerCEKRecovery {
	return &BrokerCEKRecovery{client: client, keyID: keyID, suite: suite}
}

// RecoverCEK implements [CEKRecovery] by filling a [basil.KemEnvelope] from the
// stream's KEM header (with aad = the CEK-wrap AAD) and calling UnwrapEnvelope.
func (b *BrokerCEKRecovery) RecoverCEK(ctx context.Context, env *KEMEnvelope, aad []byte) ([]byte, error) {
	cek, err := b.client.UnwrapEnvelope(ctx, b.keyID, &basil.KemEnvelope{
		KemAlgorithm:      b.kemAlgorithm(),
		EnvelopeAlgorithm: basil.EnvelopeAlgorithmAES256GCM,
		KeyVersion:        0,
		EncapsulatedKey:   env.EncapsulatedKey,
		Nonce:             env.Nonce[:],
		Bytes:             env.Ciphertext,
	}, aad)
	if err != nil {
		return nil, err
	}
	if len(cek) != CEKLen {
		return nil, ErrBadCEKLength
	}
	return cek, nil
}

func (b *BrokerCEKRecovery) kemAlgorithm() basil.KemAlgorithm {
	switch b.suite {
	case SuiteMLKEM512:
		return basil.KemAlgorithmMLKEM512
	case SuiteMLKEM768:
		return basil.KemAlgorithmMLKEM768
	case SuiteMLKEM1024:
		return basil.KemAlgorithmMLKEM1024
	default:
		return basil.KemAlgorithmUnspecified
	}
}

// schemeForSuite resolves the circl ML-KEM scheme for an ML-KEM suite id.
func schemeForSuite(suiteID uint8) (kem.Scheme, bool) {
	switch Suite(suiteID) {
	case SuiteMLKEM512:
		return mlkem512.Scheme(), true
	case SuiteMLKEM768:
		return mlkem768.Scheme(), true
	case SuiteMLKEM1024:
		return mlkem1024.Scheme(), true
	default:
		return nil, false
	}
}

// PublicKeyFromSeed derives the FIPS-203 ML-KEM public encapsulation key bytes
// from a raw 64-byte seed for an ML-KEM suite. It stands in for the broker's
// published public key in tests and tools that hold the seed.
func PublicKeyFromSeed(seed []byte, suite Suite) ([]byte, error) {
	scheme, ok := schemeForSuite(uint8(suite))
	if !ok {
		return nil, ErrSuiteMismatch
	}
	if len(seed) != scheme.SeedSize() {
		return nil, ErrBadKEMCiphertext
	}
	pk, _ := scheme.DeriveKeyPair(seed)
	pub, err := pk.MarshalBinary()
	if err != nil {
		return nil, ErrBadPublicKey
	}
	return pub, nil
}

// wrapCEK wraps a content-encryption key into an ML-KEM envelope against
// publicKey.
func wrapCEK(publicKey []byte, suiteID uint8, cek, aad []byte) (*KEMEnvelope, error) {
	scheme, ok := schemeForSuite(suiteID)
	if !ok {
		return nil, ErrSuiteMismatch
	}
	pk, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, ErrBadPublicKey
	}
	// Re-serialize to the canonical encoding fed into the HKDF info, exactly as
	// the Rust reference uses the parsed key's to_bytes().
	derivedPublic, err := pk.MarshalBinary()
	if err != nil {
		return nil, ErrBadPublicKey
	}
	encapsulatedKey, sharedSecret, err := scheme.Encapsulate(pk)
	if err != nil {
		return nil, ErrBadPublicKey
	}
	defer wipe(sharedSecret)

	aeadKey, err := deriveKEMAEADKey(suiteID, sharedSecret, encapsulatedKey, derivedPublic)
	if err != nil {
		return nil, err
	}
	defer wipe(aeadKey)

	var nonce [NonceLen]byte
	if err := fillRandom(nonce[:]); err != nil {
		return nil, err
	}
	ciphertext, err := aeadSeal(aeadAES256GCM, aeadKey, &nonce, cek, aad)
	if err != nil {
		return nil, err
	}
	return &KEMEnvelope{
		EncapsulatedKey: encapsulatedKey,
		Nonce:           nonce,
		Ciphertext:      ciphertext,
	}, nil
}

// openCEKLocal recovers a CEK from an ML-KEM envelope using a raw seed.
func openCEKLocal(seed []byte, suiteID uint8, env *KEMEnvelope, aad []byte) ([]byte, error) {
	scheme, ok := schemeForSuite(suiteID)
	if !ok {
		return nil, ErrSuiteMismatch
	}
	if len(seed) != scheme.SeedSize() {
		return nil, ErrBadKEMCiphertext
	}
	pk, sk := scheme.DeriveKeyPair(seed)
	derivedPublic, err := pk.MarshalBinary()
	if err != nil {
		return nil, ErrBadPublicKey
	}
	sharedSecret, err := scheme.Decapsulate(sk, env.EncapsulatedKey)
	if err != nil {
		return nil, ErrBadKEMCiphertext
	}
	defer wipe(sharedSecret)

	aeadKey, err := deriveKEMAEADKey(suiteID, sharedSecret, env.EncapsulatedKey, derivedPublic)
	if err != nil {
		return nil, err
	}
	defer wipe(aeadKey)

	return aeadOpen(aeadAES256GCM, aeadKey, &env.Nonce, env.Ciphertext, aad)
}

// deriveKEMAEADKey derives the AES-256-GCM key that wraps the CEK:
// HKDF-SHA256(salt=none, ikm=shared_secret,
//
//	info=label | kem_token | "aes-256-gcm" | encapsulated_key | public_key).
//
// "salt = none" is an all-zero HashLen salt as in RFC 5869, matching the Rust
// hkdf crate's Hkdf::new(None, ...).
func deriveKEMAEADKey(suiteID uint8, sharedSecret, encapsulatedKey, publicKey []byte) ([]byte, error) {
	token, ok := kemToken(suiteID)
	if !ok {
		return nil, ErrSuiteMismatch
	}
	info := make([]byte, 0, len(kemEnvelopeLabel)+len(token)+len(envTokenAES256GCM)+len(encapsulatedKey)+len(publicKey))
	info = append(info, kemEnvelopeLabel...)
	info = append(info, token...)
	info = append(info, envTokenAES256GCM...)
	info = append(info, encapsulatedKey...)
	info = append(info, publicKey...)

	zeroSalt := make([]byte, sha256.Size)
	okm, err := hkdf.Key(sha256.New, sharedSecret, zeroSalt, string(info), CEKLen)
	if err != nil {
		return nil, ErrKDFFailed
	}
	return okm, nil
}

// serializeKEMHeader serializes the KEM header that follows the fixed header for
// an ML-KEM stream: kem_ct_len[4] | encapsulated_key | cek_nonce[12] |
// wrapped_cek_len[4] | wrapped_cek  (big-endian lengths).
func serializeKEMHeader(env *KEMEnvelope) []byte {
	out := make([]byte, 0, 4+len(env.EncapsulatedKey)+NonceLen+4+len(env.Ciphertext))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], uint32(len(env.EncapsulatedKey)))
	out = append(out, u4[:]...)
	out = append(out, env.EncapsulatedKey...)
	out = append(out, env.Nonce[:]...)
	binary.BigEndian.PutUint32(u4[:], uint32(len(env.Ciphertext)))
	out = append(out, u4[:]...)
	out = append(out, env.Ciphertext...)
	return out
}
