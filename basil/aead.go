package basil

import (
	"context"

	"github.com/openbasil/basil-go/internal/pb"
)

// AeadAlgorithm selects the AEAD suite for [Client.Encrypt]. The broker owns
// the nonce in every case, so a caller can neither choose nor misuse it.
//
// It mirrors basil.broker.v1.AeadAlgorithm. The broker rejects
// [AeadAlgorithmUnspecified] on encrypt; choose the suite the encryption key
// was provisioned for.
type AeadAlgorithm int32

const (
	// AeadAlgorithmUnspecified is the zero value; rejected by the broker on
	// encrypt.
	AeadAlgorithmUnspecified AeadAlgorithm = 0
	// AeadAlgorithmChaCha20Poly1305 is ChaCha20-Poly1305 (12-byte nonce,
	// 16-byte tag).
	AeadAlgorithmChaCha20Poly1305 AeadAlgorithm = 1
	// AeadAlgorithmAES256GCM is AES-256-GCM (12-byte nonce, 16-byte tag).
	AeadAlgorithmAES256GCM AeadAlgorithm = 2
)

// String returns the broker's enum name for the AEAD algorithm.
func (a AeadAlgorithm) String() string { return pb.AeadAlgorithm(a).String() }

// KemAlgorithm selects the key-encapsulation mechanism for
// [Client.WrapEnvelope]. It mirrors basil.broker.v1.KemAlgorithm.
type KemAlgorithm int32

const (
	// KemAlgorithmUnspecified is the zero value; rejected by the broker.
	KemAlgorithmUnspecified KemAlgorithm = 0
	// KemAlgorithmMLKEM512 is ML-KEM (FIPS 203) parameter set 512.
	KemAlgorithmMLKEM512 KemAlgorithm = 1
	// KemAlgorithmMLKEM768 is ML-KEM parameter set 768.
	KemAlgorithmMLKEM768 KemAlgorithm = 2
	// KemAlgorithmMLKEM1024 is ML-KEM parameter set 1024.
	KemAlgorithmMLKEM1024 KemAlgorithm = 3
	// KemAlgorithmX25519 is an X25519 sealed box (ECDH + HKDF-SHA256 + AEAD).
	// The envelope's EncapsulatedKey carries the 32-byte ephemeral X25519
	// public key.
	KemAlgorithmX25519 KemAlgorithm = 4
)

// String returns the broker's enum name for the KEM algorithm.
func (a KemAlgorithm) String() string { return pb.KemAlgorithm(a).String() }

// EnvelopeAlgorithm selects the AEAD that seals an envelope's payload under the
// KEM-derived key. It mirrors basil.broker.v1.EnvelopeAlgorithm.
type EnvelopeAlgorithm int32

const (
	// EnvelopeAlgorithmUnspecified is the zero value; rejected by the broker.
	EnvelopeAlgorithmUnspecified EnvelopeAlgorithm = 0
	// EnvelopeAlgorithmAES256GCM is AES-256-GCM.
	EnvelopeAlgorithmAES256GCM EnvelopeAlgorithm = 1
	// EnvelopeAlgorithmChaCha20Poly1305 is ChaCha20-Poly1305.
	EnvelopeAlgorithmChaCha20Poly1305 EnvelopeAlgorithm = 2
)

// String returns the broker's enum name for the envelope algorithm.
func (a EnvelopeAlgorithm) String() string { return pb.EnvelopeAlgorithm(a).String() }

// Ciphertext is a self-describing AEAD ciphertext produced by [Client.Encrypt]
// and consumed by [Client.Decrypt]. The broker owns the nonce, so a caller can
// neither choose nor misuse it; treat the whole value as opaque and round-trip
// it unchanged.
type Ciphertext struct {
	// Algorithm is the AEAD suite used.
	Algorithm AeadAlgorithm
	// KeyVersion is the key version the ciphertext was produced under.
	KeyVersion uint32
	// Nonce is the broker-generated nonce.
	Nonce []byte
	// Bytes is the AEAD ciphertext, including the authentication tag.
	Bytes []byte
}

// KemEnvelope is a KEM + AEAD envelope produced by [Client.WrapEnvelope] and
// consumed by [Client.UnwrapEnvelope]. Treat it as opaque and round-trip it
// unchanged.
type KemEnvelope struct {
	// KemAlgorithm is the KEM used to encapsulate the data-encryption key.
	KemAlgorithm KemAlgorithm
	// EnvelopeAlgorithm is the AEAD that sealed the payload under the
	// encapsulated key.
	EnvelopeAlgorithm EnvelopeAlgorithm
	// KeyVersion is the key version the recipient key was at.
	KeyVersion uint32
	// EncapsulatedKey is the KEM ciphertext, or the ephemeral public key for an
	// X25519 sealed box.
	EncapsulatedKey []byte
	// Nonce is the AEAD nonce.
	Nonce []byte
	// Bytes is the AEAD ciphertext, including the authentication tag.
	Bytes []byte
}

// Encrypt encrypts plaintext under the catalog encryption key named keyID using
// the AEAD suite alg, returning a self-describing [Ciphertext]. The broker
// generates the nonce; the caller never supplies one.
//
// aad is optional additional authenticated data: it is bound to the ciphertext
// but not encrypted, and must be supplied verbatim to [Client.Decrypt]. Pass
// nil for no AAD; a non-nil (even empty) slice is treated as present.
func (c *Client) Encrypt(ctx context.Context, keyID string, alg AeadAlgorithm, plaintext, aad []byte) (*Ciphertext, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.aead.Encrypt(ctx, &pb.EncryptRequest{
		KeyId:     keyID,
		Algorithm: pb.AeadAlgorithm(alg),
		Plaintext: plaintext,
		Aad:       aad,
	})
	if err != nil {
		return nil, statusError(err)
	}
	return ciphertextFromProto(resp.GetEnvelope()), nil
}

// Decrypt recovers the plaintext from ct under the catalog encryption key named
// keyID. aad must match what [Client.Encrypt] was given (nil for none);
// otherwise the broker rejects the ciphertext.
func (c *Client) Decrypt(ctx context.Context, keyID string, ct *Ciphertext, aad []byte) ([]byte, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.aead.Decrypt(ctx, &pb.DecryptRequest{
		KeyId:    keyID,
		Envelope: ciphertextToProto(ct),
		Aad:      aad,
	})
	if err != nil {
		return nil, statusError(err)
	}
	return resp.GetPlaintext(), nil
}

// WrapEnvelope wraps plaintext for the catalog KEM recipient key named keyID:
// it encapsulates a fresh data-encryption key under kem and seals plaintext
// under that key with env. The recipient unwraps it with [Client.UnwrapEnvelope].
//
// aad is optional additional authenticated data, supplied verbatim to unwrap;
// pass nil for none.
func (c *Client) WrapEnvelope(ctx context.Context, keyID string, kem KemAlgorithm, env EnvelopeAlgorithm, plaintext, aad []byte) (*KemEnvelope, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.aead.WrapEnvelope(ctx, &pb.WrapEnvelopeRequest{
		KeyId:             keyID,
		KemAlgorithm:      pb.KemAlgorithm(kem),
		EnvelopeAlgorithm: pb.EnvelopeAlgorithm(env),
		Plaintext:         plaintext,
		Aad:               aad,
	})
	if err != nil {
		return nil, statusError(err)
	}
	return kemEnvelopeFromProto(resp.GetEnvelope()), nil
}

// UnwrapEnvelope recovers the plaintext from a [KemEnvelope] using the catalog
// KEM recipient key named keyID. aad must match what [Client.WrapEnvelope] was
// given (nil for none).
func (c *Client) UnwrapEnvelope(ctx context.Context, keyID string, env *KemEnvelope, aad []byte) ([]byte, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.aead.UnwrapEnvelope(ctx, &pb.UnwrapEnvelopeRequest{
		KeyId:    keyID,
		Envelope: kemEnvelopeToProto(env),
		Aad:      aad,
	})
	if err != nil {
		return nil, statusError(err)
	}
	return resp.GetPlaintext(), nil
}

// UnsealCose recovers plaintext from complete tagged COSE_Encrypt bytes using
// the backend-custodied X25519 sealing key named keyID. coseEncrypt must be the
// exact bytes received on the wire; externalAAD must match the encryption-layer
// external AAD bound by the sender (nil for none).
func (c *Client) UnsealCose(ctx context.Context, keyID string, coseEncrypt, externalAAD []byte) ([]byte, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.aead.UnsealCose(ctx, &pb.UnsealCoseRequest{
		KeyId:       keyID,
		CoseEncrypt: coseEncrypt,
		ExternalAad: externalAAD,
	})
	if err != nil {
		return nil, statusError(err)
	}
	return resp.GetPlaintext(), nil
}

func ciphertextFromProto(e *pb.CiphertextEnvelope) *Ciphertext {
	if e == nil {
		return nil
	}
	return &Ciphertext{
		Algorithm:  AeadAlgorithm(e.GetAlg()),
		KeyVersion: e.GetKeyVersion(),
		Nonce:      e.GetNonce(),
		Bytes:      e.GetCiphertext(),
	}
}

func ciphertextToProto(c *Ciphertext) *pb.CiphertextEnvelope {
	if c == nil {
		return nil
	}
	return &pb.CiphertextEnvelope{
		Alg:        pb.AeadAlgorithm(c.Algorithm),
		KeyVersion: c.KeyVersion,
		Nonce:      c.Nonce,
		Ciphertext: c.Bytes,
	}
}

func kemEnvelopeFromProto(e *pb.KemEnvelope) *KemEnvelope {
	if e == nil {
		return nil
	}
	return &KemEnvelope{
		KemAlgorithm:      KemAlgorithm(e.GetKemAlgorithm()),
		EnvelopeAlgorithm: EnvelopeAlgorithm(e.GetEnvelopeAlgorithm()),
		KeyVersion:        e.GetKeyVersion(),
		EncapsulatedKey:   e.GetEncapsulatedKey(),
		Nonce:             e.GetNonce(),
		Bytes:             e.GetCiphertext(),
	}
}

func kemEnvelopeToProto(e *KemEnvelope) *pb.KemEnvelope {
	if e == nil {
		return nil
	}
	return &pb.KemEnvelope{
		KemAlgorithm:      pb.KemAlgorithm(e.KemAlgorithm),
		EnvelopeAlgorithm: pb.EnvelopeAlgorithm(e.EnvelopeAlgorithm),
		KeyVersion:        e.KeyVersion,
		EncapsulatedKey:   e.EncapsulatedKey,
		Nonce:             e.Nonce,
		Ciphertext:        e.Bytes,
	}
}
