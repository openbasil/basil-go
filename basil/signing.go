package basil

import (
	"context"
	"fmt"

	"github.com/openbasil/basil-go/internal/pb"
)

// PublicKey is a catalog key's public half and metadata, as returned by
// [Client.GetPublicKey]. The broker never returns private key material.
type PublicKey struct {
	// KeyID is the catalog name of the key.
	KeyID string
	// KeyType is the key's type.
	KeyType KeyType
	// Bytes is the public key material; its encoding depends on KeyType.
	Bytes []byte
	// Version is the key version these bytes belong to.
	Version uint32
}

// KeyHandle is a key created or imported in the broker catalog, returned by
// [Client.NewKey], [Client.Import], and [Client.ImportSet]. The broker returns
// only the public half; private material never leaves the vault.
type KeyHandle struct {
	// KeyID is the catalog name the key is stored under.
	KeyID string
	// PublicKey is the key's public half (raw bytes; empty for value/symmetric
	// keys).
	PublicKey []byte
}

// KeyMaterial is caller-supplied (BYOK) private key material for [Client.Import]
// and [Client.ImportSet]. It is write-only: the broker accepts it into the
// vault and never returns it on any RPC. Construct one with
// [Ed25519SeedMaterial] or [PKCS8DERMaterial]; the interface is sealed, so those
// are the only key encodings a caller can supply.
type KeyMaterial interface {
	toProto() *pb.KeyMaterial
}

// Ed25519SeedMaterial wraps a 32-byte raw Ed25519 private seed as [KeyMaterial].
func Ed25519SeedMaterial(seed []byte) KeyMaterial { return ed25519SeedMaterial(seed) }

// PKCS8DERMaterial wraps a generic PKCS#8 DER-encoded private key as
// [KeyMaterial].
func PKCS8DERMaterial(der []byte) KeyMaterial { return pkcs8DERMaterial(der) }

type ed25519SeedMaterial []byte

func (m ed25519SeedMaterial) toProto() *pb.KeyMaterial {
	return &pb.KeyMaterial{Material: &pb.KeyMaterial_Ed25519Seed{Ed25519Seed: m}}
}

type pkcs8DERMaterial []byte

func (m pkcs8DERMaterial) toProto() *pb.KeyMaterial {
	return &pb.KeyMaterial{Material: &pb.KeyMaterial_Pkcs8Der{Pkcs8Der: m}}
}

// ImportEntry is one key to import in a [Client.ImportSet] batch.
type ImportEntry struct {
	// KeyID is the catalog name to store the key under.
	KeyID string
	// KeyType is the key's type.
	KeyType KeyType
	// Material is the caller-provided key material (write-only; never returned).
	Material KeyMaterial
}

// Sign signs message with the catalog key named keyID and returns the raw
// signature bytes.
//
// The broker signs the input as-is: message is the message itself, NOT a
// precomputed digest, and the broker performs no caller-directed prehashing.
// The signature scheme is derived from the key's catalog type; call
// [Client.SignWithAlgorithm] to choose an explicit scheme (for example a NATS
// NKey signing input).
func (c *Client) Sign(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	return c.SignWithAlgorithm(ctx, keyID, message, SigningAlgorithmUnspecified)
}

// SignWithAlgorithm signs with an explicit [SigningAlgorithm]. Pass
// [SigningAlgorithmUnspecified] to let the broker pick the scheme implied by
// the key type. See [Client.Sign] for the meaning of message.
func (c *Client) SignWithAlgorithm(ctx context.Context, keyID string, message []byte, alg SigningAlgorithm) ([]byte, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.signing.Sign(ctx, &pb.SignRequest{
		KeyId:     keyID,
		Message:   message,
		Algorithm: pb.SigningAlgorithm(alg),
	})
	if err != nil {
		return nil, statusError(err)
	}
	return resp.GetSignature(), nil
}

// Verify reports whether signature is a valid signature over message under the
// catalog key named keyID. message is the raw signed bytes (see [Client.Sign]).
// The scheme is derived from the key type; call [Client.VerifyWithAlgorithm]
// for an explicit scheme.
//
// A returned (false, nil) means the broker authoritatively rejected the
// signature; a non-nil error means the verification could not be performed
// (policy denial, unknown key, transport failure).
func (c *Client) Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error) {
	return c.VerifyWithAlgorithm(ctx, keyID, message, signature, SigningAlgorithmUnspecified)
}

// VerifyWithAlgorithm verifies with an explicit [SigningAlgorithm]. See
// [Client.Verify] for the meaning of the result.
func (c *Client) VerifyWithAlgorithm(ctx context.Context, keyID string, message, signature []byte, alg SigningAlgorithm) (bool, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.signing.Verify(ctx, &pb.VerifyRequest{
		KeyId:     keyID,
		Message:   message,
		Signature: signature,
		Algorithm: pb.SigningAlgorithm(alg),
	})
	if err != nil {
		return false, statusError(err)
	}
	return resp.GetValid(), nil
}

// GetPublicKey fetches a key's public half by catalog name. Pass a non-nil
// version to request a specific key version; nil selects the latest visible
// version.
func (c *Client) GetPublicKey(ctx context.Context, keyID string, version *uint32) (*PublicKey, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.signing.GetPublicKey(ctx, &pb.GetPublicKeyRequest{
		KeyId:   keyID,
		Version: version,
	})
	if err != nil {
		return nil, statusError(err)
	}
	return &PublicKey{
		KeyID:   resp.GetKeyId(),
		KeyType: keyTypeFromProto(resp.GetKeyType()),
		Bytes:   resp.GetPublicKey(),
		Version: resp.GetVersion(),
	}, nil
}

// NewKey generates a new key under catalog name keyID and returns its public
// half. Custody and storage of the new key are controlled by the operator's
// catalog entry, never chosen by the caller (secure by default).
//
// Classical types are generated in place by the backend. The post-quantum types
// (ML-DSA signing, ML-KEM sealing) provision a software-custodied key against
// the operator-declared catalog entry: the broker generates and seals the seed
// and returns only the public half. Requires the broker-side new_key permission
// (plus use_software_custody for the software-custodied PQC types).
func (c *Client) NewKey(ctx context.Context, keyID string, keyType KeyType) (*KeyHandle, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.signing.NewKey(ctx, &pb.NewKeyRequest{
		KeyId:   keyID,
		KeyType: keyTypeToProto(keyType),
	})
	if err != nil {
		return nil, statusError(err)
	}
	return &KeyHandle{KeyID: resp.GetKeyId(), PublicKey: resp.GetPublicKey()}, nil
}

// Import stores caller-supplied BYOK private key material under catalog name
// keyID and returns its public half. material must be non-nil; construct it with
// [Ed25519SeedMaterial] or [PKCS8DERMaterial]. As with [Client.NewKey], custody
// and storage stay catalog-controlled, never client-chosen.
func (c *Client) Import(ctx context.Context, keyID string, keyType KeyType, material KeyMaterial) (*KeyHandle, error) {
	if material == nil {
		return nil, fmt.Errorf("basil: Import requires non-nil key material")
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.signing.Import(ctx, &pb.ImportRequest{
		KeyId:    keyID,
		KeyType:  keyTypeToProto(keyType),
		Material: material.toProto(),
	})
	if err != nil {
		return nil, statusError(err)
	}
	return &KeyHandle{KeyID: resp.GetKeyId(), PublicKey: resp.GetPublicKey()}, nil
}

// ImportSet imports several keys in one authorized call (for example an
// nsc-init bundle: operator + SYS account + SYS user). Authorization is
// all-or-nothing (every entry is policy-checked before any import), but the
// imports themselves are sequential, not transactional. It returns one
// [KeyHandle] per imported key, in request order. Every entry's Material must be
// non-nil.
func (c *Client) ImportSet(ctx context.Context, entries []ImportEntry) ([]KeyHandle, error) {
	pbEntries := make([]*pb.ImportEntry, len(entries))
	for i, e := range entries {
		if e.Material == nil {
			return nil, fmt.Errorf("basil: ImportSet entry %d (%q) requires non-nil key material", i, e.KeyID)
		}
		pbEntries[i] = &pb.ImportEntry{
			KeyId:    e.KeyID,
			KeyType:  keyTypeToProto(e.KeyType),
			Material: e.Material.toProto(),
		}
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.signing.ImportSet(ctx, &pb.ImportSetRequest{Entries: pbEntries})
	if err != nil {
		return nil, statusError(err)
	}
	keys := make([]KeyHandle, len(resp.GetKeys()))
	for i, k := range resp.GetKeys() {
		keys[i] = KeyHandle{KeyID: k.GetKeyId(), PublicKey: k.GetPublicKey()}
	}
	return keys, nil
}
