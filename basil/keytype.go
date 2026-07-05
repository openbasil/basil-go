package basil

import "github.com/openbasil/basil-go/internal/pb"

// KeyType is the asymmetric key type reported by the broker for a catalog key.
//
// It mirrors basil.broker.v1.KeyType on the wire. Only the public, classical,
// and post-quantum signing/KEM families the broker recognises are represented;
// an unrecognised wire value maps to [KeyTypeUnspecified].
type KeyType int32

const (
	// KeyTypeUnspecified is the zero value; the broker never returns it for a
	// real key.
	KeyTypeUnspecified KeyType = 0
	// KeyTypeEd25519 is a raw Ed25519 signing key.
	KeyTypeEd25519 KeyType = 1
	// KeyTypeEd25519NKey is an Ed25519 key wrapped in the NATS NKey envelope.
	KeyTypeEd25519NKey KeyType = 2
	// KeyTypeRSA2048 is an RSA-2048 key.
	KeyTypeRSA2048 KeyType = 3
	// KeyTypeECDSAP256 is an ECDSA P-256 key.
	KeyTypeECDSAP256 KeyType = 10
	// KeyTypeECDSAP384 is an ECDSA P-384 key.
	KeyTypeECDSAP384 KeyType = 11
	// KeyTypeECDSAP521 is an ECDSA P-521 key.
	KeyTypeECDSAP521 KeyType = 12
	// KeyTypeMLDSA44 is an ML-DSA (FIPS 204) key, parameter set 44.
	KeyTypeMLDSA44 KeyType = 4
	// KeyTypeMLDSA65 is an ML-DSA key, parameter set 65.
	KeyTypeMLDSA65 KeyType = 5
	// KeyTypeMLDSA87 is an ML-DSA key, parameter set 87.
	KeyTypeMLDSA87 KeyType = 6
	// KeyTypeMLKEM512 is an ML-KEM (FIPS 203) key, parameter set 512.
	KeyTypeMLKEM512 KeyType = 7
	// KeyTypeMLKEM768 is an ML-KEM key, parameter set 768.
	KeyTypeMLKEM768 KeyType = 8
	// KeyTypeMLKEM1024 is an ML-KEM key, parameter set 1024.
	KeyTypeMLKEM1024 KeyType = 9
)

// String returns the broker's enum name for the key type.
func (k KeyType) String() string {
	return pb.KeyType(k).String()
}

func keyTypeFromProto(v pb.KeyType) KeyType {
	switch v {
	case pb.KeyType_KEY_TYPE_ED25519,
		pb.KeyType_KEY_TYPE_ED25519_NKEY,
		pb.KeyType_KEY_TYPE_RSA_2048,
		pb.KeyType_KEY_TYPE_ECDSA_P256,
		pb.KeyType_KEY_TYPE_ECDSA_P384,
		pb.KeyType_KEY_TYPE_ECDSA_P521,
		pb.KeyType_KEY_TYPE_ML_DSA_44,
		pb.KeyType_KEY_TYPE_ML_DSA_65,
		pb.KeyType_KEY_TYPE_ML_DSA_87,
		pb.KeyType_KEY_TYPE_ML_KEM_512,
		pb.KeyType_KEY_TYPE_ML_KEM_768,
		pb.KeyType_KEY_TYPE_ML_KEM_1024:
		return KeyType(v)
	default:
		return KeyTypeUnspecified
	}
}

// keyTypeToProto maps a public KeyType to its wire enum for NewKey/Import
// request building. The Go and proto enums share numeric values, so this is a
// direct conversion; it exists as a single named seam for that mapping.
func keyTypeToProto(k KeyType) pb.KeyType { return pb.KeyType(k) }

// SigningAlgorithm selects the signature scheme for [Client.SignWithAlgorithm]
// and [Client.VerifyWithAlgorithm].
//
// It mirrors basil.broker.v1.SigningAlgorithm. [SigningAlgorithmUnspecified]
// lets the broker derive the scheme from the catalog key's type, which is the
// right choice for almost every caller; pass an explicit value only when a key
// supports more than one scheme (for example Ed25519 raw versus the NATS NKey
// signing input).
type SigningAlgorithm int32

const (
	// SigningAlgorithmUnspecified lets the broker pick the scheme implied by
	// the key type.
	SigningAlgorithmUnspecified SigningAlgorithm = 0
	// SigningAlgorithmEd25519 is raw Ed25519 (EdDSA over the message).
	SigningAlgorithmEd25519 SigningAlgorithm = 1
	// SigningAlgorithmEd25519NKey is Ed25519 over a NATS NKey signing input.
	SigningAlgorithmEd25519NKey SigningAlgorithm = 2
	// SigningAlgorithmRS256 is RSASSA-PKCS1-v1_5 over SHA-256.
	SigningAlgorithmRS256 SigningAlgorithm = 3
	// SigningAlgorithmES256 is ECDSA P-256 over SHA-256.
	SigningAlgorithmES256 SigningAlgorithm = 7
	// SigningAlgorithmMLDSA44 is ML-DSA parameter set 44.
	SigningAlgorithmMLDSA44 SigningAlgorithm = 4
	// SigningAlgorithmMLDSA65 is ML-DSA parameter set 65.
	SigningAlgorithmMLDSA65 SigningAlgorithm = 5
	// SigningAlgorithmMLDSA87 is ML-DSA parameter set 87.
	SigningAlgorithmMLDSA87 SigningAlgorithm = 6
)

// String returns the broker's enum name for the signing algorithm.
func (a SigningAlgorithm) String() string {
	return pb.SigningAlgorithm(a).String()
}
