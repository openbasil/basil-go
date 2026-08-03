package basil

import (
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/grpc"
)

const (
	describeNixCacheKeyRequestMax      = 295
	describeNixCacheKeyResponseMax     = 203
	enrollNixCacheKeyRequestMax        = 295
	enrollNixCacheKeyResponseMax       = 205
	signNixCacheFingerprintRequestMax  = 524939
	signNixCacheFingerprintResponseMax = 269
	nixCacheFingerprintMax             = 524626
)

// NixCacheKey is the enrolled public identity of a Nix binary-cache signing
// key. It never contains private material.
type NixCacheKey struct {
	// KeyName is the Nix verifier identity.
	KeyName string
	// PublicKey is the raw 32-byte Ed25519 public key.
	PublicKey [32]byte
	// BackendVersion is the immutable backend version. V1 requires 1.
	BackendVersion uint32
}

// NixCacheEnrollmentDisposition describes whether an enrollment created or
// found identical backend material.
type NixCacheEnrollmentDisposition int32

const (
	// NixCacheEnrollmentCreated means this request created the backend key.
	NixCacheEnrollmentCreated NixCacheEnrollmentDisposition = 1
	// NixCacheEnrollmentExisting means compare-only validation found the same key.
	NixCacheEnrollmentExisting NixCacheEnrollmentDisposition = 2
)

// NixCacheEnrollment is a public-only Nix key enrollment result.
type NixCacheEnrollment struct {
	Key         NixCacheKey
	Disposition NixCacheEnrollmentDisposition
}

// NixCacheSignature is a purpose-specific signature over one canonical
// PATH_INFO_V1 fingerprint.
type NixCacheSignature struct {
	Key       NixCacheKey
	Signature [64]byte
}

// DescribeNixCacheKey returns the enrolled verifier identity for keyID.
func (c *Client) DescribeNixCacheKey(ctx context.Context, keyID string, batchID, requestID [16]byte) (*NixCacheKey, error) {
	if err := validateNixCacheRequest(keyID, batchID, requestID); err != nil {
		return nil, err
	}
	request := &pb.DescribeNixCacheKeyRequest{KeyId: keyID, BatchId: batchID[:], RequestId: requestID[:]}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	response, err := c.nixCache.DescribeNixCacheKey(ctx, request, nixCacheCallOptions(describeNixCacheKeyRequestMax, describeNixCacheKeyResponseMax)...)
	if err != nil {
		return nil, statusError(err)
	}
	if err := validateNixCacheResponseEcho(response, batchID, requestID); err != nil {
		return nil, err
	}
	key, err := nixCacheKey(response.GetKeyName(), response.GetPublicKey(), response.GetBackendVersion())
	return &key, err
}

// EnrollNixCacheKey ensures and enrolls one pending Nix binary-cache key.
func (c *Client) EnrollNixCacheKey(ctx context.Context, keyID string, batchID, requestID [16]byte) (*NixCacheEnrollment, error) {
	if err := validateNixCacheRequest(keyID, batchID, requestID); err != nil {
		return nil, err
	}
	request := &pb.EnrollNixCacheKeyRequest{KeyId: keyID, BatchId: batchID[:], RequestId: requestID[:]}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	response, err := c.nixCache.EnrollNixCacheKey(ctx, request, nixCacheCallOptions(enrollNixCacheKeyRequestMax, enrollNixCacheKeyResponseMax)...)
	if err != nil {
		return nil, statusError(err)
	}
	if err := validateNixCacheResponseEcho(response, batchID, requestID); err != nil {
		return nil, err
	}
	disposition := NixCacheEnrollmentDisposition(response.GetDisposition())
	if disposition != NixCacheEnrollmentCreated && disposition != NixCacheEnrollmentExisting {
		return nil, fmt.Errorf("basil: Nix cache response has invalid enrollment disposition %d", disposition)
	}
	key, err := nixCacheKey(response.GetKeyName(), response.GetPublicKey(), response.GetBackendVersion())
	if err != nil {
		return nil, err
	}
	return &NixCacheEnrollment{Key: key, Disposition: disposition}, nil
}

// SignNixCacheFingerprint signs one canonical PATH_INFO_V1 fingerprint.
func (c *Client) SignNixCacheFingerprint(ctx context.Context, keyID string, fingerprint []byte, batchID, requestID [16]byte) (*NixCacheSignature, error) {
	if err := validateNixCacheRequest(keyID, batchID, requestID); err != nil {
		return nil, err
	}
	if len(fingerprint) == 0 || len(fingerprint) > nixCacheFingerprintMax {
		return nil, fmt.Errorf("basil: Nix cache fingerprint length %d is outside 1..=%d", len(fingerprint), nixCacheFingerprintMax)
	}
	request := &pb.SignNixCacheFingerprintRequest{
		KeyId: keyID, Profile: "PATH_INFO_V1", Fingerprint: fingerprint,
		BatchId: batchID[:], RequestId: requestID[:],
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	response, err := c.nixCache.SignNixCacheFingerprint(ctx, request, nixCacheCallOptions(signNixCacheFingerprintRequestMax, signNixCacheFingerprintResponseMax)...)
	if err != nil {
		return nil, statusError(err)
	}
	if err := validateNixCacheResponseEcho(response, batchID, requestID); err != nil {
		return nil, err
	}
	if len(response.GetSignature()) != 64 {
		return nil, fmt.Errorf("basil: Nix cache response signature is %d bytes; expected 64", len(response.GetSignature()))
	}
	key, err := nixCacheKey(response.GetKeyName(), response.GetPublicKey(), response.GetBackendVersion())
	if err != nil {
		return nil, err
	}
	result := &NixCacheSignature{Key: key}
	copy(result.Signature[:], response.GetSignature())
	return result, nil
}

func validateNixCacheRequest(keyID string, batchID, requestID [16]byte) error {
	if !utf8.ValidString(keyID) || len(keyID) == 0 || len(keyID) > 256 {
		return fmt.Errorf("basil: Nix cache key ID length must be 1..=256 valid UTF-8 bytes")
	}
	for _, value := range []byte(keyID) {
		if value < 0x20 || value == 0x7f {
			return fmt.Errorf("basil: Nix cache key ID contains a control byte")
		}
	}
	if allZero16(batchID) || allZero16(requestID) {
		return fmt.Errorf("basil: Nix cache batch and request IDs must not be all zero")
	}
	return nil
}

func nixCacheCallOptions(maximumSend, maximumReceive int) []grpc.CallOption {
	return []grpc.CallOption{
		grpc.ForceCodec(nixCacheProtoCodec{}),
		grpc.MaxCallSendMsgSize(maximumSend),
		grpc.MaxCallRecvMsgSize(maximumReceive),
	}
}

func validateNixCacheResponseEcho(message any, batchID, requestID [16]byte) error {
	var actualBatch, actualRequest []byte
	switch response := message.(type) {
	case *pb.DescribeNixCacheKeyResponse:
		actualBatch, actualRequest = response.GetBatchId(), response.GetRequestId()
	case *pb.EnrollNixCacheKeyResponse:
		actualBatch, actualRequest = response.GetBatchId(), response.GetRequestId()
	case *pb.SignNixCacheFingerprintResponse:
		actualBatch, actualRequest = response.GetBatchId(), response.GetRequestId()
	default:
		return fmt.Errorf("basil: unsupported Nix cache response type %T", message)
	}
	if string(actualBatch) != string(batchID[:]) || string(actualRequest) != string(requestID[:]) {
		return fmt.Errorf("basil: Nix cache response changed a correlation ID")
	}
	return nil
}

func nixCacheKey(keyName string, publicKey []byte, backendVersion uint32) (NixCacheKey, error) {
	if !validNixCacheKeyName(keyName) {
		return NixCacheKey{}, fmt.Errorf("basil: invalid Nix cache key name")
	}
	if len(publicKey) != 32 {
		return NixCacheKey{}, fmt.Errorf("basil: Nix cache public key is %d bytes; expected 32", len(publicKey))
	}
	if backendVersion != 1 {
		return NixCacheKey{}, fmt.Errorf("basil: Nix cache backend version is %d; expected 1", backendVersion)
	}
	result := NixCacheKey{KeyName: keyName, BackendVersion: backendVersion}
	copy(result.PublicKey[:], publicKey)
	return result, nil
}

func validNixCacheKeyName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		valid := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		if index > 0 {
			valid = valid || character == '.' || character == '_' || character == '-'
		}
		if !valid {
			return false
		}
	}
	return true
}

func allZero16(value [16]byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return false
		}
	}
	return true
}
