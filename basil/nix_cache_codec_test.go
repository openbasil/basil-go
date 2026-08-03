package basil

import (
	"strings"
	"testing"

	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestNixCacheStrictCodecAcceptsAllSixSchemas(t *testing.T) {
	codec := nixCacheProtoCodec{}
	for _, message := range validNixCacheMessages() {
		raw, err := codec.Marshal(message)
		if err != nil {
			t.Fatalf("Marshal(%T): %v", message, err)
		}
		decoded := message.ProtoReflect().Type().New().Interface()
		if err := codec.Unmarshal(raw, decoded); err != nil {
			t.Fatalf("Unmarshal(%T): %v", message, err)
		}
	}
}

func TestNixCacheStrictCodecRejectsRawWireViolations(t *testing.T) {
	codec := nixCacheProtoCodec{}
	describe := validNixCacheMessages()[0]
	raw, err := proto.Marshal(describe)
	if err != nil {
		t.Fatalf("marshal describe: %v", err)
	}

	unknown := append([]byte(nil), raw...)
	unknown = protowire.AppendTag(unknown, 4, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 1)
	assertStrictCodecRejects(t, codec, unknown, &pb.DescribeNixCacheKeyRequest{}, "unknown field")

	duplicate := append([]byte(nil), raw...)
	duplicate = protowire.AppendTag(duplicate, 1, protowire.BytesType)
	duplicate = protowire.AppendBytes(duplicate, []byte("other"))
	assertStrictCodecRejects(t, codec, duplicate, &pb.DescribeNixCacheKeyRequest{}, "duplicate field")

	wrongWire := protowire.AppendTag(nil, 1, protowire.VarintType)
	wrongWire = protowire.AppendVarint(wrongWire, 1)
	assertStrictCodecRejects(t, codec, wrongWire, &pb.SignNixCacheFingerprintRequest{}, "wire type")

	missing, err := proto.Marshal(&pb.EnrollNixCacheKeyRequest{KeyId: "k", BatchId: bytes16ForCodec(1)})
	if err != nil {
		t.Fatalf("marshal missing: %v", err)
	}
	assertStrictCodecRejects(t, codec, missing, &pb.EnrollNixCacheKeyRequest{}, "missing required field")

	invalidEnum, err := proto.Marshal(&pb.EnrollNixCacheKeyResponse{
		KeyName: "cache.example-1", PublicKey: make([]byte, 32), BackendVersion: 1,
		Disposition: 3, BatchId: bytes16ForCodec(1), RequestId: bytes16ForCodec(2),
	})
	if err != nil {
		t.Fatalf("marshal invalid enum: %v", err)
	}
	assertStrictCodecRejects(t, codec, invalidEnum, &pb.EnrollNixCacheKeyResponse{}, "invalid enum")

	oversized, err := proto.Marshal(&pb.SignNixCacheFingerprintRequest{
		KeyId: strings.Repeat("k", 256), Profile: "PATH_INFO_V1",
		Fingerprint: make([]byte, nixCacheFingerprintMax+1),
		BatchId:     bytes16ForCodec(1), RequestId: bytes16ForCodec(2),
	})
	if err != nil {
		t.Fatalf("marshal oversized: %v", err)
	}
	assertStrictCodecRejects(t, codec, oversized, &pb.SignNixCacheFingerprintRequest{}, "maximum")
}

func assertStrictCodecRejects(t *testing.T, codec nixCacheProtoCodec, raw []byte, message proto.Message, want string) {
	t.Helper()
	err := codec.Unmarshal(raw, message)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Unmarshal(%T) error = %v, want %q", message, err, want)
	}
}

func validNixCacheMessages() []proto.Message {
	return []proto.Message{
		&pb.DescribeNixCacheKeyRequest{KeyId: "k", BatchId: bytes16ForCodec(1), RequestId: bytes16ForCodec(2)},
		&pb.DescribeNixCacheKeyResponse{KeyName: "cache.example-1", PublicKey: make([]byte, 32), BackendVersion: 1, BatchId: bytes16ForCodec(1), RequestId: bytes16ForCodec(2)},
		&pb.EnrollNixCacheKeyRequest{KeyId: "k", BatchId: bytes16ForCodec(1), RequestId: bytes16ForCodec(2)},
		&pb.EnrollNixCacheKeyResponse{KeyName: "cache.example-1", PublicKey: make([]byte, 32), BackendVersion: 1, Disposition: pb.NixCacheEnrollmentDisposition_NIX_CACHE_ENROLLMENT_DISPOSITION_CREATED, BatchId: bytes16ForCodec(1), RequestId: bytes16ForCodec(2)},
		&pb.SignNixCacheFingerprintRequest{KeyId: "k", Profile: "PATH_INFO_V1", Fingerprint: []byte("fingerprint"), BatchId: bytes16ForCodec(1), RequestId: bytes16ForCodec(2)},
		&pb.SignNixCacheFingerprintResponse{KeyName: "cache.example-1", PublicKey: make([]byte, 32), BackendVersion: 1, Signature: make([]byte, 64), BatchId: bytes16ForCodec(1), RequestId: bytes16ForCodec(2)},
	}
}

func bytes16ForCodec(value byte) []byte {
	result := make([]byte, 16)
	for index := range result {
		result[index] = value
	}
	return result
}
