package basil_test

import (
	"context"
	"strings"
	"testing"

	"github.com/openbasil/basil-go/basil"
	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

type fakeNixCacheService struct {
	pb.UnimplementedNixCacheServiceServer
	describeRequest *pb.DescribeNixCacheKeyRequest
	enrollRequest   *pb.EnrollNixCacheKeyRequest
	signRequest     *pb.SignNixCacheFingerprintRequest
	wrongEcho       bool
	rawSuffix       []byte
	keyName         string
}

func (f *fakeNixCacheService) DescribeNixCacheKey(_ context.Context, request *pb.DescribeNixCacheKeyRequest) (*pb.DescribeNixCacheKeyResponse, error) {
	f.describeRequest = request
	batchID, requestID := f.echoes(request.GetBatchId(), request.GetRequestId())
	response := &pb.DescribeNixCacheKeyResponse{
		KeyName: f.responseKeyName(), PublicKey: make([]byte, 32), BackendVersion: 1,
		BatchId: batchID, RequestId: requestID,
	}
	f.addRawSuffix(response)
	return response, nil
}

func (f *fakeNixCacheService) EnrollNixCacheKey(_ context.Context, request *pb.EnrollNixCacheKeyRequest) (*pb.EnrollNixCacheKeyResponse, error) {
	f.enrollRequest = request
	batchID, requestID := f.echoes(request.GetBatchId(), request.GetRequestId())
	return &pb.EnrollNixCacheKeyResponse{
		KeyName: "cache.example-1", PublicKey: make([]byte, 32), BackendVersion: 1,
		Disposition: pb.NixCacheEnrollmentDisposition_NIX_CACHE_ENROLLMENT_DISPOSITION_CREATED,
		BatchId:     batchID, RequestId: requestID,
	}, nil
}

func (f *fakeNixCacheService) SignNixCacheFingerprint(_ context.Context, request *pb.SignNixCacheFingerprintRequest) (*pb.SignNixCacheFingerprintResponse, error) {
	f.signRequest = request
	batchID, requestID := f.echoes(request.GetBatchId(), request.GetRequestId())
	return &pb.SignNixCacheFingerprintResponse{
		KeyName: "cache.example-1", PublicKey: make([]byte, 32), BackendVersion: 1,
		Signature: make([]byte, 64), BatchId: batchID, RequestId: requestID,
	}, nil
}

func (f *fakeNixCacheService) echoes(batchID, requestID []byte) ([]byte, []byte) {
	if f.wrongEcho {
		return bytes16(9), requestID
	}
	return batchID, requestID
}

func (f *fakeNixCacheService) addRawSuffix(message proto.Message) {
	if len(f.rawSuffix) != 0 {
		message.ProtoReflect().SetUnknown(append([]byte(nil), f.rawSuffix...))
	}
}

func (f *fakeNixCacheService) responseKeyName() string {
	if f.keyName != "" {
		return f.keyName
	}
	return "cache.example-1"
}

func dialNixCache(t *testing.T, fake *fakeNixCacheService) *basil.Client {
	t.Helper()
	return serveAndDial(t, func(server *grpc.Server) { pb.RegisterNixCacheServiceServer(server, fake) })
}

func TestNixCacheOperationsUsePurposeSpecificRPCs(t *testing.T) {
	fake := &fakeNixCacheService{}
	client := dialNixCache(t, fake)
	batchID, requestID := id16(1), id16(2)

	key, err := client.DescribeNixCacheKey(context.Background(), "catalog-key", batchID, requestID)
	if err != nil {
		t.Fatalf("DescribeNixCacheKey: %v", err)
	}
	if key.KeyName != "cache.example-1" || fake.describeRequest.GetKeyId() != "catalog-key" {
		t.Fatalf("unexpected describe result/request: %#v %#v", key, fake.describeRequest)
	}

	enrollment, err := client.EnrollNixCacheKey(context.Background(), "catalog-key", batchID, requestID)
	if err != nil {
		t.Fatalf("EnrollNixCacheKey: %v", err)
	}
	if enrollment.Disposition != basil.NixCacheEnrollmentCreated || fake.enrollRequest.GetKeyId() != "catalog-key" {
		t.Fatalf("unexpected enrollment result/request: %#v %#v", enrollment, fake.enrollRequest)
	}

	signature, err := client.SignNixCacheFingerprint(context.Background(), "catalog-key", []byte("fingerprint"), batchID, requestID)
	if err != nil {
		t.Fatalf("SignNixCacheFingerprint: %v", err)
	}
	if len(signature.Signature) != 64 || fake.signRequest.GetProfile() != "PATH_INFO_V1" || string(fake.signRequest.GetFingerprint()) != "fingerprint" {
		t.Fatalf("unexpected sign result/request: %#v %#v", signature, fake.signRequest)
	}
}

func TestNixCacheClientRejectsInvalidInputsBeforeRPC(t *testing.T) {
	fake := &fakeNixCacheService{}
	client := dialNixCache(t, fake)
	zero, requestID := [16]byte{}, id16(2)
	if _, err := client.DescribeNixCacheKey(context.Background(), "catalog-key", zero, requestID); err == nil {
		t.Fatal("zero batch ID accepted")
	}
	if _, err := client.EnrollNixCacheKey(context.Background(), strings.Repeat("k", 257), id16(1), requestID); err == nil {
		t.Fatal("oversized key ID accepted")
	}
	if _, err := client.SignNixCacheFingerprint(context.Background(), "catalog-key", nil, id16(1), requestID); err == nil {
		t.Fatal("empty fingerprint accepted")
	}
	if fake.describeRequest != nil || fake.enrollRequest != nil || fake.signRequest != nil {
		t.Fatal("invalid request reached RPC server")
	}
}

func TestNixCacheClientRejectsChangedCorrelationID(t *testing.T) {
	client := dialNixCache(t, &fakeNixCacheService{wrongEcho: true})
	_, err := client.DescribeNixCacheKey(context.Background(), "catalog-key", id16(1), id16(2))
	if err == nil || !strings.Contains(err.Error(), "changed a correlation ID") {
		t.Fatalf("DescribeNixCacheKey error = %v, want correlation failure", err)
	}
}

func TestNixCacheGeneratedClientRejectsDuplicateRawResponseField(t *testing.T) {
	duplicateKeyName := protowire.AppendTag(nil, 1, protowire.BytesType)
	duplicateKeyName = protowire.AppendBytes(duplicateKeyName, []byte("other.example-1"))
	client := dialNixCache(t, &fakeNixCacheService{rawSuffix: duplicateKeyName})
	_, err := client.DescribeNixCacheKey(context.Background(), "catalog-key", id16(1), id16(2))
	if err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("DescribeNixCacheKey error = %v, want raw duplicate rejection", err)
	}
}

func TestNixCacheGeneratedClientEnforcesExactReceiveLimit(t *testing.T) {
	client := dialNixCache(t, &fakeNixCacheService{keyName: strings.Repeat("k", 129)})
	_, err := client.DescribeNixCacheKey(context.Background(), "catalog-key", id16(1), id16(2))
	if err == nil || !strings.Contains(err.Error(), "larger than max (204 vs. 203)") {
		t.Fatalf("DescribeNixCacheKey error = %v, want exact 203-byte receive limit", err)
	}
}

func TestNixCacheStrictCodecIsScopedPerCall(t *testing.T) {
	nixFake := &fakeNixCacheService{}
	signingFake := &fakeSigning{signResp: &pb.SignResponse{Signature: []byte("ordinary")}}
	client := serveAndDial(t, func(server *grpc.Server) {
		pb.RegisterNixCacheServiceServer(server, nixFake)
		pb.RegisterSigningServiceServer(server, signingFake)
	})
	if _, err := client.DescribeNixCacheKey(context.Background(), "catalog-key", id16(1), id16(2)); err != nil {
		t.Fatalf("DescribeNixCacheKey: %v", err)
	}
	signature, err := client.Sign(context.Background(), "ordinary-key", []byte("message"))
	if err != nil {
		t.Fatalf("ordinary Sign after strict Nix call: %v", err)
	}
	if string(signature) != "ordinary" {
		t.Fatalf("ordinary Sign signature = %q", signature)
	}
}

func id16(value byte) [16]byte {
	var result [16]byte
	for index := range result {
		result[index] = value
	}
	return result
}

func bytes16(value byte) []byte {
	result := id16(value)
	return result[:]
}
