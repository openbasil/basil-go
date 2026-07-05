package basil_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openbasil/basil-go/basil"
	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeSigning is an in-process SigningService used to drive the client without
// a live broker. It records the last request of each kind and returns either a
// canned response or a canned error.
type fakeSigning struct {
	pb.UnimplementedSigningServiceServer

	mu            sync.Mutex
	lastSign      *pb.SignRequest
	lastVerify    *pb.VerifyRequest
	lastPublic    *pb.GetPublicKeyRequest
	lastNewKey    *pb.NewKeyRequest
	lastImport    *pb.ImportRequest
	lastImportSet *pb.ImportSetRequest

	signResp      *pb.SignResponse
	verifyResp    *pb.VerifyResponse
	publicResp    *pb.GetPublicKeyResponse
	newKeyResp    *pb.NewKeyResponse
	importSetResp *pb.ImportSetResponse
	err           error         // if non-nil, returned by every RPC
	delay         time.Duration // artificial Sign latency, honoring ctx
}

func (f *fakeSigning) NewKey(_ context.Context, req *pb.NewKeyRequest) (*pb.NewKeyResponse, error) {
	f.mu.Lock()
	f.lastNewKey = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.newKeyResp, nil
}

func (f *fakeSigning) Import(_ context.Context, req *pb.ImportRequest) (*pb.NewKeyResponse, error) {
	f.mu.Lock()
	f.lastImport = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.newKeyResp, nil
}

func (f *fakeSigning) ImportSet(_ context.Context, req *pb.ImportSetRequest) (*pb.ImportSetResponse, error) {
	f.mu.Lock()
	f.lastImportSet = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.importSetResp, nil
}

func (f *fakeSigning) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	f.mu.Lock()
	f.lastSign = req
	f.mu.Unlock()
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.signResp, nil
}

func (f *fakeSigning) Verify(_ context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	f.mu.Lock()
	f.lastVerify = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.verifyResp, nil
}

func (f *fakeSigning) GetPublicKey(_ context.Context, req *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	f.mu.Lock()
	f.lastPublic = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.publicResp, nil
}

// startFakeServer serves f over a fresh Unix socket and returns its path.
func startFakeServer(t *testing.T, f *fakeSigning) string {
	t.Helper()
	// A short socket path keeps us well under the AF_UNIX 108-byte limit.
	sock := filepath.Join(t.TempDir(), "b.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %q: %v", sock, err)
	}
	srv := grpc.NewServer()
	pb.RegisterSigningServiceServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return sock
}

func dialFake(t *testing.T, f *fakeSigning) *basil.Client {
	t.Helper()
	c, err := basil.Dial(startFakeServer(t, f))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSignBuildsRequestAndReturnsSignature(t *testing.T) {
	f := &fakeSigning{signResp: &pb.SignResponse{Signature: []byte("sigbytes")}}
	c := dialFake(t, f)

	sig, err := c.SignWithAlgorithm(context.Background(), "app.signing", []byte("payload"), basil.SigningAlgorithmEd25519)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if string(sig) != "sigbytes" {
		t.Errorf("signature = %q, want %q", sig, "sigbytes")
	}

	f.mu.Lock()
	got := f.lastSign
	f.mu.Unlock()
	if got.GetKeyId() != "app.signing" {
		t.Errorf("key_id = %q, want app.signing", got.GetKeyId())
	}
	if string(got.GetMessage()) != "payload" {
		t.Errorf("message = %q, want payload", got.GetMessage())
	}
	if got.GetAlgorithm() != pb.SigningAlgorithm_SIGNING_ALGORITHM_ED25519 {
		t.Errorf("algorithm = %v, want ED25519", got.GetAlgorithm())
	}
}

func TestSignDefaultsToUnspecifiedAlgorithm(t *testing.T) {
	f := &fakeSigning{signResp: &pb.SignResponse{Signature: []byte{1}}}
	c := dialFake(t, f)

	if _, err := c.Sign(context.Background(), "k", []byte("m")); err != nil {
		t.Fatalf("sign: %v", err)
	}
	f.mu.Lock()
	got := f.lastSign.GetAlgorithm()
	f.mu.Unlock()
	if got != pb.SigningAlgorithm_SIGNING_ALGORITHM_UNSPECIFIED {
		t.Errorf("algorithm = %v, want UNSPECIFIED", got)
	}
}

func TestVerifyReturnsValidAndBuildsRequest(t *testing.T) {
	f := &fakeSigning{verifyResp: &pb.VerifyResponse{Valid: true}}
	c := dialFake(t, f)

	ok, err := c.Verify(context.Background(), "k", []byte("m"), []byte("s"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Errorf("valid = false, want true")
	}
	f.mu.Lock()
	got := f.lastVerify
	f.mu.Unlock()
	if got.GetKeyId() != "k" || string(got.GetMessage()) != "m" || string(got.GetSignature()) != "s" {
		t.Errorf("unexpected verify request: %+v", got)
	}
}

func TestVerifyFalseIsNotAnError(t *testing.T) {
	f := &fakeSigning{verifyResp: &pb.VerifyResponse{Valid: false}}
	c := dialFake(t, f)

	ok, err := c.Verify(context.Background(), "k", []byte("m"), []byte("s"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Errorf("valid = true, want false")
	}
}

func TestGetPublicKeyMapsResponse(t *testing.T) {
	f := &fakeSigning{publicResp: &pb.GetPublicKeyResponse{
		KeyId:     "app.signing",
		KeyType:   pb.KeyType_KEY_TYPE_ED25519,
		PublicKey: []byte("pub"),
		Version:   7,
	}}
	c := dialFake(t, f)

	ver := uint32(7)
	pub, err := c.GetPublicKey(context.Background(), "app.signing", &ver)
	if err != nil {
		t.Fatalf("get public key: %v", err)
	}
	if pub.KeyID != "app.signing" || pub.KeyType != basil.KeyTypeEd25519 || string(pub.Bytes) != "pub" || pub.Version != 7 {
		t.Errorf("unexpected public key: %+v", pub)
	}

	f.mu.Lock()
	got := f.lastPublic
	f.mu.Unlock()
	if got.Version == nil || got.GetVersion() != 7 {
		t.Errorf("version field = %v, want explicit 7", got.Version)
	}
}

func TestGetPublicKeyNilVersionOmitsField(t *testing.T) {
	f := &fakeSigning{publicResp: &pb.GetPublicKeyResponse{KeyId: "k"}}
	c := dialFake(t, f)

	if _, err := c.GetPublicKey(context.Background(), "k", nil); err != nil {
		t.Fatalf("get public key: %v", err)
	}
	f.mu.Lock()
	got := f.lastPublic
	f.mu.Unlock()
	if got.Version != nil {
		t.Errorf("version = %v, want nil (omitted)", *got.Version)
	}
}

func TestStatusErrorExtractsBrokerReasonAndOp(t *testing.T) {
	st := status.New(codes.PermissionDenied, "policy denied the sign")
	st, err := st.WithDetails(&pb.BrokerErrorInfo{Reason: "UNAUTHORIZED", Op: "sign"})
	if err != nil {
		t.Fatalf("attach detail: %v", err)
	}
	f := &fakeSigning{err: st.Err()}
	c := dialFake(t, f)

	_, gotErr := c.Sign(context.Background(), "k", []byte("m"))
	if gotErr == nil {
		t.Fatal("expected an error")
	}

	se, ok := basil.AsStatusError(gotErr)
	if !ok {
		t.Fatalf("error is not a *StatusError: %v", gotErr)
	}
	if se.Code != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", se.Code)
	}
	if se.Reason != "UNAUTHORIZED" {
		t.Errorf("reason = %q, want UNAUTHORIZED", se.Reason)
	}
	if se.Op != "sign" {
		t.Errorf("op = %q, want sign", se.Op)
	}
	// status.Code must still recover the canonical code from our error.
	if status.Code(gotErr) != codes.PermissionDenied {
		t.Errorf("status.Code = %v, want PermissionDenied", status.Code(gotErr))
	}
}

func TestStatusErrorWithoutDetailHasEmptyReason(t *testing.T) {
	f := &fakeSigning{err: status.Error(codes.Unavailable, "boom")}
	c := dialFake(t, f)

	_, err := c.Sign(context.Background(), "k", []byte("m"))
	se, ok := basil.AsStatusError(err)
	if !ok {
		t.Fatalf("error is not a *StatusError: %v", err)
	}
	if se.Reason != "" || se.Op != "" {
		t.Errorf("reason/op = %q/%q, want empty", se.Reason, se.Op)
	}
	if se.Code != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", se.Code)
	}
}

func TestErrorsAsMatchesStatusError(t *testing.T) {
	f := &fakeSigning{err: status.Error(codes.NotFound, "no such key")}
	c := dialFake(t, f)

	_, err := c.GetPublicKey(context.Background(), "missing", nil)
	var se *basil.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("errors.As did not match *StatusError: %v", err)
	}
	if se.Code != codes.NotFound {
		t.Errorf("code = %v, want NotFound", se.Code)
	}
}

func TestNewKeyBuildsRequestAndMapsHandle(t *testing.T) {
	f := &fakeSigning{newKeyResp: &pb.NewKeyResponse{KeyId: "app.ecdsa384", PublicKey: []byte("pub")}}
	c := dialFake(t, f)

	h, err := c.NewKey(context.Background(), "app.ecdsa384", basil.KeyTypeECDSAP384)
	if err != nil {
		t.Fatalf("new key: %v", err)
	}
	if h.KeyID != "app.ecdsa384" || string(h.PublicKey) != "pub" {
		t.Errorf("unexpected handle: %+v", h)
	}
	f.mu.Lock()
	got := f.lastNewKey
	f.mu.Unlock()
	if got.GetKeyId() != "app.ecdsa384" {
		t.Errorf("key_id = %q, want app.ecdsa384", got.GetKeyId())
	}
	if got.GetKeyType() != pb.KeyType_KEY_TYPE_ECDSA_P384 {
		t.Errorf("key_type = %v, want ECDSA_P384", got.GetKeyType())
	}
}

func TestImportBuildsEd25519SeedMaterial(t *testing.T) {
	f := &fakeSigning{newKeyResp: &pb.NewKeyResponse{KeyId: "nats.operator", PublicKey: []byte("op")}}
	c := dialFake(t, f)

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	h, err := c.Import(context.Background(), "nats.operator", basil.KeyTypeEd25519, basil.Ed25519SeedMaterial(seed))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if h.KeyID != "nats.operator" || string(h.PublicKey) != "op" {
		t.Errorf("unexpected handle: %+v", h)
	}
	f.mu.Lock()
	got := f.lastImport
	f.mu.Unlock()
	if got.GetKeyType() != pb.KeyType_KEY_TYPE_ED25519 {
		t.Errorf("key_type = %v, want ED25519", got.GetKeyType())
	}
	if !bytes.Equal(got.GetMaterial().GetEd25519Seed(), seed) {
		t.Errorf("ed25519_seed = %x, want %x", got.GetMaterial().GetEd25519Seed(), seed)
	}
	if got.GetMaterial().GetPkcs8Der() != nil {
		t.Errorf("pkcs8_der set, want only ed25519_seed")
	}
}

func TestImportRejectsNilMaterialBeforeRPC(t *testing.T) {
	f := &fakeSigning{}
	c := dialFake(t, f)

	if _, err := c.Import(context.Background(), "k", basil.KeyTypeEd25519, nil); err == nil {
		t.Fatal("expected an error for nil material")
	}
	f.mu.Lock()
	reached := f.lastImport
	f.mu.Unlock()
	if reached != nil {
		t.Errorf("RPC was sent despite nil material: %+v", reached)
	}
}

func TestImportSetMapsPkcs8AndPreservesOrder(t *testing.T) {
	f := &fakeSigning{importSetResp: &pb.ImportSetResponse{Keys: []*pb.ImportedKey{
		{KeyId: "a", PublicKey: []byte("pa")},
		{KeyId: "b", PublicKey: []byte("pb")},
	}}}
	c := dialFake(t, f)

	der := []byte{0x30, 0x2e, 0x02, 0x01}
	keys, err := c.ImportSet(context.Background(), []basil.ImportEntry{
		{KeyID: "a", KeyType: basil.KeyTypeEd25519, Material: basil.Ed25519SeedMaterial([]byte("seed"))},
		{KeyID: "b", KeyType: basil.KeyTypeECDSAP521, Material: basil.PKCS8DERMaterial(der)},
	})
	if err != nil {
		t.Fatalf("import set: %v", err)
	}
	if len(keys) != 2 || keys[0].KeyID != "a" || keys[1].KeyID != "b" ||
		string(keys[0].PublicKey) != "pa" || string(keys[1].PublicKey) != "pb" {
		t.Errorf("unexpected keys: %+v", keys)
	}
	f.mu.Lock()
	got := f.lastImportSet
	f.mu.Unlock()
	if len(got.GetEntries()) != 2 {
		t.Fatalf("entries = %d, want 2", len(got.GetEntries()))
	}
	if got.GetEntries()[1].GetKeyType() != pb.KeyType_KEY_TYPE_ECDSA_P521 {
		t.Errorf("entry[1] key_type = %v, want ECDSA_P521", got.GetEntries()[1].GetKeyType())
	}
	if !bytes.Equal(got.GetEntries()[1].GetMaterial().GetPkcs8Der(), der) {
		t.Errorf("entry[1] pkcs8_der = %x, want %x", got.GetEntries()[1].GetMaterial().GetPkcs8Der(), der)
	}
}

func TestImportSetRejectsNilEntryMaterial(t *testing.T) {
	f := &fakeSigning{}
	c := dialFake(t, f)

	_, err := c.ImportSet(context.Background(), []basil.ImportEntry{
		{KeyID: "ok", KeyType: basil.KeyTypeEd25519, Material: basil.Ed25519SeedMaterial([]byte("s"))},
		{KeyID: "bad", KeyType: basil.KeyTypeEd25519},
	})
	if err == nil {
		t.Fatal("expected an error for a nil-material entry")
	}
	f.mu.Lock()
	reached := f.lastImportSet
	f.mu.Unlock()
	if reached != nil {
		t.Errorf("RPC was sent despite a nil-material entry: %+v", reached)
	}
}

func TestNewKeyMapsStatusError(t *testing.T) {
	f := &fakeSigning{err: status.Error(codes.PermissionDenied, "denied")}
	c := dialFake(t, f)

	_, err := c.NewKey(context.Background(), "k", basil.KeyTypeEd25519)
	se, ok := basil.AsStatusError(err)
	if !ok {
		t.Fatalf("error is not a *StatusError: %v", err)
	}
	if se.Code != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", se.Code)
	}
}
