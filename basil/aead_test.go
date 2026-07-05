package basil_test

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/openbasil/basil-go/basil"
	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeAead struct {
	pb.UnimplementedAeadServiceServer

	mu          sync.Mutex
	lastEncrypt *pb.EncryptRequest
	lastDecrypt *pb.DecryptRequest
	lastWrap    *pb.WrapEnvelopeRequest
	lastUnwrap  *pb.UnwrapEnvelopeRequest
	lastUnseal  *pb.UnsealCoseRequest

	encryptResp *pb.EncryptResponse
	decryptResp *pb.DecryptResponse
	wrapResp    *pb.WrapEnvelopeResponse
	unwrapResp  *pb.UnwrapEnvelopeResponse
	unsealResp  *pb.UnsealCoseResponse
	err         error
}

func (f *fakeAead) Encrypt(_ context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	f.mu.Lock()
	f.lastEncrypt = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.encryptResp, nil
}

func (f *fakeAead) Decrypt(_ context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	f.mu.Lock()
	f.lastDecrypt = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.decryptResp, nil
}

func (f *fakeAead) WrapEnvelope(_ context.Context, req *pb.WrapEnvelopeRequest) (*pb.WrapEnvelopeResponse, error) {
	f.mu.Lock()
	f.lastWrap = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.wrapResp, nil
}

func (f *fakeAead) UnwrapEnvelope(_ context.Context, req *pb.UnwrapEnvelopeRequest) (*pb.UnwrapEnvelopeResponse, error) {
	f.mu.Lock()
	f.lastUnwrap = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.unwrapResp, nil
}

func (f *fakeAead) UnsealCose(_ context.Context, req *pb.UnsealCoseRequest) (*pb.UnsealCoseResponse, error) {
	f.mu.Lock()
	f.lastUnseal = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.unsealResp, nil
}

func dialAead(t *testing.T, f *fakeAead) *basil.Client {
	return serveAndDial(t, func(srv *grpc.Server) { pb.RegisterAeadServiceServer(srv, f) })
}

func TestEncryptBuildsRequestAndMapsEnvelope(t *testing.T) {
	f := &fakeAead{encryptResp: &pb.EncryptResponse{Envelope: &pb.CiphertextEnvelope{
		Alg:        pb.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
		KeyVersion: 3,
		Nonce:      []byte("nonce12bytes"),
		Ciphertext: []byte("ct+tag"),
	}}}
	c := dialAead(t, f)

	ct, err := c.Encrypt(context.Background(), "app.aead", basil.AeadAlgorithmAES256GCM, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ct.Algorithm != basil.AeadAlgorithmAES256GCM || ct.KeyVersion != 3 ||
		string(ct.Nonce) != "nonce12bytes" || string(ct.Bytes) != "ct+tag" {
		t.Errorf("unexpected ciphertext: %+v", ct)
	}

	f.mu.Lock()
	got := f.lastEncrypt
	f.mu.Unlock()
	if got.GetKeyId() != "app.aead" {
		t.Errorf("key_id = %q, want app.aead", got.GetKeyId())
	}
	if got.GetAlgorithm() != pb.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM {
		t.Errorf("algorithm = %v, want AES_256_GCM", got.GetAlgorithm())
	}
	if string(got.GetPlaintext()) != "secret" {
		t.Errorf("plaintext = %q, want secret", got.GetPlaintext())
	}
	if string(got.GetAad()) != "aad" {
		t.Errorf("aad = %q, want aad", got.GetAad())
	}
}

func TestEncryptAADOmittedWhenNil(t *testing.T) {
	f := &fakeAead{encryptResp: &pb.EncryptResponse{Envelope: &pb.CiphertextEnvelope{}}}
	c := dialAead(t, f)

	if _, err := c.Encrypt(context.Background(), "k", basil.AeadAlgorithmChaCha20Poly1305, []byte("p"), nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	f.mu.Lock()
	got := f.lastEncrypt
	f.mu.Unlock()
	if got.Aad != nil {
		t.Errorf("aad = %v, want nil (omitted)", got.Aad)
	}
}

func TestDecryptBuildsRequestAndReturnsPlaintext(t *testing.T) {
	f := &fakeAead{decryptResp: &pb.DecryptResponse{Plaintext: []byte("secret")}}
	c := dialAead(t, f)

	ct := &basil.Ciphertext{
		Algorithm:  basil.AeadAlgorithmAES256GCM,
		KeyVersion: 3,
		Nonce:      []byte("nonce12bytes"),
		Bytes:      []byte("ct+tag"),
	}
	pt, err := c.Decrypt(context.Background(), "app.aead", ct, []byte("aad"))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != "secret" {
		t.Errorf("plaintext = %q, want secret", pt)
	}

	f.mu.Lock()
	got := f.lastDecrypt
	f.mu.Unlock()
	env := got.GetEnvelope()
	if got.GetKeyId() != "app.aead" || env.GetKeyVersion() != 3 ||
		string(env.GetNonce()) != "nonce12bytes" || string(env.GetCiphertext()) != "ct+tag" {
		t.Errorf("unexpected decrypt request: %+v", got)
	}
	if env.GetAlg() != pb.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM {
		t.Errorf("envelope alg = %v, want AES_256_GCM", env.GetAlg())
	}
	if string(got.GetAad()) != "aad" {
		t.Errorf("aad = %q, want aad", got.GetAad())
	}
}

func TestWrapEnvelopeBuildsRequestAndMapsEnvelope(t *testing.T) {
	f := &fakeAead{wrapResp: &pb.WrapEnvelopeResponse{Envelope: &pb.KemEnvelope{
		KemAlgorithm:      pb.KemAlgorithm_KEM_ALGORITHM_ML_KEM_768,
		EnvelopeAlgorithm: pb.EnvelopeAlgorithm_ENVELOPE_ALGORITHM_AES_256_GCM,
		KeyVersion:        2,
		EncapsulatedKey:   []byte("kem-ct"),
		Nonce:             []byte("nonce"),
		Ciphertext:        []byte("payload"),
	}}}
	c := dialAead(t, f)

	env, err := c.WrapEnvelope(context.Background(), "kem.key",
		basil.KemAlgorithmMLKEM768, basil.EnvelopeAlgorithmAES256GCM, []byte("data"), nil)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if env.KemAlgorithm != basil.KemAlgorithmMLKEM768 ||
		env.EnvelopeAlgorithm != basil.EnvelopeAlgorithmAES256GCM ||
		env.KeyVersion != 2 || string(env.EncapsulatedKey) != "kem-ct" ||
		string(env.Nonce) != "nonce" || string(env.Bytes) != "payload" {
		t.Errorf("unexpected envelope: %+v", env)
	}

	f.mu.Lock()
	got := f.lastWrap
	f.mu.Unlock()
	if got.GetKeyId() != "kem.key" ||
		got.GetKemAlgorithm() != pb.KemAlgorithm_KEM_ALGORITHM_ML_KEM_768 ||
		got.GetEnvelopeAlgorithm() != pb.EnvelopeAlgorithm_ENVELOPE_ALGORITHM_AES_256_GCM ||
		string(got.GetPlaintext()) != "data" {
		t.Errorf("unexpected wrap request: %+v", got)
	}
}

func TestUnwrapEnvelopeBuildsRequestAndReturnsPlaintext(t *testing.T) {
	f := &fakeAead{unwrapResp: &pb.UnwrapEnvelopeResponse{Plaintext: []byte("data")}}
	c := dialAead(t, f)

	env := &basil.KemEnvelope{
		KemAlgorithm:      basil.KemAlgorithmX25519,
		EnvelopeAlgorithm: basil.EnvelopeAlgorithmChaCha20Poly1305,
		KeyVersion:        1,
		EncapsulatedKey:   []byte("ephemeral-pub"),
		Nonce:             []byte("nonce"),
		Bytes:             []byte("payload"),
	}
	pt, err := c.UnwrapEnvelope(context.Background(), "kem.key", env, []byte("aad"))
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if string(pt) != "data" {
		t.Errorf("plaintext = %q, want data", pt)
	}

	f.mu.Lock()
	got := f.lastUnwrap
	f.mu.Unlock()
	gotEnv := got.GetEnvelope()
	if got.GetKeyId() != "kem.key" ||
		gotEnv.GetKemAlgorithm() != pb.KemAlgorithm_KEM_ALGORITHM_X25519 ||
		string(gotEnv.GetEncapsulatedKey()) != "ephemeral-pub" ||
		!bytes.Equal(got.GetAad(), []byte("aad")) {
		t.Errorf("unexpected unwrap request: %+v", got)
	}
}

func TestUnsealCoseBuildsRequestAndReturnsPlaintext(t *testing.T) {
	f := &fakeAead{unsealResp: &pb.UnsealCoseResponse{Plaintext: []byte("data")}}
	c := dialAead(t, f)

	pt, err := c.UnsealCose(context.Background(), "cose.key", []byte("tagged-cose"), []byte("aad"))
	if err != nil {
		t.Fatalf("unseal cose: %v", err)
	}
	if string(pt) != "data" {
		t.Errorf("plaintext = %q, want data", pt)
	}

	f.mu.Lock()
	got := f.lastUnseal
	f.mu.Unlock()
	if got.GetKeyId() != "cose.key" ||
		!bytes.Equal(got.GetCoseEncrypt(), []byte("tagged-cose")) ||
		!bytes.Equal(got.GetExternalAad(), []byte("aad")) {
		t.Errorf("unexpected unseal request: %+v", got)
	}
}

func TestEncryptMapsStatusError(t *testing.T) {
	st := status.New(codes.PermissionDenied, "policy denied the encrypt")
	st, err := st.WithDetails(&pb.BrokerErrorInfo{Reason: "UNAUTHORIZED", Op: "encrypt"})
	if err != nil {
		t.Fatalf("attach detail: %v", err)
	}
	c := dialAead(t, &fakeAead{err: st.Err()})

	_, gotErr := c.Encrypt(context.Background(), "k", basil.AeadAlgorithmAES256GCM, []byte("p"), nil)
	se, ok := basil.AsStatusError(gotErr)
	if !ok {
		t.Fatalf("error is not a *StatusError: %v", gotErr)
	}
	if se.Code != codes.PermissionDenied || se.Reason != "UNAUTHORIZED" || se.Op != "encrypt" {
		t.Errorf("unexpected status error: %+v", se)
	}
}
