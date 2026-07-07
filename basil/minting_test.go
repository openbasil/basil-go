package basil_test

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/openbasil/basil-go/basil"
	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeMinting struct {
	pb.UnimplementedMintingServiceServer
	pb.UnimplementedNatsServiceServer

	mu       sync.Mutex
	lastJwt  *pb.MintJwtRequest
	lastUser *pb.MintNatsUserRequest
	lastSign *pb.SignNatsJwtRequest
	lastCert *pb.IssueCertificateRequest
	lastEnc  *pb.EncryptNatsCurveRequest
	lastDec  *pb.DecryptNatsCurveRequest
	lastVal  *pb.ValidateNatsJwtRequest

	credResp     *pb.CredentialResponse
	certResp     *pb.IssueCertificateResponse
	encResp      *pb.EncryptNatsCurveResponse
	decResp      *pb.DecryptNatsCurveResponse
	validateResp *pb.ValidateNatsJwtResponse
	err          error
}

func (f *fakeMinting) MintJwt(_ context.Context, req *pb.MintJwtRequest) (*pb.CredentialResponse, error) {
	f.mu.Lock()
	f.lastJwt = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.credResp, nil
}

func (f *fakeMinting) MintNatsUser(_ context.Context, req *pb.MintNatsUserRequest) (*pb.CredentialResponse, error) {
	f.mu.Lock()
	f.lastUser = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.credResp, nil
}

func (f *fakeMinting) SignNatsJwt(_ context.Context, req *pb.SignNatsJwtRequest) (*pb.CredentialResponse, error) {
	f.mu.Lock()
	f.lastSign = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.credResp, nil
}

func (f *fakeMinting) EncryptNatsCurve(_ context.Context, req *pb.EncryptNatsCurveRequest) (*pb.EncryptNatsCurveResponse, error) {
	f.mu.Lock()
	f.lastEnc = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.encResp, nil
}

func (f *fakeMinting) DecryptNatsCurve(_ context.Context, req *pb.DecryptNatsCurveRequest) (*pb.DecryptNatsCurveResponse, error) {
	f.mu.Lock()
	f.lastDec = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.decResp, nil
}

func (f *fakeMinting) ValidateNatsJwt(_ context.Context, req *pb.ValidateNatsJwtRequest) (*pb.ValidateNatsJwtResponse, error) {
	f.mu.Lock()
	f.lastVal = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.validateResp, nil
}

func (f *fakeMinting) IssueCertificate(_ context.Context, req *pb.IssueCertificateRequest) (*pb.IssueCertificateResponse, error) {
	f.mu.Lock()
	f.lastCert = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.certResp, nil
}

func dialMinting(t *testing.T, f *fakeMinting) *basil.Client {
	return serveAndDial(t, func(srv *grpc.Server) {
		pb.RegisterMintingServiceServer(srv, f)
		pb.RegisterNatsServiceServer(srv, f)
	})
}

func TestMintJwtBuildsRequestAndMapsExpiry(t *testing.T) {
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	f := &fakeMinting{credResp: &pb.CredentialResponse{
		Token:     "header.payload.sig",
		ExpiresAt: timestamppb.New(exp),
	}}
	c := dialMinting(t, f)

	cred, err := c.MintJwt(context.Background(), basil.JwtRequest{
		KeyID:   "app.signing",
		Subject: "svc-a",
		TTL:     15 * time.Minute,
		Claims:  map[string]any{"env": "prod", "large": uint64(1)<<53 + 1},
	})
	if err != nil {
		t.Fatalf("mint jwt: %v", err)
	}
	if cred.Token != "header.payload.sig" {
		t.Errorf("token = %q", cred.Token)
	}
	if !cred.ExpiresAt.Equal(exp) {
		t.Errorf("expires_at = %v, want %v", cred.ExpiresAt, exp)
	}

	f.mu.Lock()
	got := f.lastJwt
	f.mu.Unlock()
	if got.GetKeyId() != "app.signing" {
		t.Errorf("key_id = %q", got.GetKeyId())
	}
	if got.Subject == nil || got.GetSubject() != "svc-a" {
		t.Errorf("subject = %v, want svc-a", got.Subject)
	}
	if got.GetTtl().AsDuration() != 15*time.Minute {
		t.Errorf("ttl = %v, want 15m", got.GetTtl().AsDuration())
	}
	var claims map[string]any
	dec := json.NewDecoder(bytes.NewReader(got.GetExtraClaimsJson()))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		t.Fatalf("extra_claims_json is not JSON: %v", err)
	}
	if claims["env"] != "prod" {
		t.Errorf("claims.env = %v, want prod", claims["env"])
	}
	large, ok := claims["large"].(json.Number)
	if !ok || large.String() != "9007199254740993" {
		t.Errorf("claims.large = %v, want 9007199254740993", claims["large"])
	}
}

func TestMintJwtNonExpiringOmitsTTLAndSubject(t *testing.T) {
	f := &fakeMinting{credResp: &pb.CredentialResponse{Token: "t"}}
	c := dialMinting(t, f)

	cred, err := c.MintJwt(context.Background(), basil.JwtRequest{KeyID: "k"})
	if err != nil {
		t.Fatalf("mint jwt: %v", err)
	}
	if !cred.ExpiresAt.IsZero() {
		t.Errorf("expires_at = %v, want zero (non-expiring)", cred.ExpiresAt)
	}
	f.mu.Lock()
	got := f.lastJwt
	f.mu.Unlock()
	if got.Ttl != nil {
		t.Errorf("ttl = %v, want nil (omitted)", got.Ttl)
	}
	if got.Subject != nil {
		t.Errorf("subject = %v, want nil (omitted)", got.Subject)
	}
	if len(got.GetExtraClaimsJson()) != 0 {
		t.Errorf("extra_claims_json = %s, want empty (omitted)", got.GetExtraClaimsJson())
	}
}

func TestMintJwtRejectsInvalidClaimsBeforeWire(t *testing.T) {
	f := &fakeMinting{credResp: &pb.CredentialResponse{Token: "t"}}
	c := dialMinting(t, f)

	_, err := c.MintJwt(context.Background(), basil.JwtRequest{
		KeyID:  "k",
		Claims: map[string]any{"bad": make(chan int)},
	})
	if err == nil {
		t.Fatal("expected an error for an unrepresentable claim")
	}
	f.mu.Lock()
	called := f.lastJwt
	f.mu.Unlock()
	if called != nil {
		t.Error("request reached the wire despite invalid claims")
	}
}

func TestMintNatsUserBuildsRequest(t *testing.T) {
	f := &fakeMinting{credResp: &pb.CredentialResponse{Token: "ucreds"}}
	c := dialMinting(t, f)

	if _, err := c.MintNatsUser(context.Background(), basil.NatsUserRequest{
		KeyID:           "nats.account",
		SubjectUserNKey: "UABC",
		Name:            "alice",
		TTL:             time.Hour,
		PubAllow:        []string{"orders.>"},
		SubDeny:         []string{"secret.>"},
		IssuerAccount:   "AISSUER",
	}); err != nil {
		t.Fatalf("mint nats user: %v", err)
	}
	f.mu.Lock()
	got := f.lastUser
	f.mu.Unlock()
	if got.GetKeyId() != "nats.account" || got.GetSubjectUserNkey() != "UABC" || got.GetName() != "alice" {
		t.Errorf("unexpected request: %+v", got)
	}
	if got.GetTtl().AsDuration() != time.Hour {
		t.Errorf("ttl = %v, want 1h", got.GetTtl().AsDuration())
	}
	if len(got.GetPubAllow()) != 1 || got.GetPubAllow()[0] != "orders.>" {
		t.Errorf("pub_allow = %v", got.GetPubAllow())
	}
	if len(got.GetSubDeny()) != 1 || got.GetSubDeny()[0] != "secret.>" {
		t.Errorf("sub_deny = %v", got.GetSubDeny())
	}
	if got.IssuerAccount == nil || got.GetIssuerAccount() != "AISSUER" {
		t.Errorf("issuer_account = %v, want AISSUER", got.IssuerAccount)
	}
}

func TestMintNatsUserOmitsEmptyIssuerAccount(t *testing.T) {
	f := &fakeMinting{credResp: &pb.CredentialResponse{Token: "ucreds"}}
	c := dialMinting(t, f)

	if _, err := c.MintNatsUser(context.Background(), basil.NatsUserRequest{
		KeyID:           "nats.account",
		SubjectUserNKey: "UABC",
		Name:            "alice",
	}); err != nil {
		t.Fatalf("mint nats user: %v", err)
	}
	f.mu.Lock()
	got := f.lastUser
	f.mu.Unlock()
	if got.IssuerAccount != nil {
		t.Errorf("issuer_account = %v, want nil (omitted)", got.GetIssuerAccount())
	}
}

func TestSignNatsJwtBuildsRequestWithTimestamps(t *testing.T) {
	f := &fakeMinting{credResp: &pb.CredentialResponse{Token: "njwt"}}
	c := dialMinting(t, f)

	iat := time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)
	if _, err := c.SignNatsJwt(context.Background(), basil.NatsJwtRequest{
		KeyID:        "nats.account",
		Claims:       map[string]any{"sub": "UABC", "name": "alice", "nats": map[string]any{"type": "user"}},
		ExpectedType: basil.NatsJwtTypeUser,
		TTL:          30 * time.Minute,
		IssuedAt:     iat,
		JtiMode:      basil.NatsJtiModeRewrite,
	}); err != nil {
		t.Fatalf("sign nats jwt: %v", err)
	}
	f.mu.Lock()
	got := f.lastSign
	f.mu.Unlock()
	if got.GetKeyId() != "nats.account" {
		t.Errorf("key_id = %q", got.GetKeyId())
	}
	if got.GetExpectedType() != pb.NatsJwtType_NATS_JWT_TYPE_USER {
		t.Errorf("expected_type = %v, want USER", got.GetExpectedType())
	}
	if got.GetJtiMode() != pb.NatsJtiMode_NATS_JTI_MODE_REWRITE {
		t.Errorf("jti_mode = %v, want REWRITE", got.GetJtiMode())
	}
	if got.GetTtl().AsDuration() != 30*time.Minute {
		t.Errorf("ttl = %v, want 30m", got.GetTtl().AsDuration())
	}
	if !got.GetIssuedAt().AsTime().Equal(iat) {
		t.Errorf("issued_at = %v, want %v", got.GetIssuedAt().AsTime(), iat)
	}
	if got.ExpiresAt != nil {
		t.Errorf("expires_at = %v, want nil (omitted)", got.ExpiresAt)
	}
	var claims map[string]any
	if err := json.Unmarshal(got.GetClaimsJson(), &claims); err != nil {
		t.Fatalf("claims_json is not JSON: %v", err)
	}
	if claims["sub"] != "UABC" {
		t.Errorf("claims.sub = %v", claims["sub"])
	}
}

func TestSignNatsJwtPreservesRawIntegerClaims(t *testing.T) {
	const raw = `{"sub":"UABC","iat":9007199254740993,"nats":{"type":"user","version":2}}`
	tests := []struct {
		name   string
		claims any
	}{
		{name: "raw message", claims: json.RawMessage(raw)},
		{name: "bytes", claims: []byte(raw)},
		{name: "string", claims: raw},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeMinting{credResp: &pb.CredentialResponse{Token: "njwt"}}
			c := dialMinting(t, f)

			if _, err := c.SignNatsJwt(context.Background(), basil.NatsJwtRequest{
				KeyID:        "nats.account",
				Claims:       tt.claims,
				ExpectedType: basil.NatsJwtTypeUser,
			}); err != nil {
				t.Fatalf("sign nats jwt: %v", err)
			}
			f.mu.Lock()
			got := f.lastSign
			f.mu.Unlock()
			if string(got.GetClaimsJson()) != raw {
				t.Errorf("claims_json = %s, want %s", got.GetClaimsJson(), raw)
			}
		})
	}
}

func TestValidateNatsJwtBuildsRequestAndMapsValidResponse(t *testing.T) {
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	iat := time.Date(2026, 6, 26, 1, 2, 3, 0, time.UTC)
	f := &fakeMinting{validateResp: &pb.ValidateNatsJwtResponse{
		Valid:              true,
		Reason:             pb.NatsJwtValidationReason_NATS_JWT_VALIDATION_REASON_VALID,
		Subject:            "UABC",
		Issuer:             "AISSUER",
		MatchedSignerKeyId: "nats.account",
		JwtType:            pb.NatsJwtType_NATS_JWT_TYPE_USER,
		ExpiresAtUnix:      uint64(exp.Unix()),
		IssuedAtUnix:       uint64(iat.Unix()),
	}}
	c := dialMinting(t, f)

	got, err := c.Nats().ValidateNatsJwt(context.Background(), basil.ValidateNatsJwtRequest{
		JWT: "header.payload.sig",
		AllowedSigners: []basil.AllowedSigner{
			basil.AllowedSignerKeyID("nats.account"),
			basil.AllowedSignerNatsPublicKey("AISSUER"),
		},
		ExpectedType: basil.NatsJwtTypeUser,
	})
	if err != nil {
		t.Fatalf("validate nats jwt: %v", err)
	}
	if !got.Valid || got.Reason != basil.NatsJwtValidationReasonValid ||
		got.Subject != "UABC" || got.Issuer != "AISSUER" ||
		got.MatchedSignerKeyID != "nats.account" || got.JWTType != basil.NatsJwtTypeUser {
		t.Errorf("unexpected validation: %+v", got)
	}
	if !got.ExpiresAt.Equal(exp) || !got.IssuedAt.Equal(iat) {
		t.Errorf("times = exp %v iat %v, want exp %v iat %v", got.ExpiresAt, got.IssuedAt, exp, iat)
	}

	f.mu.Lock()
	req := f.lastVal
	f.mu.Unlock()
	if req.GetJwt() != "header.payload.sig" {
		t.Errorf("jwt = %q", req.GetJwt())
	}
	if req.GetExpectedType() != pb.NatsJwtType_NATS_JWT_TYPE_USER {
		t.Errorf("expected_type = %v, want USER", req.GetExpectedType())
	}
	signers := req.GetAllowedSigners()
	if len(signers) != 2 {
		t.Fatalf("allowed_signers = %d, want 2", len(signers))
	}
	if signers[0].GetKeyId() != "nats.account" {
		t.Errorf("signer[0].key_id = %q", signers[0].GetKeyId())
	}
	if signers[1].GetNatsPublicKey() != "AISSUER" {
		t.Errorf("signer[1].nats_public_key = %q", signers[1].GetNatsPublicKey())
	}
}

func TestValidateNatsJwtRejectsEmptyAllowedSigner(t *testing.T) {
	f := &fakeMinting{validateResp: &pb.ValidateNatsJwtResponse{Valid: true}}
	c := dialMinting(t, f)

	_, err := c.Nats().ValidateNatsJwt(context.Background(), basil.ValidateNatsJwtRequest{
		JWT:            "header.payload.sig",
		AllowedSigners: []basil.AllowedSigner{{}},
	})
	if err == nil {
		t.Fatal("ValidateNatsJwt succeeded with an empty AllowedSigner")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastVal != nil {
		t.Fatal("ValidateNatsJwt sent RPC despite invalid local AllowedSigner")
	}
}

func TestValidateNatsJwtAuthoritativeRejectIsNotError(t *testing.T) {
	f := &fakeMinting{validateResp: &pb.ValidateNatsJwtResponse{
		Valid:   false,
		Reason:  pb.NatsJwtValidationReason_NATS_JWT_VALIDATION_REASON_UNKNOWN_SIGNER,
		Subject: "UABC",
		Issuer:  "AOTHER",
		JwtType: pb.NatsJwtType_NATS_JWT_TYPE_USER,
	}}
	c := dialMinting(t, f)

	got, err := c.ValidateNatsJwt(context.Background(), basil.ValidateNatsJwtRequest{
		JWT:            "header.payload.sig",
		AllowedSigners: []basil.AllowedSigner{basil.AllowedSignerKeyID("nats.account")},
		ExpectedType:   basil.NatsJwtTypeUser,
	})
	if err != nil {
		t.Fatalf("validate nats jwt reject: %v", err)
	}
	if got.Valid {
		t.Fatal("valid = true, want false")
	}
	if got.Reason != basil.NatsJwtValidationReasonUnknownSigner {
		t.Errorf("reason = %v, want unknown signer", got.Reason)
	}
	if got.Subject != "UABC" || got.Issuer != "AOTHER" || got.MatchedSignerKeyID != "" {
		t.Errorf("unexpected reject details: %+v", got)
	}
}

func TestNatsCurveEncryptDecryptBuildRequests(t *testing.T) {
	f := &fakeMinting{
		encResp: &pb.EncryptNatsCurveResponse{Ciphertext: []byte("boxed")},
		decResp: &pb.DecryptNatsCurveResponse{Plaintext: []byte("plain")},
	}
	c := dialMinting(t, f)

	ciphertext, err := c.EncryptNatsCurve(context.Background(), basil.NatsCurveEncryptRequest{
		KeyID:               "nats.xkey.sender",
		RecipientPublicXKey: "XRECIPIENT",
		Plaintext:           []byte("plain"),
	})
	if err != nil {
		t.Fatalf("encrypt nats curve: %v", err)
	}
	if string(ciphertext) != "boxed" {
		t.Errorf("ciphertext = %q, want boxed", ciphertext)
	}
	plaintext, err := c.DecryptNatsCurve(context.Background(), basil.NatsCurveDecryptRequest{
		KeyID:            "nats.xkey.receiver",
		SenderPublicXKey: "XSENDER",
		Ciphertext:       ciphertext,
	})
	if err != nil {
		t.Fatalf("decrypt nats curve: %v", err)
	}
	if string(plaintext) != "plain" {
		t.Errorf("plaintext = %q, want plain", plaintext)
	}

	f.mu.Lock()
	enc := f.lastEnc
	dec := f.lastDec
	f.mu.Unlock()
	if enc.GetKeyId() != "nats.xkey.sender" || enc.GetRecipientPublicXkey() != "XRECIPIENT" ||
		string(enc.GetPlaintext()) != "plain" {
		t.Errorf("unexpected encrypt request: %+v", enc)
	}
	if dec.GetKeyId() != "nats.xkey.receiver" || dec.GetSenderPublicXkey() != "XSENDER" ||
		string(dec.GetCiphertext()) != "boxed" {
		t.Errorf("unexpected decrypt request: %+v", dec)
	}
}

func TestIssueCertificateBuildsRequestAndMapsResponse(t *testing.T) {
	f := &fakeMinting{certResp: &pb.IssueCertificateResponse{
		CertChainDer:  [][]byte{[]byte("leaf"), []byte("issuer")},
		PrivateKeyDer: []byte("pkcs8"),
		CaChainDer:    [][]byte{[]byte("root")},
	}}
	c := dialMinting(t, f)

	cert, err := c.IssueCertificate(context.Background(), basil.CertificateRequest{
		IssuerKeyID: "web.tls.cert_issuer",
		CommonName:  "svc.example.org",
		DNSSANs:     []string{"svc.example.org"},
		IPSANs:      []string{"10.0.0.1"},
		TTL:         24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	if len(cert.CertChainDER) != 2 || string(cert.CertChainDER[0]) != "leaf" ||
		string(cert.PrivateKeyDER) != "pkcs8" || len(cert.CAChainDER) != 1 {
		t.Errorf("unexpected certificate: %+v", cert)
	}

	f.mu.Lock()
	got := f.lastCert
	f.mu.Unlock()
	if got.GetIssuerKeyId() != "web.tls.cert_issuer" || got.GetCommonName() != "svc.example.org" {
		t.Errorf("unexpected cert request: %+v", got)
	}
	if len(got.GetDnsSans()) != 1 || got.GetDnsSans()[0] != "svc.example.org" {
		t.Errorf("dns_sans = %v", got.GetDnsSans())
	}
	if len(got.GetIpSans()) != 1 || got.GetIpSans()[0] != "10.0.0.1" {
		t.Errorf("ip_sans = %v", got.GetIpSans())
	}
	if got.GetTtl().AsDuration() != 24*time.Hour {
		t.Errorf("ttl = %v, want 24h", got.GetTtl().AsDuration())
	}
}

func TestMintMapsStatusError(t *testing.T) {
	st := status.New(codes.PermissionDenied, "policy denied the mint")
	st, err := st.WithDetails(&pb.BrokerErrorInfo{Reason: "UNAUTHORIZED", Op: "mint_nats_user"})
	if err != nil {
		t.Fatalf("attach detail: %v", err)
	}
	c := dialMinting(t, &fakeMinting{err: st.Err()})

	_, gotErr := c.MintNatsUser(context.Background(), basil.NatsUserRequest{KeyID: "k"})
	se, ok := basil.AsStatusError(gotErr)
	if !ok {
		t.Fatalf("error is not a *StatusError: %v", gotErr)
	}
	if se.Code != codes.PermissionDenied || se.Reason != "UNAUTHORIZED" || se.Op != "mint_nats_user" {
		t.Errorf("unexpected status error: %+v", se)
	}
}

func TestValidateNatsJwtMapsStatusError(t *testing.T) {
	st := status.New(codes.PermissionDenied, "policy denied validation")
	st, err := st.WithDetails(&pb.BrokerErrorInfo{Reason: "UNAUTHORIZED", Op: "validate_nats_jwt"})
	if err != nil {
		t.Fatalf("attach detail: %v", err)
	}
	c := dialMinting(t, &fakeMinting{err: st.Err()})

	_, gotErr := c.Nats().ValidateNatsJwt(context.Background(), basil.ValidateNatsJwtRequest{
		JWT:            "header.payload.sig",
		AllowedSigners: []basil.AllowedSigner{basil.AllowedSignerKeyID("nats.account")},
	})
	se, ok := basil.AsStatusError(gotErr)
	if !ok {
		t.Fatalf("error is not a *StatusError: %v", gotErr)
	}
	if se.Code != codes.PermissionDenied || se.Reason != "UNAUTHORIZED" || se.Op != "validate_nats_jwt" {
		t.Errorf("unexpected status error: %+v", se)
	}
}

func TestMintJwtPreservesRawIntegerClaims(t *testing.T) {
	f := &fakeMinting{credResp: &pb.CredentialResponse{Token: "t"}}
	c := dialMinting(t, f)

	raw := json.RawMessage(`{"big":9007199254740993}`)
	if _, err := c.MintJwt(context.Background(), basil.JwtRequest{KeyID: "k", Claims: raw}); err != nil {
		t.Fatalf("MintJwt rejected raw integer claims: %v", err)
	}
	f.mu.Lock()
	got := f.lastJwt
	f.mu.Unlock()
	if string(got.GetExtraClaimsJson()) != string(raw) {
		t.Errorf("extra_claims_json = %s, want %s", got.GetExtraClaimsJson(), raw)
	}
}
