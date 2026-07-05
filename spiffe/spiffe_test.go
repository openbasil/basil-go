package spiffe_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/openbasil/basil-go/basil"
	"github.com/openbasil/basil-go/internal/pb"
	"github.com/openbasil/basil-go/spiffe"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	testTD       = "example.org"
	testSpiffeID = "spiffe://example.org/workload"
	testAudience = "spiffe://example.org/db"
	headerKey    = "workload.spiffe.io"
)

// fixture holds pre-generated SVID material served by the fake Workload API.
type fixture struct {
	chainDER  []byte // leaf certificate DER (chain, leaf first)
	keyDER    []byte // PKCS#8 leaf private key DER
	bundleDER []byte // trust-domain X.509 bundle DER (the CA certificate)
	jwksBytes []byte // trust-domain JWT bundle as a JWKS document
	jwtToken  string // a signed ES256 JWT-SVID for testAudience
	notAfter  time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	uri, err := url.Parse(testSpiffeID)
	if err != nil {
		t.Fatalf("parse spiffe uri: %v", err)
	}
	notAfter := time.Now().Add(time.Hour).Truncate(time.Second)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	// JWT-SVID signed with ES256. The Workload API client validates claims
	// (sub/aud/exp) but not the signature when fetching, so any signer works.
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: leafKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-kid"),
	)
	if err != nil {
		t.Fatalf("jose signer: %v", err)
	}
	token, err := jwt.Signed(sig).Claims(jwt.Claims{
		Subject:  testSpiffeID,
		Audience: jwt.Audience{testAudience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}).Serialize()
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	// JWT trust bundle (JWKS) advertising the signing public key.
	td := spiffeid.RequireTrustDomainFromString(testTD)
	jb := jwtbundle.New(td)
	if err := jb.AddJWTAuthority("test-kid", leafKey.Public()); err != nil {
		t.Fatalf("add jwt authority: %v", err)
	}
	jwks, err := jb.Marshal()
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	return fixture{
		chainDER:  leafDER,
		keyDER:    keyDER,
		bundleDER: caDER,
		jwksBytes: jwks,
		jwtToken:  token,
		notAfter:  notAfter,
	}
}

// fakeWorkloadAPI is an in-process SPIFFE Workload API server. It fails closed
// when the mandatory workload.spiffe.io header is absent, exactly as the broker
// does, so a successful call proves the client injected the header.
type fakeWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	fx fixture

	mu            sync.Mutex
	lastHeader    []string
	lastAudiences []string

	// jwtErr, when set, is returned by FetchJWTSVID instead of a response.
	jwtErr error
}

func (f *fakeWorkloadAPI) checkHeader(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	vals := md.Get(headerKey)
	f.mu.Lock()
	f.lastHeader = vals
	f.mu.Unlock()
	if len(vals) == 0 || vals[0] != "true" {
		return status.Error(codes.InvalidArgument, "missing workload.spiffe.io header")
	}
	return nil
}

func (f *fakeWorkloadAPI) FetchX509SVID(_ *workload.X509SVIDRequest, stream grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	if err := f.checkHeader(stream.Context()); err != nil {
		return err
	}
	return stream.Send(&workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{{
			SpiffeId:    testSpiffeID,
			X509Svid:    f.fx.chainDER,
			X509SvidKey: f.fx.keyDER,
			Bundle:      f.fx.bundleDER,
		}},
	})
}

func (f *fakeWorkloadAPI) FetchX509Bundles(_ *workload.X509BundlesRequest, stream grpc.ServerStreamingServer[workload.X509BundlesResponse]) error {
	if err := f.checkHeader(stream.Context()); err != nil {
		return err
	}
	return stream.Send(&workload.X509BundlesResponse{
		Bundles: map[string][]byte{testTD: f.fx.bundleDER},
	})
}

func (f *fakeWorkloadAPI) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	if err := f.checkHeader(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.lastAudiences = req.GetAudience()
	f.mu.Unlock()
	if f.jwtErr != nil {
		return nil, f.jwtErr
	}
	return &workload.JWTSVIDResponse{
		Svids: []*workload.JWTSVID{{SpiffeId: testSpiffeID, Svid: f.fx.jwtToken}},
	}, nil
}

func (f *fakeWorkloadAPI) FetchJWTBundles(_ *workload.JWTBundlesRequest, stream grpc.ServerStreamingServer[workload.JWTBundlesResponse]) error {
	if err := f.checkHeader(stream.Context()); err != nil {
		return err
	}
	return stream.Send(&workload.JWTBundlesResponse{
		Bundles: map[string][]byte{testTD: f.fx.jwksBytes},
	})
}

func (f *fakeWorkloadAPI) ValidateJWTSVID(ctx context.Context, _ *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	if err := f.checkHeader(ctx); err != nil {
		return nil, err
	}
	// The client re-parses the token itself; only a non-error response matters.
	return &workload.ValidateJWTSVIDResponse{SpiffeId: testSpiffeID}, nil
}

// serveAndDial starts the fake Workload API over a fresh Unix socket and
// returns a SPIFFE client dialed at it. Both are torn down via t.Cleanup.
func serveAndDial(t *testing.T, fake *fakeWorkloadAPI) *spiffe.Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "wl.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %q: %v", sock, err)
	}
	srv := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	c, err := spiffe.Dial(context.Background(), sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestFetchX509SVID(t *testing.T) {
	fx := newFixture(t)
	fake := &fakeWorkloadAPI{fx: fx}
	c := serveAndDial(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	svid, err := c.FetchX509SVID(ctx)
	if err != nil {
		t.Fatalf("FetchX509SVID: %v", err)
	}
	if got := svid.ID.String(); got != testSpiffeID {
		t.Errorf("spiffe id = %q, want %q", got, testSpiffeID)
	}
	if len(svid.Certificates) != 1 {
		t.Errorf("cert chain len = %d, want 1", len(svid.Certificates))
	}
	if svid.PrivateKey == nil {
		t.Error("private key is nil; the workload's own SVID key must be returned")
	}
	if exp := svid.Certificates[0].NotAfter; !exp.Equal(fx.notAfter) {
		t.Errorf("expiry = %v, want %v", exp, fx.notAfter)
	}

	// A successful call means the mandatory header was injected by the client.
	fake.mu.Lock()
	hdr := fake.lastHeader
	fake.mu.Unlock()
	if len(hdr) != 1 || hdr[0] != "true" {
		t.Errorf("workload.spiffe.io header = %v, want [true]", hdr)
	}
}

func TestFetchX509Bundles(t *testing.T) {
	fake := &fakeWorkloadAPI{fx: newFixture(t)}
	c := serveAndDial(t, fake)

	set, err := c.FetchX509Bundles(context.Background())
	if err != nil {
		t.Fatalf("FetchX509Bundles: %v", err)
	}
	td := spiffeid.RequireTrustDomainFromString(testTD)
	b, err := set.GetX509BundleForTrustDomain(td)
	if err != nil {
		t.Fatalf("bundle for %s: %v", td, err)
	}
	if len(b.X509Authorities()) != 1 {
		t.Errorf("x509 authorities = %d, want 1", len(b.X509Authorities()))
	}
}

func TestFetchJWTSVID(t *testing.T) {
	fake := &fakeWorkloadAPI{fx: newFixture(t)}
	c := serveAndDial(t, fake)

	svid, err := c.FetchJWTSVID(context.Background(), testAudience)
	if err != nil {
		t.Fatalf("FetchJWTSVID: %v", err)
	}
	if got := svid.ID.String(); got != testSpiffeID {
		t.Errorf("spiffe id = %q, want %q", got, testSpiffeID)
	}
	if svid.Marshal() == "" {
		t.Error("marshaled token is empty")
	}
	found := false
	for _, a := range svid.Audience {
		if a == testAudience {
			found = true
		}
	}
	if !found {
		t.Errorf("audience %v missing %q", svid.Audience, testAudience)
	}
	if svid.Expiry.IsZero() {
		t.Error("expiry is zero")
	}

	fake.mu.Lock()
	auds := fake.lastAudiences
	fake.mu.Unlock()
	if len(auds) == 0 || auds[0] != testAudience {
		t.Errorf("server saw audiences %v, want first %q", auds, testAudience)
	}
}

func TestFetchJWTBundles(t *testing.T) {
	fake := &fakeWorkloadAPI{fx: newFixture(t)}
	c := serveAndDial(t, fake)

	set, err := c.FetchJWTBundles(context.Background())
	if err != nil {
		t.Fatalf("FetchJWTBundles: %v", err)
	}
	td := spiffeid.RequireTrustDomainFromString(testTD)
	b, err := set.GetJWTBundleForTrustDomain(td)
	if err != nil {
		t.Fatalf("jwt bundle for %s: %v", td, err)
	}
	if _, ok := b.FindJWTAuthority("test-kid"); !ok {
		t.Error("jwt bundle missing authority test-kid")
	}
}

func TestValidateJWTSVID(t *testing.T) {
	fx := newFixture(t)
	fake := &fakeWorkloadAPI{fx: fx}
	c := serveAndDial(t, fake)

	svid, err := c.ValidateJWTSVID(context.Background(), fx.jwtToken, testAudience)
	if err != nil {
		t.Fatalf("ValidateJWTSVID: %v", err)
	}
	if got := svid.ID.String(); got != testSpiffeID {
		t.Errorf("spiffe id = %q, want %q", got, testSpiffeID)
	}
}

// TestErrorMappingStatusError proves a broker denial reaches the caller as a
// typed *basil.StatusError with the BrokerErrorInfo detail decoded, even though
// the error travels back through the go-spiffe client.
func TestErrorMappingStatusError(t *testing.T) {
	st := status.New(codes.PermissionDenied, "policy denied fetch")
	st, err := st.WithDetails(&pb.BrokerErrorInfo{Reason: "UNAUTHORIZED", Op: "fetch_jwtsvid"})
	if err != nil {
		t.Fatalf("attach detail: %v", err)
	}
	fake := &fakeWorkloadAPI{fx: newFixture(t), jwtErr: st.Err()}
	c := serveAndDial(t, fake)

	_, gotErr := c.FetchJWTSVID(context.Background(), testAudience)
	if gotErr == nil {
		t.Fatal("expected an error")
	}
	var se *basil.StatusError
	if !errors.As(gotErr, &se) {
		t.Fatalf("error %v is not a *basil.StatusError", gotErr)
	}
	if se.Code != codes.PermissionDenied {
		t.Errorf("code = %s, want PermissionDenied", se.Code)
	}
	if se.Reason != "UNAUTHORIZED" {
		t.Errorf("reason = %q, want UNAUTHORIZED", se.Reason)
	}
	if se.Op != "fetch_jwtsvid" {
		t.Errorf("op = %q, want fetch_jwtsvid", se.Op)
	}
}

func TestMissingHeaderFailsClosed(t *testing.T) {
	// Sanity check the fake's guard itself: a raw client with no header is
	// rejected, which is what makes the other tests' success meaningful.
	fake := &fakeWorkloadAPI{fx: newFixture(t)}
	sock := filepath.Join(t.TempDir(), "wl.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///"+sock,
		grpc.WithAuthority("localhost"),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial raw: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	raw := workload.NewSpiffeWorkloadAPIClient(conn)
	// No workload.spiffe.io header on the outgoing context.
	_, err = raw.FetchJWTSVID(context.Background(), &workload.JWTSVIDRequest{Audience: []string{testAudience}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing-header call: code = %s, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

func TestSocketAddr(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/run/basil/agent.sock", "unix:///run/basil/agent.sock"},
		{"unix:///run/basil/agent.sock", "unix:///run/basil/agent.sock"},
		{"tcp://127.0.0.1:8080", "tcp://127.0.0.1:8080"},
	}
	for _, tc := range cases {
		if got := spiffe.SocketAddrForTest(tc.in); got != tc.want {
			t.Errorf("socketAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDialEmptyPath(t *testing.T) {
	if _, err := spiffe.Dial(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty socket path")
	}
}
