package basil_test

import (
	"context"
	"sync"
	"testing"

	"github.com/openbasil/basil-go/basil"
	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/grpc"
)

type fakeSecret struct {
	pb.UnimplementedSecretServiceServer

	mu         sync.Mutex
	lastGet    *pb.GetSecretRequest
	lastSet    *pb.SetSecretRequest
	lastRotate *pb.RotateSecretRequest
	lastList   *pb.ListCatalogRequest

	getResp    *pb.GetSecretResponse
	setResp    *pb.SetSecretResponse
	rotateResp *pb.RotateSecretResponse
	listResp   []*pb.CatalogEntry
	err        error
}

func (f *fakeSecret) GetSecret(_ context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	f.mu.Lock()
	f.lastGet = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.getResp, nil
}

func (f *fakeSecret) SetSecret(_ context.Context, req *pb.SetSecretRequest) (*pb.SetSecretResponse, error) {
	f.mu.Lock()
	f.lastSet = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.setResp, nil
}

func (f *fakeSecret) RotateSecret(_ context.Context, req *pb.RotateSecretRequest) (*pb.RotateSecretResponse, error) {
	f.mu.Lock()
	f.lastRotate = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.rotateResp, nil
}

func (f *fakeSecret) ListCatalog(req *pb.ListCatalogRequest, stream grpc.ServerStreamingServer[pb.CatalogEntry]) error {
	f.mu.Lock()
	f.lastList = req
	f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	for _, e := range f.listResp {
		if err := stream.Send(e); err != nil {
			return err
		}
	}
	return nil
}

func dialSecret(t *testing.T, f *fakeSecret) *basil.Client {
	return serveAndDial(t, func(srv *grpc.Server) { pb.RegisterSecretServiceServer(srv, f) })
}

func TestGetSecretMapsResponseAndExplicitVersion(t *testing.T) {
	f := &fakeSecret{getResp: &pb.GetSecretResponse{Value: []byte("hunter2"), Version: 5}}
	c := dialSecret(t, f)

	ver := uint32(5)
	s, err := c.GetSecret(context.Background(), "app.db_password", &ver)
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(s.Value) != "hunter2" || s.Version != 5 {
		t.Errorf("unexpected secret: %+v", s)
	}

	f.mu.Lock()
	got := f.lastGet
	f.mu.Unlock()
	if got.GetSecretId() != "app.db_password" {
		t.Errorf("secret_id = %q, want app.db_password", got.GetSecretId())
	}
	if got.Version == nil || got.GetVersion() != 5 {
		t.Errorf("version = %v, want explicit 5", got.Version)
	}
}

func TestGetSecretNilVersionOmitsField(t *testing.T) {
	f := &fakeSecret{getResp: &pb.GetSecretResponse{Value: []byte("v")}}
	c := dialSecret(t, f)

	if _, err := c.GetSecret(context.Background(), "k", nil); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	f.mu.Lock()
	got := f.lastGet
	f.mu.Unlock()
	if got.Version != nil {
		t.Errorf("version = %v, want nil (omitted)", *got.Version)
	}
}

func TestSetSecretReturnsVersionAndBuildsRequest(t *testing.T) {
	f := &fakeSecret{setResp: &pb.SetSecretResponse{Version: 8}}
	c := dialSecret(t, f)

	ver, err := c.SetSecret(context.Background(), "app.db_password", []byte("new"))
	if err != nil {
		t.Fatalf("set secret: %v", err)
	}
	if ver != 8 {
		t.Errorf("version = %d, want 8", ver)
	}
	f.mu.Lock()
	got := f.lastSet
	f.mu.Unlock()
	if got.GetSecretId() != "app.db_password" || string(got.GetValue()) != "new" {
		t.Errorf("unexpected set request: %+v", got)
	}
}

func TestRotateSecretReturnsVersion(t *testing.T) {
	f := &fakeSecret{rotateResp: &pb.RotateSecretResponse{Version: 9}}
	c := dialSecret(t, f)

	ver, err := c.RotateSecret(context.Background(), "app.db_password")
	if err != nil {
		t.Fatalf("rotate secret: %v", err)
	}
	if ver != 9 {
		t.Errorf("version = %d, want 9", ver)
	}
	f.mu.Lock()
	got := f.lastRotate
	f.mu.Unlock()
	if got.GetSecretId() != "app.db_password" {
		t.Errorf("secret_id = %q, want app.db_password", got.GetSecretId())
	}
}

func TestListCatalogCollectsStreamAndMapsEntries(t *testing.T) {
	kt := pb.KeyType_KEY_TYPE_ED25519
	f := &fakeSecret{listResp: []*pb.CatalogEntry{
		{Name: "web.tls.signing_key", Kind: pb.CatalogKind_CATALOG_KIND_SIGNING, KeyType: &kt, LatestVersion: 2},
		{Name: "app.db_password", Kind: pb.CatalogKind_CATALOG_KIND_VALUE, LatestVersion: 1},
	}}
	c := dialSecret(t, f)

	entries, err := c.ListCatalog(context.Background(), nil)
	if err != nil {
		t.Fatalf("list catalog: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Name != "web.tls.signing_key" || entries[0].Kind != basil.CatalogKindSigning ||
		entries[0].KeyType == nil || *entries[0].KeyType != basil.KeyTypeEd25519 || entries[0].LatestVersion != 2 {
		t.Errorf("unexpected entry[0]: %+v", entries[0])
	}
	if entries[1].Name != "app.db_password" || entries[1].Kind != basil.CatalogKindValue ||
		entries[1].KeyType != nil {
		t.Errorf("unexpected entry[1]: %+v", entries[1])
	}
}

func TestListCatalogPassesPrefix(t *testing.T) {
	f := &fakeSecret{}
	c := dialSecret(t, f)

	prefix := "app."
	if _, err := c.ListCatalog(context.Background(), &prefix); err != nil {
		t.Fatalf("list catalog: %v", err)
	}
	f.mu.Lock()
	got := f.lastList
	f.mu.Unlock()
	if got.Prefix == nil || got.GetPrefix() != "app." {
		t.Errorf("prefix = %v, want explicit app.", got.Prefix)
	}
}
