package basil_test

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/openbasil/basil-go/basil"
	"google.golang.org/grpc"
)

// serveAndDial starts an in-process gRPC server over a fresh Unix socket, lets
// register install one or more fake services on it, and returns a Client dialed
// at that socket. Both the server and the client are torn down via t.Cleanup.
// It drives the data-plane surfaces (AEAD, secrets, minting, admin) without a
// live broker.
func serveAndDial(t *testing.T, register func(srv *grpc.Server)) *basil.Client {
	t.Helper()
	// A short socket path keeps us well under the AF_UNIX 108-byte limit.
	sock := filepath.Join(t.TempDir(), "b.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix %q: %v", sock, err)
	}
	srv := grpc.NewServer()
	register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	c, err := basil.Dial(sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
