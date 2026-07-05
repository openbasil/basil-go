package basil_test

import (
	"context"
	"testing"
	"time"

	"github.com/openbasil/basil-go/basil"
	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDialRejectsEmptyPath(t *testing.T) {
	if _, err := basil.Dial(""); err == nil {
		t.Fatal("Dial(\"\") = nil error, want error")
	}
}

func TestCloseReturnsNil(t *testing.T) {
	c := dialFake(t, &fakeSigning{signResp: &pb.SignResponse{}})
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestDefaultTimeoutAppliesWithoutDeadline proves the client supplies its own
// deadline when the caller's context has none: a slow broker is cut off and
// the RPC fails with DeadlineExceeded.
func TestDefaultTimeoutAppliesWithoutDeadline(t *testing.T) {
	f := &fakeSigning{signResp: &pb.SignResponse{Signature: []byte{1}}, delay: time.Second}
	c, err := basil.Dial(startFakeServer(t, f), basil.WithTimeout(30*time.Millisecond))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	_, err = c.Sign(context.Background(), "k", []byte("m"))
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("err = %v (code %v), want DeadlineExceeded", err, status.Code(err))
	}
}

// TestExplicitTimeoutDoesNotBlockFastCall ensures a configured default does not
// interfere with a call that completes within it.
func TestExplicitTimeoutDoesNotBlockFastCall(t *testing.T) {
	f := &fakeSigning{signResp: &pb.SignResponse{Signature: []byte("ok")}}
	c, err := basil.Dial(startFakeServer(t, f), basil.WithTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	sig, err := c.Sign(context.Background(), "k", []byte("m"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if string(sig) != "ok" {
		t.Errorf("signature = %q, want ok", sig)
	}
}
