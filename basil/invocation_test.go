package basil_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/openbasil/basil-go/basil"
	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/grpc"
)

// fakeInvocation serves InvocationService with a canned challenge response.
type fakeInvocation struct {
	pb.UnimplementedInvocationServiceServer
	lastRequest          *pb.GetInvocationChallengeRequest
	response             *pb.GetInvocationChallengeResponse
	capabilitiesResponse *pb.GetInvocationCapabilitiesResponse
}

func (f *fakeInvocation) GetInvocationChallenge(_ context.Context, req *pb.GetInvocationChallengeRequest) (*pb.GetInvocationChallengeResponse, error) {
	f.lastRequest = req
	return f.response, nil
}

func (f *fakeInvocation) GetInvocationCapabilities(_ context.Context, _ *pb.GetInvocationCapabilitiesRequest) (*pb.GetInvocationCapabilitiesResponse, error) {
	return f.capabilitiesResponse, nil
}

func challengeBytes() []byte {
	out := make([]byte, basil.InvocationChallengeLen)
	for i := range out {
		out[i] = 0x22
	}
	// Distinct 16-byte instance-ID prefix.
	for i := range 16 {
		out[i] = 0x11
	}
	return out
}

func TestGetInvocationChallengeRoundTrips(t *testing.T) {
	fake := &fakeInvocation{
		response: &pb.GetInvocationChallengeResponse{
			Challenge:     challengeBytes(),
			Generation:    3,
			ExpiresAtUnix: 1_800_000_060,
		},
	}
	c := serveAndDial(t, func(srv *grpc.Server) {
		pb.RegisterInvocationServiceServer(srv, fake)
	})

	jkt := bytes.Repeat([]byte{0x5a}, basil.InvocationChallengeLen)
	issued, err := c.GetInvocationChallenge(context.Background(), jkt, "")
	if err != nil {
		t.Fatalf("GetInvocationChallenge: %v", err)
	}
	if !bytes.Equal(issued.Challenge[:], challengeBytes()) {
		t.Fatalf("challenge = %x", issued.Challenge)
	}
	if issued.Generation != 3 || issued.ExpiresAtUnix != 1_800_000_060 {
		t.Fatalf("generation/expiry = %d/%d", issued.Generation, issued.ExpiresAtUnix)
	}
	if !bytes.Equal(fake.lastRequest.GetJkt(), jkt) {
		t.Fatalf("wire jkt = %x", fake.lastRequest.GetJkt())
	}
	// A direct local caller sends no courier-observed source.
	if fake.lastRequest.CourierObservedSource != nil {
		t.Fatalf("courier source = %q, want absent", fake.lastRequest.GetCourierObservedSource())
	}

	// The courier form carries the source verbatim.
	if _, err := c.GetInvocationChallenge(context.Background(), jkt, "203.0.113.7"); err != nil {
		t.Fatalf("GetInvocationChallenge with source: %v", err)
	}
	if fake.lastRequest.GetCourierObservedSource() != "203.0.113.7" {
		t.Fatalf("courier source = %q", fake.lastRequest.GetCourierObservedSource())
	}
}

func TestGetInvocationChallengeRejectsMalformedInputs(t *testing.T) {
	fake := &fakeInvocation{
		response: &pb.GetInvocationChallengeResponse{
			Challenge:     []byte{0x01, 0x02},
			Generation:    1,
			ExpiresAtUnix: 1,
		},
	}
	c := serveAndDial(t, func(srv *grpc.Server) {
		pb.RegisterInvocationServiceServer(srv, fake)
	})

	// A short self-asserted thumbprint never reaches the wire.
	if _, err := c.GetInvocationChallenge(context.Background(), []byte{0x5a}, ""); err == nil {
		t.Fatal("short jkt accepted")
	}
	if fake.lastRequest != nil {
		t.Fatalf("short jkt reached the broker: %v", fake.lastRequest)
	}

	// A broker reply violating the 32-byte challenge contract is rejected.
	jkt := bytes.Repeat([]byte{0x5a}, basil.InvocationChallengeLen)
	if _, err := c.GetInvocationChallenge(context.Background(), jkt, ""); err == nil {
		t.Fatal("2-byte challenge accepted")
	}
}

func TestGetInvocationCapabilitiesRoundTripsClosedProfile(t *testing.T) {
	fake := &fakeInvocation{
		capabilitiesResponse: &pb.GetInvocationCapabilitiesResponse{
			ListenerProfile:        pb.ListenerProfile_COURIER,
			RequireChallenge:       true,
			CourierProtocolVersion: 1,
		},
	}
	c := serveAndDial(t, func(srv *grpc.Server) {
		pb.RegisterInvocationServiceServer(srv, fake)
	})

	got, err := c.GetInvocationCapabilities(context.Background())
	if err != nil {
		t.Fatalf("GetInvocationCapabilities: %v", err)
	}
	if got.ListenerProfile != basil.InvocationListenerCourier || !got.RequireChallenge || got.CourierProtocolVersion != 1 {
		t.Fatalf("capabilities = %+v", got)
	}
}

func TestGetInvocationCapabilitiesRejectsUnknownProfiles(t *testing.T) {
	for _, profile := range []pb.ListenerProfile{pb.ListenerProfile_UNSPECIFIED, pb.ListenerProfile(99)} {
		fake := &fakeInvocation{
			capabilitiesResponse: &pb.GetInvocationCapabilitiesResponse{ListenerProfile: profile},
		}
		c := serveAndDial(t, func(srv *grpc.Server) {
			pb.RegisterInvocationServiceServer(srv, fake)
		})
		if _, err := c.GetInvocationCapabilities(context.Background()); err == nil {
			t.Fatalf("profile %d accepted", profile)
		}
	}
}
