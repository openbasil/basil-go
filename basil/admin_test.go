package basil_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/openbasil/basil-go/basil"
	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeAdmin struct {
	pb.UnimplementedAdminServiceServer

	statusResp    *pb.StatusResponse
	healthResp    *pb.HealthResponse
	readinessResp *pb.ReadinessResponse
	reloadResp    *pb.ReloadResponse
	explainResp   *pb.ExplainResponse
	revokeResp    *pb.RevokeResponse
	watchEvents   []*pb.Event
	lastReload    *pb.ReloadRequest
	lastExplain   *pb.ExplainRequest
	lastRevoke    *pb.RevokeRequest
	lastWatch     *pb.WatchRequest
	err           error
}

func (f *fakeAdmin) Status(_ context.Context, _ *pb.StatusRequest) (*pb.StatusResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.statusResp, nil
}

func (f *fakeAdmin) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.healthResp, nil
}

func (f *fakeAdmin) Readiness(_ context.Context, _ *pb.ReadinessRequest) (*pb.ReadinessResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.readinessResp, nil
}

func (f *fakeAdmin) Reload(_ context.Context, req *pb.ReloadRequest) (*pb.ReloadResponse, error) {
	f.lastReload = req
	if f.err != nil {
		return nil, f.err
	}
	return f.reloadResp, nil
}

func (f *fakeAdmin) Explain(_ context.Context, req *pb.ExplainRequest) (*pb.ExplainResponse, error) {
	f.lastExplain = req
	if f.err != nil {
		return nil, f.err
	}
	return f.explainResp, nil
}

func (f *fakeAdmin) Revoke(_ context.Context, req *pb.RevokeRequest) (*pb.RevokeResponse, error) {
	f.lastRevoke = req
	if f.err != nil {
		return nil, f.err
	}
	return f.revokeResp, nil
}

func (f *fakeAdmin) Watch(req *pb.WatchRequest, stream pb.AdminService_WatchServer) error {
	f.lastWatch = req
	if f.err != nil {
		return f.err
	}
	for _, ev := range f.watchEvents {
		if err := stream.Send(ev); err != nil {
			return err
		}
	}
	return nil
}

func dialAdmin(t *testing.T, f *fakeAdmin) *basil.Client {
	return serveAndDial(t, func(srv *grpc.Server) { pb.RegisterAdminServiceServer(srv, f) })
}

func TestStatusMapsResponse(t *testing.T) {
	f := &fakeAdmin{statusResp: &pb.StatusResponse{Backend: "vault", Version: "1.2.3", Protocol: 1}}
	c := dialAdmin(t, f)

	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Backend != "vault" || st.Version != "1.2.3" || st.Protocol != 1 {
		t.Errorf("unexpected status: %+v", st)
	}
}

func TestHealthMapsResponse(t *testing.T) {
	f := &fakeAdmin{healthResp: &pb.HealthResponse{Alive: true, Version: "1.2.3"}}
	c := dialAdmin(t, f)

	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if !h.Alive || h.Version != "1.2.3" {
		t.Errorf("unexpected health: %+v", h)
	}
}

func TestReadinessMapsResponse(t *testing.T) {
	f := &fakeAdmin{readinessResp: &pb.ReadinessResponse{
		Ready:               true,
		Reason:              pb.ReadinessReason_READINESS_REASON_READY,
		Generation:          7,
		KeysTotal:           10,
		KeysPresent:         9,
		KeysRequiredMissing: 0,
		KeysOptionalMissing: 1,
	}}
	c := dialAdmin(t, f)

	r, err := c.Readiness(context.Background())
	if err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if !r.Ready || r.Reason != basil.ReadinessReasonReady || r.Generation != 7 ||
		r.KeysTotal != 10 || r.KeysPresent != 9 || r.KeysRequiredMissing != 0 || r.KeysOptionalMissing != 1 {
		t.Errorf("unexpected readiness: %+v", r)
	}
}

func TestStatusMapsStatusError(t *testing.T) {
	c := dialAdmin(t, &fakeAdmin{err: status.Error(codes.Unavailable, "broker down")})

	_, err := c.Status(context.Background())
	se, ok := basil.AsStatusError(err)
	if !ok {
		t.Fatalf("error is not a *StatusError: %v", err)
	}
	if se.Code != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", se.Code)
	}
}

func TestReloadAppliedMapsResponse(t *testing.T) {
	f := &fakeAdmin{reloadResp: &pb.ReloadResponse{
		Applied:            true,
		Checked:            false,
		PreviousGeneration: 4,
		NewGeneration:      5,
		KeyCount:           12,
		GrantCount:         30,
	}}
	c := dialAdmin(t, f)

	r, err := c.Reload(context.Background(), false)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !r.Applied || r.Checked || r.PreviousGeneration != 4 || r.NewGeneration != 5 ||
		r.KeyCount != 12 || r.GrantCount != 30 || r.Rejection != nil {
		t.Errorf("unexpected reload result: %+v", r)
	}
	if f.lastReload.GetCheck() {
		t.Errorf("check = true, want false")
	}
}

func TestReloadRejectionMapsThrough(t *testing.T) {
	f := &fakeAdmin{reloadResp: &pb.ReloadResponse{
		Applied:            false,
		PreviousGeneration: 7,
		NewGeneration:      7,
		Rejection:          &pb.ReloadRejection{Reason: "routing_shape_changed", Message: "routes differ"},
	}}
	c := dialAdmin(t, f)

	r, err := c.Reload(context.Background(), true)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if r.Applied || r.Rejection == nil || r.Rejection.Reason != "routing_shape_changed" ||
		r.Rejection.Message != "routes differ" {
		t.Errorf("unexpected rejection mapping: %+v", r)
	}
	if !f.lastReload.GetCheck() {
		t.Errorf("check = false, want true")
	}
}

func TestExplainAllowMapsMatchedRule(t *testing.T) {
	f := &fakeAdmin{explainResp: &pb.ExplainResponse{
		Subject:  "svc.app",
		Op:       "sign",
		Key:      "app.signing",
		Decision: "allow",
		Via:      "subject:svc.app",
		MatchedRule: &pb.MatchedRule{
			Rule:    "r1",
			Via:     "subject:svc.app",
			Action:  "sign",
			Target:  "app.*",
			Subject: "svc.app",
		},
	}}
	c := dialAdmin(t, f)

	e, err := c.Explain(context.Background(), "svc.app", "sign", "app.signing")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if e.Subject != "svc.app" || e.Op != "sign" || e.Key != "app.signing" ||
		e.Decision != "allow" || e.Via != "subject:svc.app" {
		t.Errorf("unexpected explain result: %+v", e)
	}
	if e.MatchedRule == nil || e.MatchedRule.Rule != "r1" || e.MatchedRule.Action != "sign" ||
		e.MatchedRule.Target != "app.*" || e.MatchedRule.Subject != "svc.app" {
		t.Errorf("unexpected matched rule: %+v", e.MatchedRule)
	}
	if f.lastExplain.GetSubject() != "svc.app" || f.lastExplain.GetOp() != "sign" ||
		f.lastExplain.GetKey() != "app.signing" {
		t.Errorf("unexpected explain request: %+v", f.lastExplain)
	}
}

func TestExplainDenyHasNoMatchedRule(t *testing.T) {
	f := &fakeAdmin{explainResp: &pb.ExplainResponse{
		Subject:  "svc.app",
		Op:       "get",
		Key:      "secret",
		Decision: "deny",
		Reason:   "not_permitted",
	}}
	c := dialAdmin(t, f)

	e, err := c.Explain(context.Background(), "svc.app", "get", "secret")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if e.Decision != "deny" || e.Reason != "not_permitted" || e.Via != "" || e.MatchedRule != nil {
		t.Errorf("unexpected deny mapping: %+v", e)
	}
}

func TestRevokeMapsResponse(t *testing.T) {
	f := &fakeAdmin{revokeResp: &pb.RevokeResponse{
		TrustDomain:   "example.org",
		Jti:           "abc123",
		ExpiresAtUnix: 1893456000,
		Persisted:     true,
	}}
	c := dialAdmin(t, f)

	r, err := c.Revoke(context.Background(), "example.org", "abc123", 1893456000)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if r.TrustDomain != "example.org" || r.JTI != "abc123" || r.ExpiresAtUnix != 1893456000 || !r.Persisted {
		t.Errorf("unexpected revoke result: %+v", r)
	}
	if f.lastRevoke.GetTrustDomain() != "example.org" || f.lastRevoke.GetJti() != "abc123" ||
		f.lastRevoke.GetExpiresAtUnix() != 1893456000 {
		t.Errorf("unexpected revoke request: %+v", f.lastRevoke)
	}
}

func TestWatchStreamsTypedEvents(t *testing.T) {
	f := &fakeAdmin{watchEvents: []*pb.Event{
		{
			Kind:   pb.EventKind_EVENT_KIND_KEY_ROTATED,
			Detail: &pb.Event_KeyRotated{KeyRotated: &pb.KeyRotated{KeyId: "app.signing", NewVersion: 3}},
		},
		{
			Kind:   pb.EventKind_EVENT_KIND_REVOKED,
			Detail: &pb.Event_Revoked{Revoked: &pb.Revoked{TrustDomain: "example.org", Id: "jti-1"}},
		},
	}}
	c := dialAdmin(t, f)

	stream, err := c.Watch(context.Background(), basil.EventKindKeyRotated, basil.EventKindRevoked)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	defer func() { _ = stream.Close() }()

	var got []*basil.Event
	for ev, err := range stream.Events() {
		if err != nil {
			t.Fatalf("events: %v", err)
		}
		got = append(got, ev)
	}
	if len(got) != 2 {
		t.Fatalf("received %d events, want 2", len(got))
	}
	if got[0].Kind != basil.EventKindKeyRotated || got[0].KeyRotated == nil ||
		got[0].KeyRotated.KeyID != "app.signing" || got[0].KeyRotated.NewVersion != 3 {
		t.Errorf("unexpected first event: %+v", got[0])
	}
	if got[1].Kind != basil.EventKindRevoked || got[1].Revoked == nil ||
		got[1].Revoked.TrustDomain != "example.org" || got[1].Revoked.ID != "jti-1" {
		t.Errorf("unexpected second event: %+v", got[1])
	}
	if f.lastWatch == nil || len(f.lastWatch.GetKinds()) != 2 {
		t.Errorf("watch request kinds = %+v, want 2 kinds", f.lastWatch.GetKinds())
	}
}

func TestWatchRecvReturnsEOFOnCleanClose(t *testing.T) {
	f := &fakeAdmin{watchEvents: []*pb.Event{
		{Kind: pb.EventKind_EVENT_KIND_BUNDLE_CHANGED, Detail: &pb.Event_BundleChanged{
			BundleChanged: &pb.BundleChanged{TrustDomain: "example.org"},
		}},
	}}
	c := dialAdmin(t, f)

	stream, err := c.Watch(context.Background())
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	defer func() { _ = stream.Close() }()

	ev, err := stream.Recv()
	if err != nil {
		t.Fatalf("first recv: %v", err)
	}
	if ev.Kind != basil.EventKindBundleChanged || ev.BundleChanged == nil ||
		ev.BundleChanged.TrustDomain != "example.org" {
		t.Errorf("unexpected event: %+v", ev)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("second recv err = %v, want io.EOF", err)
	}
}

func TestWatchMapsStatusError(t *testing.T) {
	c := dialAdmin(t, &fakeAdmin{err: status.Error(codes.PermissionDenied, "no watch")})

	stream, err := c.Watch(context.Background())
	if err != nil {
		// A streaming RPC can surface the denial either at open or on first Recv.
		se, ok := basil.AsStatusError(err)
		if !ok || se.Code != codes.PermissionDenied {
			t.Fatalf("open error = %v, want PermissionDenied *StatusError", err)
		}
		return
	}
	defer func() { _ = stream.Close() }()
	_, err = stream.Recv()
	se, ok := basil.AsStatusError(err)
	if !ok || se.Code != codes.PermissionDenied {
		t.Fatalf("recv error = %v, want PermissionDenied *StatusError", err)
	}
}
