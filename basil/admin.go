package basil

import (
	"context"
	"errors"
	"io"
	"iter"
	"time"

	"github.com/openbasil/basil-go/internal/pb"
)

// ReadinessReason is the coarse, non-secret category explaining a
// [Readiness] decision. It mirrors basil.broker.v1.ReadinessReason and never
// names a key.
type ReadinessReason int32

const (
	// ReadinessReasonUnspecified is the zero value.
	ReadinessReasonUnspecified ReadinessReason = 0
	// ReadinessReasonReady means the broker can serve: every backend is
	// reachable and no required key's material is absent.
	ReadinessReasonReady ReadinessReason = 1
	// ReadinessReasonBackendUnreachable means at least one backend was
	// unreachable (or rejecting) while probing.
	ReadinessReasonBackendUnreachable ReadinessReason = 2
	// ReadinessReasonRequiredKeyMissing means at least one missing=error key's
	// material is absent, so its ops would fail closed.
	ReadinessReasonRequiredKeyMissing ReadinessReason = 3
)

// String returns the broker's enum name for the readiness reason.
func (r ReadinessReason) String() string { return pb.ReadinessReason(r).String() }

// Status is the broker's identity and protocol info, as returned by
// [Client.Status].
type Status struct {
	// Backend is the backend identifier the broker is running against (for
	// example "vault").
	Backend string
	// Version is the broker build version string.
	Version string
	// Protocol is the wire protocol version number.
	Protocol uint32
}

// Health is the broker's liveness, as returned by [Client.Health]. A returned
// value is itself the liveness signal: the daemon is up and serving the socket.
type Health struct {
	// Alive is always true for a response that was produced; the field is
	// explicit so a future degraded-but-alive state has a home.
	Alive bool
	// Version is the broker build version string (matches [Status.Version]).
	Version string
}

// Readiness is the broker's readiness, a non-secret operational summary, as
// returned by [Client.Readiness]. It never carries key names, key material, or
// the catalog inventory.
type Readiness struct {
	// Ready reports whether the broker can serve: true iff serving would not
	// fail closed for any configured key and every backend is reachable.
	Ready bool
	// Reason is the dominant reason readiness was decided (a coarse category,
	// not a key name).
	Reason ReadinessReason
	// Generation is the id of the currently serving policy/catalog generation
	// (monotonic, bumped on each successful hot reload).
	Generation uint64
	// KeysTotal is the total number of catalog keys probed.
	KeysTotal uint32
	// KeysPresent is the number of keys whose material is present.
	KeysPresent uint32
	// KeysRequiredMissing is the number of absent missing=error keys whose ops
	// would fail closed (non-zero makes the broker not ready).
	KeysRequiredMissing uint32
	// KeysOptionalMissing is the number of absent keys whose missing policy is
	// warn or generate (reported for visibility only).
	KeysOptionalMissing uint32
}

// Status reports the broker's backend, build version, and wire protocol
// version. It is broker introspection and touches no backend.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.admin.Status(ctx, &pb.StatusRequest{})
	if err != nil {
		return nil, statusError(err)
	}
	return &Status{
		Backend:  resp.GetBackend(),
		Version:  resp.GetVersion(),
		Protocol: resp.GetProtocol(),
	}, nil
}

// Health probes broker liveness: whether the daemon is up and serving the
// socket. It is cheap and never touches a backend; a successful return says
// nothing about whether the broker can serve data-plane ops (see
// [Client.Readiness] for that).
func (c *Client) Health(ctx context.Context) (*Health, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.admin.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return nil, statusError(err)
	}
	return &Health{Alive: resp.GetAlive(), Version: resp.GetVersion()}, nil
}

// Readiness probes whether the broker can actually serve: it checks per-backend
// reachability and every catalog key's material, and reports whether serving
// would fail closed. The result is a non-secret summary (counts plus a coarse
// reason); it never returns key names or material.
func (c *Client) Readiness(ctx context.Context) (*Readiness, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.admin.Readiness(ctx, &pb.ReadinessRequest{})
	if err != nil {
		return nil, statusError(err)
	}
	return &Readiness{
		Ready:               resp.GetReady(),
		Reason:              ReadinessReason(resp.GetReason()),
		Generation:          resp.GetGeneration(),
		KeysTotal:           resp.GetKeysTotal(),
		KeysPresent:         resp.GetKeysPresent(),
		KeysRequiredMissing: resp.GetKeysRequiredMissing(),
		KeysOptionalMissing: resp.GetKeysOptionalMissing(),
	}, nil
}

// ReloadResult is the outcome of an admin [Client.Reload].
type ReloadResult struct {
	// Applied reports whether a generation swap occurred: true only for a
	// successful non-dry-run reload; false for a dry-run (check) or any rejection.
	Applied bool
	// Checked reports whether this was a dry-run (check = true): validated, never
	// swapped.
	Checked bool
	// PreviousGeneration is the generation that was serving before this call (and
	// still is, on a dry-run or rejection).
	PreviousGeneration uint64
	// NewGeneration is the generation now serving (a real applied reload) or the
	// would-be new generation (a dry-run that validated). It equals
	// PreviousGeneration on a rejection.
	NewGeneration uint64
	// KeyCount is the number of catalog keys in the validated candidate generation.
	KeyCount uint32
	// GrantCount is the number of resolved policy allow-grants in the validated
	// candidate generation.
	GrantCount uint32
	// Rejection is set only when the candidate was rejected (Applied is false and
	// this was not a clean dry-run); nil otherwise.
	Rejection *ReloadRejection
}

// ReloadRejection explains why a [Client.Reload] candidate was rejected; the
// previous generation keeps serving.
type ReloadRejection struct {
	// Reason is a stable, non-secret reason token (for example "validation_failed",
	// "routing_shape_changed", "catalog_read_failed", "no_reload_inputs").
	Reason string
	// Message is a human-readable, non-secret description of the rejection.
	Message string
}

// Reload triggers a permission-gated catalog/policy hot reload from disk. The
// broker re-reads the catalog/policy from its configured on-disk paths (never
// from the wire; this call carries no config), validates the candidate, and,
// unless check is true, atomically swaps in a new generation.
//
// check = true is a dry-run: it validates and reports the would-be outcome
// without swapping. A caller lacking the dedicated reload permission gets a
// *StatusError with code PermissionDenied; a validation/routing rejection
// returns no error with Applied false and a non-nil Rejection.
func (c *Client) Reload(ctx context.Context, check bool) (*ReloadResult, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.admin.Reload(ctx, &pb.ReloadRequest{Check: check})
	if err != nil {
		return nil, statusError(err)
	}
	out := &ReloadResult{
		Applied:            resp.GetApplied(),
		Checked:            resp.GetChecked(),
		PreviousGeneration: resp.GetPreviousGeneration(),
		NewGeneration:      resp.GetNewGeneration(),
		KeyCount:           resp.GetKeyCount(),
		GrantCount:         resp.GetGrantCount(),
	}
	if r := resp.GetRejection(); r != nil {
		out.Rejection = &ReloadRejection{Reason: r.GetReason(), Message: r.GetMessage()}
	}
	return out, nil
}

// MatchedRule is the rule provenance for a rule-based allow in an
// [ExplainResult]. It is absent for denies and public-class allows.
type MatchedRule struct {
	// Rule is the policy rule id that matched.
	Rule string
	// Via is the scope that matched ("subject:<name>").
	Via string
	// Action is the action token that matched.
	Action string
	// Target is the target glob that matched.
	Target string
	// Subject is the matched policy subject.
	Subject string
}

// ExplainResult is a live policy explanation against the broker's serving
// generation, as returned by [Client.Explain]. Its shape mirrors
// `basil config explain --json` for the single-tuple path.
type ExplainResult struct {
	// Subject is the subject evaluated.
	Subject string
	// Op is the operation token evaluated.
	Op string
	// Key is the catalog key/target evaluated.
	Key string
	// Decision is "allow" or "deny".
	Decision string
	// Via is the allow scope ("subject:<name>" or "public_class"); empty on a
	// deny.
	Via string
	// Reason is the deny reason token ("unknown_key", "not_writable",
	// "not_permitted"); empty on an allow.
	Reason string
	// MatchedRule is the rule provenance for a rule-based allow; nil for denies and
	// public-class allows.
	MatchedRule *MatchedRule
}

// Explain evaluates a policy decision (subject, op token, catalog key)
// against the broker's currently serving generation. It is a permission-gated
// admin RPC: the caller needs the dedicated explain permission over
// broker.explain.
func (c *Client) Explain(ctx context.Context, subject, op, key string) (*ExplainResult, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.admin.Explain(ctx, &pb.ExplainRequest{Subject: subject, Op: op, Key: key})
	if err != nil {
		return nil, statusError(err)
	}
	out := &ExplainResult{
		Subject:  resp.GetSubject(),
		Op:       resp.GetOp(),
		Key:      resp.GetKey(),
		Decision: resp.GetDecision(),
		Via:      resp.GetVia(),
		Reason:   resp.GetReason(),
	}
	if m := resp.GetMatchedRule(); m != nil {
		out.MatchedRule = &MatchedRule{
			Rule:    m.GetRule(),
			Via:     m.GetVia(),
			Action:  m.GetAction(),
			Target:  m.GetTarget(),
			Subject: m.GetSubject(),
		}
	}
	return out, nil
}

// RevokeResult is the outcome of a live [Client.Revoke].
type RevokeResult struct {
	// TrustDomain is the SPIFFE trust domain revoked (without "spiffe://").
	TrustDomain string
	// JTI is the JWT ID that was revoked.
	JTI string
	// ExpiresAtUnix is the expiry recorded for the deny-list entry; the entry
	// auto-expires at this time.
	ExpiresAtUnix uint64
	// Persisted reports whether the revocation was written to the configured
	// backing store.
	Persisted bool
}

// Revoke persists and publishes a JWT-SVID revocation by its (trust domain,
// jti) tuple. expiresAtUnix is the credential's Unix expiry, at which the
// deny-list entry auto-expires. It is a permission-gated admin RPC: the caller
// needs the dedicated revoke permission over broker.revoke, and the broker must
// have a configured revocation_store=jwt-svid backing key so the revocation
// survives restart.
func (c *Client) Revoke(ctx context.Context, trustDomain, jti string, expiresAtUnix uint64) (*RevokeResult, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.admin.Revoke(ctx, &pb.RevokeRequest{
		TrustDomain:   trustDomain,
		Jti:           jti,
		ExpiresAtUnix: expiresAtUnix,
	})
	if err != nil {
		return nil, statusError(err)
	}
	return &RevokeResult{
		TrustDomain:   resp.GetTrustDomain(),
		JTI:           resp.GetJti(),
		ExpiresAtUnix: resp.GetExpiresAtUnix(),
		Persisted:     resp.GetPersisted(),
	}, nil
}

// EventKind is the kind of a change [Event] streamed by [Client.Watch]. It
// mirrors basil.broker.v1.EventKind.
type EventKind int32

const (
	// EventKindUnspecified is the zero value.
	EventKindUnspecified EventKind = 0
	// EventKindKeyRotated marks a key rotated to a new version.
	EventKindKeyRotated EventKind = 1
	// EventKindBundleChanged marks a trust-bundle change.
	EventKindBundleChanged EventKind = 2
	// EventKindRevoked marks a credential revocation.
	EventKindRevoked EventKind = 3
)

// String returns the broker's enum name for the event kind.
func (k EventKind) String() string { return pb.EventKind(k).String() }

// KeyRotated is the detail of an [EventKindKeyRotated] [Event].
type KeyRotated struct {
	// KeyID is the catalog name of the rotated key.
	KeyID string
	// NewVersion is the version the key rotated to.
	NewVersion uint32
}

// BundleChanged is the detail of an [EventKindBundleChanged] [Event].
type BundleChanged struct {
	// TrustDomain is the trust domain whose bundle changed.
	TrustDomain string
}

// Revoked is the detail of an [EventKindRevoked] [Event].
type Revoked struct {
	// TrustDomain is the trust domain the revoked credential belongs to.
	TrustDomain string
	// ID identifies the revoked credential (for example a JWT jti).
	ID string
}

// Event is a change notification streamed by [Client.Watch]. Kind selects which
// detail pointer is set; the other two are nil.
type Event struct {
	// Kind is the event kind.
	Kind EventKind
	// At is when the event occurred, or the zero time if the broker sent none.
	At time.Time
	// KeyRotated is set when Kind is EventKindKeyRotated.
	KeyRotated *KeyRotated
	// BundleChanged is set when Kind is EventKindBundleChanged.
	BundleChanged *BundleChanged
	// Revoked is set when Kind is EventKindRevoked.
	Revoked *Revoked
}

func eventFromProto(ev *pb.Event) *Event {
	out := &Event{Kind: EventKind(ev.GetKind())}
	if ts := ev.GetAt(); ts != nil {
		out.At = ts.AsTime()
	}
	if kr := ev.GetKeyRotated(); kr != nil {
		out.KeyRotated = &KeyRotated{KeyID: kr.GetKeyId(), NewVersion: kr.GetNewVersion()}
	}
	if bc := ev.GetBundleChanged(); bc != nil {
		out.BundleChanged = &BundleChanged{TrustDomain: bc.GetTrustDomain()}
	}
	if rv := ev.GetRevoked(); rv != nil {
		out.Revoked = &Revoked{TrustDomain: rv.GetTrustDomain(), ID: rv.GetId()}
	}
	return out
}

// WatchStream is an open server-stream of broker change [Event]s from
// [Client.Watch]. Consume it by ranging over [WatchStream.Events] or by calling
// [WatchStream.Recv] in a loop, then release it with [WatchStream.Close]. A
// WatchStream is not safe for concurrent Recv/Events, but [WatchStream.Close]
// may be called from another goroutine to unblock a pending receive.
type WatchStream struct {
	stream pb.AdminService_WatchClient
	cancel context.CancelFunc
}

// Recv blocks for the next event. It returns [io.EOF] when the broker closes the
// stream cleanly, a *StatusError on an RPC failure, or the context's error if
// the context passed to [Client.Watch] was cancelled (including via
// [WatchStream.Close]).
func (s *WatchStream) Recv() (*Event, error) {
	msg, err := s.stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, statusError(err)
	}
	return eventFromProto(msg), nil
}

// Events returns a range-over-func iterator over the stream's events. Each
// successful event is yielded with a nil error; a failure yields a single final
// (nil, err) pair and ends iteration. A clean server close ([io.EOF]) ends
// iteration WITHOUT yielding an error. It shares the underlying stream with
// [WatchStream.Recv]; use one or the other, not both.
func (s *WatchStream) Events() iter.Seq2[*Event, error] {
	return func(yield func(*Event, error) bool) {
		for {
			ev, err := s.Recv()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					yield(nil, err)
				}
				return
			}
			if !yield(ev, nil) {
				return
			}
		}
	}
}

// Close stops the stream and releases its resources. It is idempotent and safe
// to call from a different goroutine to unblock an in-flight [WatchStream.Recv].
func (s *WatchStream) Close() error {
	s.cancel()
	return nil
}

// Watch opens a server-stream of broker change events (key rotations, bundle
// changes, revocations). Pass zero kinds to receive every kind, or one or more
// [EventKind] values to filter. The returned [WatchStream] stays open until the
// broker ends it, the passed context is cancelled, or [WatchStream.Close] is
// called; unlike the unary RPCs it is NOT subject to the client's default
// per-RPC timeout. The caller owns the stream and must Close it.
func (c *Client) Watch(ctx context.Context, kinds ...EventKind) (*WatchStream, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	pbKinds := make([]pb.EventKind, len(kinds))
	for i, k := range kinds {
		pbKinds[i] = pb.EventKind(k)
	}
	stream, err := c.admin.Watch(streamCtx, &pb.WatchRequest{Kinds: pbKinds})
	if err != nil {
		cancel()
		return nil, statusError(err)
	}
	return &WatchStream{stream: stream, cancel: cancel}, nil
}
