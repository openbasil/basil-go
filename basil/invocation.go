package basil

import (
	"context"
	"fmt"

	"github.com/openbasil/basil-go/internal/pb"
)

// InvocationChallengeLen is the exact byte length of a broker-issued
// single-use freshness challenge: a 16-byte issuing-instance ID prefix
// followed by 16 CSPRNG bytes.
const InvocationChallengeLen = 32

// ReasonChallengeIssuanceDeclined is the stable broker reason token attached
// to the ResourceExhausted status when GetInvocationChallenge declines
// issuance under capacity or rate-limit pressure. That denial is retryable
// with the same request after backoff.
const ReasonChallengeIssuanceDeclined = "CHALLENGE_ISSUANCE_DECLINED"

// InvocationListenerProfile is the broker's closed invocation-listener
// service surface.
type InvocationListenerProfile uint8

const (
	// InvocationListenerHost exposes the host and operator service surface.
	InvocationListenerHost InvocationListenerProfile = 1
	// InvocationListenerCourier exposes only InvocationService.
	InvocationListenerCourier InvocationListenerProfile = 3
)

// InvocationCapabilities describes the effective local listener contract.
type InvocationCapabilities struct {
	// ListenerProfile is the closed service surface serving this RPC.
	ListenerProfile InvocationListenerProfile
	// RequireChallenge reports whether every invocation requires freshness.
	RequireChallenge bool
	// CourierProtocolVersion is the frozen courier protocol version.
	CourierProtocolVersion uint32
}

// InvocationChallenge is a single-use sealed-invocation freshness challenge
// issued by the broker for one self-asserted proof-key thumbprint. The
// challenge bytes are embedded verbatim in the sealed invocation's
// encrypted-layer claim -70008 and consumed exactly once.
type InvocationChallenge struct {
	// Challenge is the 32 challenge bytes: a 16-byte issuing-instance ID
	// prefix followed by 16 CSPRNG bytes.
	Challenge [InvocationChallengeLen]byte
	// Generation is the serving generation the challenge is bound to.
	Generation uint64
	// ExpiresAtUnix is the Unix-seconds expiry, at most 60 seconds out.
	ExpiresAtUnix int64
}

// GetInvocationCapabilities returns the effective contract of the local
// invocation listener. An unspecified or unknown profile is rejected rather
// than exposed as a permissive default.
func (c *Client) GetInvocationCapabilities(ctx context.Context) (*InvocationCapabilities, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.invocation.GetInvocationCapabilities(ctx, &pb.GetInvocationCapabilitiesRequest{})
	if err != nil {
		return nil, statusError(err)
	}
	var profile InvocationListenerProfile
	switch resp.GetListenerProfile() {
	case pb.ListenerProfile_HOST:
		profile = InvocationListenerHost
	case pb.ListenerProfile_COURIER:
		profile = InvocationListenerCourier
	case pb.ListenerProfile_UNSPECIFIED:
		return nil, fmt.Errorf("basil: broker returned an unspecified invocation listener profile")
	default:
		return nil, fmt.Errorf("basil: broker returned unknown invocation listener profile %d", resp.GetListenerProfile())
	}
	return &InvocationCapabilities{
		ListenerProfile:        profile,
		RequireChallenge:       resp.GetRequireChallenge(),
		CourierProtocolVersion: resp.GetCourierProtocolVersion(),
	}, nil
}

// GetInvocationChallenge fetches a single-use freshness challenge bound to
// jkt, the caller's self-asserted RFC 7638 SHA-256 proof-key thumbprint (32
// bytes).
//
// courierObservedSource is set only by a trusted courier in front of the
// broker to partition issuance rate limits per client source; direct local
// callers pass "". It is never an identity or authorization input. Declined
// issuance surfaces as a [StatusError] with codes.ResourceExhausted and
// Reason [ReasonChallengeIssuanceDeclined]. [Client.GetInvocationCapabilities]
// is the authority for the connected listener's challenge and courier contract.
func (c *Client) GetInvocationChallenge(ctx context.Context, jkt []byte, courierObservedSource string) (*InvocationChallenge, error) {
	if len(jkt) != InvocationChallengeLen {
		return nil, fmt.Errorf("basil: jkt must be exactly %d bytes, got %d", InvocationChallengeLen, len(jkt))
	}
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	req := &pb.GetInvocationChallengeRequest{Jkt: append([]byte(nil), jkt...)}
	if courierObservedSource != "" {
		req.CourierObservedSource = &courierObservedSource
	}
	resp, err := c.invocation.GetInvocationChallenge(ctx, req)
	if err != nil {
		return nil, statusError(err)
	}
	if len(resp.GetChallenge()) != InvocationChallengeLen {
		return nil, fmt.Errorf("basil: freshness challenge must be exactly %d bytes, got %d", InvocationChallengeLen, len(resp.GetChallenge()))
	}
	out := &InvocationChallenge{
		Generation:    resp.GetGeneration(),
		ExpiresAtUnix: resp.GetExpiresAtUnix(),
	}
	copy(out.Challenge[:], resp.GetChallenge())
	return out, nil
}
