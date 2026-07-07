package spiffe

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openbasil/basil-go/basil"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
)

// DefaultTimeout is applied to each one-shot fetch/validate call whose context
// carries no deadline of its own. It does not apply to the long-lived Watch
// methods, which run until their context is cancelled.
const DefaultTimeout = 30 * time.Second

type config struct {
	timeout    time.Duration
	clientOpts []workloadapi.ClientOption
}

// Option configures a [Client] at [Dial] time.
type Option func(*config)

// WithTimeout sets the per-call timeout applied to a one-shot fetch/validate
// when the caller's context has no deadline of its own. A non-positive
// duration disables the default, requiring callers to supply their own
// deadline. The default is [DefaultTimeout]. Watch calls are never bounded by
// this timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithClientOptions adds extra go-spiffe [workloadapi.ClientOption]s, such
// as a logger or a custom backoff strategy. They are applied before the
// options [Dial] fixes, so the Workload API endpoint address and the pinned
// HTTP/2 :authority cannot be overridden through this option.
func WithClientOptions(opts ...workloadapi.ClientOption) Option {
	return func(c *config) { c.clientOpts = append(c.clientOpts, opts...) }
}

// Client fetches and validates Basil-issued SPIFFE SVIDs over the broker's
// local SPIFFE Workload API Unix-domain socket.
//
// It wraps go-spiffe's [workloadapi.Client], which transparently attaches the
// mandatory `workload.spiffe.io: true` request header, parses X.509-SVIDs and
// JWT-SVIDs into typed values, and manages the streaming reconnect/backoff for
// the Watch surface. Basil attests the caller by SO_PEERCRED on the socket, so,
// exactly as for an SVID delivered by SPIRE, the Workload API legitimately
// returns the workload's own X.509-SVID private key to that workload.
//
// A Client is safe for concurrent use by multiple goroutines. Create one with
// [Dial] and release it with [Client.Close].
type Client struct {
	wl      *workloadapi.Client
	timeout time.Duration
}

// Dial connects to the Basil SPIFFE Workload API on the Unix-domain socket at
// socketPath. A bare filesystem path is wired as a `unix://` endpoint; a value
// that already carries a scheme (`unix://`, `tcp://`) is used unchanged.
//
// The connection is lazy: it is established on the first call, so Dial returns
// promptly and an unreachable socket surfaces as an error on first use. The
// caller owns the returned Client and must call [Client.Close].
func Dial(ctx context.Context, socketPath string, opts ...Option) (*Client, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("basil/spiffe: empty socket path")
	}
	cfg := config{timeout: DefaultTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}

	wl, err := workloadapi.New(ctx, clientOptions(socketPath, cfg.clientOpts)...)
	if err != nil {
		return nil, fmt.Errorf("basil/spiffe: dial %q: %w", socketPath, err)
	}
	return &Client{wl: wl, timeout: cfg.timeout}, nil
}

// Close releases the underlying Workload API connection. The Client must not be
// used afterwards.
func (c *Client) Close() error { return c.wl.Close() }

// Workload exposes the underlying go-spiffe Workload API client for advanced
// use (for example a JWT-SVID for a specific subject SPIFFE ID via
// [jwtsvid.Params], or the WIT-SVID surface). Errors from the returned client
// are raw gRPC errors; pass them through [basil.FromError] to recover a typed
// [basil.StatusError].
func (c *Client) Workload() *workloadapi.Client { return c.wl }

// FetchX509SVID fetches the workload's default X.509-SVID: its SPIFFE ID, the
// certificate chain (leaf first), the leaf private key, and, via the leaf's
// NotAfter, its expiry.
func (c *Client) FetchX509SVID(ctx context.Context) (*x509svid.SVID, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	svid, err := c.wl.FetchX509SVID(ctx)
	return svid, basil.FromError(err)
}

// FetchX509SVIDs fetches every X.509-SVID the workload is entitled to. Use the
// `Hint` on each SVID to disambiguate when more than one is returned.
func (c *Client) FetchX509SVIDs(ctx context.Context) ([]*x509svid.SVID, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	svids, err := c.wl.FetchX509SVIDs(ctx)
	return svids, basil.FromError(err)
}

// FetchX509Bundles fetches the X.509 trust bundles, keyed by trust domain,
// that the workload should trust when verifying peer X.509-SVIDs.
func (c *Client) FetchX509Bundles(ctx context.Context) (*x509bundle.Set, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	set, err := c.wl.FetchX509Bundles(ctx)
	return set, basil.FromError(err)
}

// FetchX509Context fetches the workload's X.509-SVIDs together with the trust
// bundles in a single call.
func (c *Client) FetchX509Context(ctx context.Context) (*workloadapi.X509Context, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	x, err := c.wl.FetchX509Context(ctx)
	return x, basil.FromError(err)
}

// FetchJWTSVID fetches a JWT-SVID for the given audience (and any additional
// audiences). The returned SVID carries the token (via [jwtsvid.SVID.Marshal]),
// the SPIFFE ID, the parsed claims, and the expiry.
func (c *Client) FetchJWTSVID(ctx context.Context, audience string, extraAudiences ...string) (*jwtsvid.SVID, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	svid, err := c.wl.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience, ExtraAudiences: extraAudiences})
	return svid, basil.FromError(err)
}

// FetchJWTSVIDs fetches every JWT-SVID the workload is entitled to for the
// given audience(s).
func (c *Client) FetchJWTSVIDs(ctx context.Context, audience string, extraAudiences ...string) ([]*jwtsvid.SVID, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	svids, err := c.wl.FetchJWTSVIDs(ctx, jwtsvid.Params{Audience: audience, ExtraAudiences: extraAudiences})
	return svids, basil.FromError(err)
}

// FetchJWTBundles fetches the JWT trust bundles (JWKS documents), keyed by
// trust domain, for validating peer JWT-SVIDs offline.
func (c *Client) FetchJWTBundles(ctx context.Context) (*jwtbundle.Set, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	set, err := c.wl.FetchJWTBundles(ctx)
	return set, basil.FromError(err)
}

// ValidateJWTSVID asks the broker to validate token against audience and
// returns the parsed JWT-SVID (SPIFFE ID and claims) on success.
func (c *Client) ValidateJWTSVID(ctx context.Context, token, audience string) (*jwtsvid.SVID, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	svid, err := c.wl.ValidateJWTSVID(ctx, token, audience)
	return svid, basil.FromError(err)
}

// WatchX509Context streams X.509-SVID and bundle updates to watcher until ctx
// is cancelled, so a long-running workload always holds a fresh SVID across
// rotations. go-spiffe reconnects with backoff on transient failures and
// reports them via the watcher's error callback. This call blocks; run it in
// its own goroutine. Prefer [NewX509Source] for the common "keep a current
// SVID for TLS" case.
func (c *Client) WatchX509Context(ctx context.Context, watcher workloadapi.X509ContextWatcher) error {
	return basil.FromError(c.wl.WatchX509Context(ctx, watcher))
}

// WatchJWTBundles streams JWT bundle updates to watcher until ctx is cancelled.
// This call blocks; run it in its own goroutine.
func (c *Client) WatchJWTBundles(ctx context.Context, watcher workloadapi.JWTBundleWatcher) error {
	return basil.FromError(c.wl.WatchJWTBundles(ctx, watcher))
}

// NewX509Source returns a rotation-aware [workloadapi.X509Source] bound to the
// Basil Workload API at socketPath. The source keeps the workload's X.509-SVID
// and trust bundles current in the background; it satisfies go-spiffe's
// tlsconfig sources, so it plugs straight into mTLS server/client config. Close
// it when done. extra appends go-spiffe client options (logger, backoff).
func NewX509Source(ctx context.Context, socketPath string, extra ...workloadapi.ClientOption) (*workloadapi.X509Source, error) {
	src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(clientOptions(socketPath, extra)...))
	if err != nil {
		return nil, fmt.Errorf("basil/spiffe: x509 source %q: %w", socketPath, err)
	}
	return src, nil
}

// NewJWTSource returns a rotation-aware [workloadapi.JWTSource] bound to the
// Basil Workload API at socketPath. It keeps the JWT trust bundles current for
// offline JWT-SVID validation and mints JWT-SVIDs on demand. Close it when
// done. extra appends go-spiffe client options.
func NewJWTSource(ctx context.Context, socketPath string, extra ...workloadapi.ClientOption) (*workloadapi.JWTSource, error) {
	src, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(clientOptions(socketPath, extra)...))
	if err != nil {
		return nil, fmt.Errorf("basil/spiffe: jwt source %q: %w", socketPath, err)
	}
	return src, nil
}

// clientOptions builds the go-spiffe client options that bind a Workload API
// client to a Basil socket: the endpoint address plus a pinned :authority.
func clientOptions(socketPath string, extra []workloadapi.ClientOption) []workloadapi.ClientOption {
	// User-supplied options go first: a later WithAddr overwrites an earlier
	// one, and dial options accumulate with grpc-go resolving conflicts
	// last-wins, so the fixed options below always take precedence, as
	// documented on [WithClientOptions].
	return append(extra,
		workloadapi.WithAddr(socketAddr(socketPath)),
		// Pin a syntactically valid HTTP/2 :authority. The Unix-socket target
		// would otherwise leak the socket path into the :authority
		// pseudo-header, which the broker's HTTP/2 stack rejects with a
		// PROTOCOL_ERROR. The broker attests the caller by SO_PEERCRED, so the
		// value is otherwise unused.
		workloadapi.WithDialOptions(grpc.WithAuthority("localhost")),
	)
}

// socketAddr turns a bare filesystem path into a go-spiffe Workload API
// endpoint URI. A value that already carries a scheme is used unchanged.
func socketAddr(path string) string {
	if strings.Contains(path, "://") {
		return path
	}
	return "unix://" + path
}

// withTimeout applies the client's default timeout when ctx carries no
// deadline. The returned cancel func must always be called.
func (c *Client) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.timeout <= 0 {
		return ctx, func() {}
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout)
}
