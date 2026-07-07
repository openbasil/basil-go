package basil

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// DefaultTimeout is applied to each RPC whose context carries no deadline of
// its own.
const DefaultTimeout = 30 * time.Second

// Client is a connection to a Basil broker over its local Unix-domain socket.
//
// A Client is safe for concurrent use by multiple goroutines; the underlying
// gRPC connection multiplexes calls. Create one with [Dial] and release it
// with [Client.Close].
type Client struct {
	conn    *grpc.ClientConn
	signing pb.SigningServiceClient
	aead    pb.AeadServiceClient
	secret  pb.SecretServiceClient
	minting pb.MintingServiceClient
	nats    pb.NatsServiceClient
	admin   pb.AdminServiceClient
	timeout time.Duration
}

type config struct {
	timeout     time.Duration
	dialOptions []grpc.DialOption
}

// Option configures a [Client] at [Dial] time.
type Option func(*config)

// WithTimeout sets the per-RPC timeout applied when the caller's context has
// no deadline of its own. A non-positive duration disables the default
// timeout, requiring callers to supply their own context deadline. The
// default is [DefaultTimeout].
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithDialOptions adds extra gRPC dial options, such as interceptors or
// message-size limits. They are applied before the options [Dial] fixes, so
// the transport credentials, the pinned :authority, and the Unix-socket
// dialer cannot be overridden through this option.
func WithDialOptions(opts ...grpc.DialOption) Option {
	return func(c *config) { c.dialOptions = append(c.dialOptions, opts...) }
}

// Dial connects to the broker listening on the Unix-domain socket at
// socketPath. The connection is lazy: it is established on the first RPC, so
// Dial returns promptly and an unreachable socket surfaces as an error on
// first use rather than here.
//
// The caller owns the returned Client and must call [Client.Close] to release
// the connection.
func Dial(socketPath string, opts ...Option) (*Client, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("basil: empty socket path")
	}
	cfg := config{timeout: DefaultTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}

	// User-supplied options go first: grpc-go resolves conflicting options
	// last-wins, so the fixed options below always take precedence, as
	// documented on [WithDialOptions].
	dialOpts := append(cfg.dialOptions,
		// The broker speaks plaintext gRPC over a local Unix socket and
		// attests the caller via SO_PEERCRED; there is no TLS to negotiate.
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Pin a syntactically valid HTTP/2 :authority. Without this the
		// target (a filesystem path) leaks into :authority, which the broker's
		// HTTP/2 stack rejects with a PROTOCOL_ERROR. The value is otherwise
		// unused: the broker authenticates by SO_PEERCRED, not by host.
		grpc.WithAuthority("localhost"),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}),
	)

	// "passthrough:///" hands the target to the context dialer untouched,
	// sidestepping the resolver's own parsing of unix paths (which differs for
	// absolute versus relative paths).
	conn, err := grpc.NewClient("passthrough:///"+socketPath, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("basil: dial %q: %w", socketPath, err)
	}
	return &Client{
		conn:    conn,
		signing: pb.NewSigningServiceClient(conn),
		aead:    pb.NewAeadServiceClient(conn),
		secret:  pb.NewSecretServiceClient(conn),
		minting: pb.NewMintingServiceClient(conn),
		nats:    pb.NewNatsServiceClient(conn),
		admin:   pb.NewAdminServiceClient(conn),
		timeout: cfg.timeout,
	}, nil
}

// Close releases the underlying gRPC connection. It is safe to call once; the
// Client must not be used afterwards.
func (c *Client) Close() error {
	return c.conn.Close()
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
