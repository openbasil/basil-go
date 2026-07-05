// Package spiffe provides helpers for fetching and using Basil-issued SPIFFE
// SVIDs over the broker's local SPIFFE Workload API Unix-domain socket.
//
// Basil implements the open SPIFFE Workload API standard, so this package wraps
// the reference go-spiffe client ([github.com/spiffe/go-spiffe/v2/workloadapi])
// rather than reimplementing the protocol. go-spiffe attaches the mandatory
// `workload.spiffe.io: true` request header, parses X.509-SVIDs and JWT-SVIDs
// into typed values, validates them, and manages streaming rotation with
// reconnect/backoff. This package adds only the Basil-specific wiring: the
// Unix-socket endpoint address and a pinned HTTP/2 :authority.
//
// It is a separate package from the core broker client (module root, package
// basil) so that a workload using only the broker data plane does not link the
// go-spiffe dependency tree.
//
// # Fetching an SVID
//
//	c, err := spiffe.Dial(ctx, "/run/basil/agent.sock")
//	if err != nil {
//		return err
//	}
//	defer c.Close()
//
//	svid, err := c.FetchX509SVID(ctx)   // *x509svid.SVID: ID, chain, key
//	jwt, err := c.FetchJWTSVID(ctx, "spiffe://example.org/db") // *jwtsvid.SVID
//
// # Keeping a current SVID (rotation)
//
// SVIDs rotate well before they expire. For long-running workloads use a
// rotation-aware source rather than a one-shot fetch:
//
//	src, err := spiffe.NewX509Source(ctx, "/run/basil/agent.sock")
//	if err != nil {
//		return err
//	}
//	defer src.Close()
//	tlsCfg := tlsconfig.MTLSServerConfig(src, src, tlsconfig.AuthorizeAny())
//
// The source plugs straight into go-spiffe's tlsconfig helpers and always
// presents the freshest leaf. [Client.WatchX509Context] exposes the raw update
// stream when you need to react to each rotation yourself.
//
// # Errors
//
// Every method normalizes a broker rejection into a typed
// [github.com/openbasil/basil-go/basil.StatusError] via
// [github.com/openbasil/basil-go/basil.FromError], so SPIFFE errors carry the
// same Code/Reason/Op detail as the rest of the client. See docs/errors.md.
package spiffe
