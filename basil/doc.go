// Package basil is a Go client for the Basil secrets-and-identity broker.
//
// Basil brokers cryptographic operations over key material that never leaves
// the vault: the broker resolves a catalog key by its dotted identifier,
// checks policy against the caller's kernel-attested identity, and performs
// the operation in place. Public keys, signatures, ciphertext, tokens, and
// certificates come back to the caller; private key material does not.
//
// The broker listens on a local Unix-domain socket and attests the caller via
// SO_PEERCRED (process uid/gid/pid). This client simply dials that socket;
// there is no client-side attestation work to do.
//
// # Connecting
//
//	c, err := basil.Dial("/run/basil/broker.sock")
//	if err != nil {
//		return err
//	}
//	defer c.Close()
//
// # Signing and verification
//
//	sig, err := c.Sign(ctx, "app.signing", []byte("payload"))
//	ok, err := c.Verify(ctx, "app.signing", []byte("payload"), sig)
//	pub, err := c.GetPublicKey(ctx, "app.signing", nil)
//
// # Surfaces
//
// The [Client] covers the broker's data plane and introspection:
//
//   - SigningService: [Client.Sign], [Client.Verify], [Client.GetPublicKey].
//   - AeadService: [Client.Encrypt], [Client.Decrypt], and the KEM envelope
//     [Client.WrapEnvelope] / [Client.UnwrapEnvelope]. Basil owns the nonce; a
//     caller never supplies one.
//   - SecretService: [Client.GetSecret], [Client.SetSecret],
//     [Client.RotateSecret], [Client.ListCatalog].
//   - MintingService: [Client.MintJwt] and [Client.IssueCertificate]. The
//     certificate RPC releases a freshly minted leaf private key, because a TLS
//     server needs it.
//   - NatsService: the NATS minters ([Client.MintNatsUser] and friends),
//     [Client.SignNatsJwt], and curve xkey boxes via [Client.EncryptNatsCurve] /
//     [Client.DecryptNatsCurve].
//   - AdminService: [Client.Status], [Client.Health], [Client.Readiness].
//
// The SPIFFE Workload API lives in the github.com/openbasil/basil-go/spiffe
// subpackage (kept separate so this package does not link go-spiffe). The broker
// AdminService streaming Watch surface arrives in a later release. Every RPC
// takes a context, and a broker rejection is a typed [StatusError]; see
// FromError and docs/errors.md.
package basil
