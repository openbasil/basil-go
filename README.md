# basil-go

A Go client for the [Basil](https://github.com/openbasil/basil) secrets-and-identity broker.

Documentationn site **[docs.openbasil.org](https://docs.openbasil.org)**

Basil brokers cryptographic *operations* over key material that never leaves the
vault. The broker listens on a local Unix-domain socket and attests the caller
via `SO_PEERCRED` (process uid/gid/pid). This client simply dials that socket;
there is no client-side attestation to perform.

> **Scope.** The root package covers the broker data plane and introspection:
> `SigningService` (sign / verify / get-public-key), `AeadService`
> (encrypt / decrypt + KEM envelope wrap / unwrap), `SecretService`
> (get / set / rotate / list-catalog), `MintingService` (generic JWT minting
> and certificate issuance), `NatsService` (NATS mint/sign/validate and curve
> xkey boxes), and
> `AdminService` (status / health / readiness). The
> [`spiffe`](#spiffe-workload-api) subpackage covers the SPIFFE Workload API
> (fetch / validate SVIDs, trust bundles, rotation). The broker `AdminService`
> streaming `Watch` surface arrives in a later release.

## Install

```sh
go get github.com/openbasil/basil-go/basil
```

The core client is the `basil` package. The optional `spiffe`, `stream`, and
`sealedinvocation` subpackages can be imported individually where you need them.

## Connect

```go
import "github.com/openbasil/basil-go/basil"

client, err := basil.Dial("/run/basil/broker.sock")
if err != nil {
    return err
}
defer client.Close()
```

`Dial` is lazy: the connection is established on the first RPC, so an
unreachable socket surfaces as an error on first use, not at `Dial`. Options:

- `basil.WithTimeout(d)` sets the per-RPC timeout applied when the caller's
  context has no deadline (default `basil.DefaultTimeout`, 30s; pass `0` to
  disable and rely solely on your own context deadlines).
- `basil.WithDialOptions(...)` appends extra `grpc.DialOption`s (interceptors,
  message-size limits). The transport credentials and Unix dialer are fixed.

## Sign, verify, get public key

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

const keyID = "web.tls.signing_key"
msg := []byte("release v1.2.3")

sig, err := client.Sign(ctx, keyID, msg)            // raw signature bytes
ok, err := client.Verify(ctx, keyID, msg, sig)      // broker-side verification
pub, err := client.GetPublicKey(ctx, keyID, nil)    // *basil.PublicKey
```

The broker signs the input **as-is**: `msg` is the message itself, not a
precomputed digest, and the broker does no caller-directed prehashing. The
signature scheme is derived from the key's catalog type; use
`SignWithAlgorithm` / `VerifyWithAlgorithm` with a `basil.SigningAlgorithm` to
pick an explicit scheme (for example a NATS NKey signing input).

`Verify` returns `(false, nil)` when the broker authoritatively rejects a
signature; a non-nil error means verification could not be performed (denied,
unknown key, transport failure).

## Create and import keys

```go
// Generate a key under a catalog name; only the public half comes back.
h, err := client.NewKey(ctx, "app.pqc.sign", basil.KeyTypeMLDSA65)  // *basil.KeyHandle

// Import caller-supplied (BYOK) material. KeyMaterial is sealed: build it with
// Ed25519SeedMaterial (32-byte raw seed) or PKCS8DERMaterial (PKCS#8 DER).
h, err = client.Import(ctx, "nats.operator", basil.KeyTypeEd25519,
    basil.Ed25519SeedMaterial(seed))

// Import several keys in one authorized call (e.g. an nsc-init bundle). Auth is
// all-or-nothing; the imports are sequential, returned in request order.
keys, err := client.ImportSet(ctx, []basil.ImportEntry{
    {KeyID: "nats.operator", KeyType: basil.KeyTypeEd25519, Material: basil.Ed25519SeedMaterial(opSeed)},
    {KeyID: "nats.sys", KeyType: basil.KeyTypeEd25519, Material: basil.Ed25519SeedMaterial(sysSeed)},
})
```

Imported material is **write-only**: the broker takes it into the vault and no
RPC ever returns it. Custody and storage stay **catalog-controlled** (never
chosen by the caller), so `NewKey`/`Import` need the broker-side `new_key`
permission (plus `use_software_custody` for the software-custodied post-quantum
types).

## Encrypt and decrypt (AEAD)

Basil owns the nonce: you supply only plaintext (or a `*basil.Ciphertext`) and
optional AAD.

```go
// AAD is bound to the ciphertext but not encrypted; pass nil for none and
// supply the same bytes verbatim to Decrypt.
ct, err := client.Encrypt(ctx, "app.aead", basil.AeadAlgorithmAES256GCM, plaintext, aad)
pt, err := client.Decrypt(ctx, "app.aead", ct, aad)
```

`*basil.Ciphertext` is self-describing (suite, key version, nonce, ciphertext);
treat it as opaque and round-trip it unchanged. For KEM enveloping (ML-KEM or an
X25519 sealed box) use `WrapEnvelope` / `UnwrapEnvelope`, which round-trip a
`*basil.KemEnvelope`.

## Streaming encryption (files, large payloads)

The `stream` subpackage encrypts an `io.Reader` into an `io.Writer` in bounded
chunks, so arbitrarily large payloads never buffer in full. The on-the-wire
container is **byte-identical** to the Rust `basil::stream` implementation; both
follow the normative spec at
[`docs/specs/streaming-encryption-format.md`](../../docs/specs/streaming-encryption-format.md).
Basil owns every nonce (there is no caller-supplied nonce path), and decryption
fails closed on any tamper, reorder, truncation, downgrade, or malformed header.

It lives in its own subpackage so the lean root `basil` package never links the
post-quantum crypto dependencies (circl); import
`github.com/openbasil/basil-go/stream` only where you need it.

```go
import "github.com/openbasil/basil-go/stream"

// AEAD suites: a fresh 32-byte CEK is generated and returned (or supply one
// with stream.ProvidedCEK). Keep the CEK to decrypt later.
cek, err := stream.EncryptAEAD(dst, src, stream.SuiteAES256GCM,
    stream.GenerateCEK(), stream.DefaultChunkSize)
err = stream.DecryptAEAD(out, encrypted, cek)

// ML-KEM suites (post-quantum): encryption needs only the recipient's public
// encapsulation key; the CEK is wrapped once into the header. Decryption
// recovers it via a CEKRecovery seam. The broker keeps the key custodied:
err = stream.EncryptMLKEM(dst, src, stream.SuiteMLKEM768, recipientPubKey,
    stream.DefaultChunkSize)
rec := stream.NewBrokerCEKRecovery(client, "app.kem_key", stream.SuiteMLKEM768)
err = stream.DecryptMLKEM(ctx, out, encrypted, rec)
// ...or stream.NewLocalSeedCEKRecovery(seed, suite) for tests/tools that hold
// the raw 64-byte seed.
```

Suites: `SuiteAES256GCM`, `SuiteChaCha20Poly1305`, `SuiteMLKEM512`,
`SuiteMLKEM768`, `SuiteMLKEM1024` (ML-KEM suites seal chunks with AES-256-GCM).
Cross-language interop with the Rust reference is proven both directions by the
gated `-tags interop` tests against the `stream_cli` example (see **Tests**).

## Secrets (KV)

```go
sec, err := client.GetSecret(ctx, "app.db_password", nil) // nil = latest version
ver, err := client.SetSecret(ctx, "app.db_password", []byte("new"))
ver, err = client.RotateSecret(ctx, "app.db_password")
entries, err := client.ListCatalog(ctx, nil)              // nil = no prefix filter
```

`ListCatalog` drains the broker's server stream into a `[]basil.CatalogEntry`.

## Minting and certificate issuance

Minting takes auditable request structs and returns a `*basil.Credential`
(`Token` plus an `ExpiresAt` that is the zero time when non-expiring):

```go
cred, err := client.MintJwt(ctx, basil.JwtRequest{
    KeyID:   "app.signing",
    Subject: "svc-a",
    TTL:     15 * time.Minute,                  // zero mints a non-expiring token
    Claims:  map[string]any{"scope": "orders:read"},
})
```

`MintNatsUser` / `MintNatsAccount` / `MintNatsOperator` / `MintNatsSigner` /
`MintNatsServer` / `MintNatsCurve` mint NATS JWTs, `SignNatsJwt` validates
and signs a caller-built NATS claim document, `ValidateNatsJwt` verifies a
presented token against catalog keys or raw public NKeys, and
`EncryptNatsCurve` / `DecryptNatsCurve` use custodied xkeys for NATS `xkv1`
boxes.

`SignNatsJwt` sends the full claim object as raw JSON bytes so integer-valued
claims are not converted through protobuf doubles. `NatsJwtRequest.Claims` may
be a map, struct, `json.RawMessage`, `[]byte`, or JSON string. If you decode
arbitrary claim JSON into `map[string]any` first, use `json.Decoder.UseNumber`
to avoid converting large integers to `float64` before the client sees them.

`IssueCertificate` returns a `*basil.Certificate`, the one RPC that releases
private key material, because a TLS server needs the leaf private key it just
minted:

```go
cert, err := client.IssueCertificate(ctx, basil.CertificateRequest{
    IssuerKeyID: "web.tls.cert_issuer",
    CommonName:  "svc.example.org",
    DNSSANs:     []string{"svc.example.org"},
    TTL:         24 * time.Hour,
})
// cert.CertChainDER, cert.PrivateKeyDER, cert.CAChainDER
```

## Status, health, readiness

```go
st, err := client.Status(ctx)     // backend, version, protocol
h, err := client.Health(ctx)      // cheap liveness; never touches a backend
r, err := client.Readiness(ctx)   // can the broker actually serve? (non-secret summary)
```

## Operator surfaces (reload, explain, revoke, watch)

These are permission-gated admin RPCs; each needs its own dedicated grant (no
data-plane permission implies them).

```go
// Hot-reload the catalog/policy generation FROM DISK (the call carries no
// config, taken from the broker's on-disk paths only). Pass
// check=true for a dry-run that validates without swapping.
res, err := client.Reload(ctx, false)   // *basil.ReloadResult; res.Rejection != nil on a validation/routing reject

// Explain a live policy decision against the serving generation. The first
// argument is the policy subject to evaluate, not a uid/gid or principal
// expression.
ex, err := client.Explain(ctx, "svc.app", "sign", "app.signing")  // *basil.ExplainResult (Decision "allow"/"deny")

// Revoke a JWT-SVID by (trust domain, jti); needs a configured
// revocation_store=jwt-svid backing key so it survives restart.
rv, err := client.Revoke(ctx, "example.org", jti, expiresAtUnix)  // *basil.RevokeResult
```

`Watch` opens a server-stream of change events (key rotations, bundle changes,
revocations). Pass zero `EventKind`s for all kinds, or filter. Unlike the unary
RPCs the stream is **not** bounded by the default per-RPC timeout; the caller
owns it and must `Close` it. Consume it with the range-over-func iterator or a
`Recv` loop:

```go
stream, err := client.Watch(ctx, basil.EventKindKeyRotated)
defer stream.Close()

for ev, err := range stream.Events() {   // iterator: io.EOF / clean close ends it without an error
    if err != nil { /* handle */ break }
    switch ev.Kind {
    case basil.EventKindKeyRotated:
        log.Printf("rotated %s -> v%d", ev.KeyRotated.KeyID, ev.KeyRotated.NewVersion)
    }
}
// ...or the lower-level form: for { ev, err := stream.Recv(); if err == io.EOF { break }; ... }
```

## SPIFFE Workload API

Basil implements the open [SPIFFE](https://spiffe.io) Workload API, so a
workload fetches its own X.509-SVID and JWT-SVIDs over the same agent socket.
The `spiffe` subpackage wraps the reference
[go-spiffe](https://github.com/spiffe/go-spiffe) client: it attaches the
mandatory `workload.spiffe.io: true` request header, parses SVIDs into typed
values, and manages rotation. It is a **separate package** so a workload using
only the broker data plane does not link the go-spiffe dependency tree.

```go
import "github.com/openbasil/basil-go/spiffe"

c, err := spiffe.Dial(ctx, "/run/basil/agent.sock")
if err != nil {
    return err
}
defer c.Close()

svid, err := c.FetchX509SVID(ctx)          // *x509svid.SVID: ID, chain, private key
jwt, err := c.FetchJWTSVID(ctx, audience)  // *jwtsvid.SVID: token, claims, expiry
v, err := c.ValidateJWTSVID(ctx, token, audience)
bundles, err := c.FetchX509Bundles(ctx)    // peer-verification trust bundles
```

The X.509-SVID legitimately includes the workload's **own** private key, the
one exception to Basil's keys-stay-in-the-vault rule, exactly as the SPIFFE
standard requires for the workload's own identity.

SVIDs rotate before they expire. For a long-running workload, use a
rotation-aware source instead of a one-shot fetch: it keeps the freshest leaf
in the background and plugs straight into go-spiffe's mTLS `tlsconfig`:

```go
src, err := spiffe.NewX509Source(ctx, "/run/basil/agent.sock")
if err != nil {
    return err
}
defer src.Close()
tlsCfg := tlsconfig.MTLSServerConfig(src, src, tlsconfig.AuthorizeAny())
```

`spiffe.NewJWTSource` is the JWT analogue; `(*spiffe.Client).WatchX509Context`
exposes the raw rotation stream when you need to react to each update yourself.
`(*spiffe.Client).Workload()` returns the underlying go-spiffe client for
advanced use (a JWT-SVID for a specific subject SPIFFE ID, the WIT-SVID surface).

> **Design decision.** We wrap go-spiffe's `workloadapi` client (option *a*)
> rather than generating thin stubs from the proto (option *b*), because Basil's
> Workload API is wire-compatible with the standard: the proto declares the
> standard `SpiffeWorkloadAPI` service (no package, so the full service name and
> method set match), and go-spiffe sets the required `workload.spiffe.io` header
> and parses/validates SVIDs and bundles for us. The only Basil-specific wiring
> is the `unix://` endpoint address and a pinned HTTP/2 `:authority`.

## Errors

A broker rejection (data plane **or** SPIFFE Workload API) is returned as a
typed `*basil.StatusError`:

```go
sig, err := client.Sign(ctx, keyID, msg)
if se, ok := basil.AsStatusError(err); ok {
    // se.Code is the canonical gRPC code (codes.PermissionDenied, ...)
    // se.Reason / se.Op are the broker's machine-readable detail
    //   (for example "UNAUTHORIZED" / "sign"), empty if not supplied.
    log.Printf("denied: %s op=%s code=%s", se.Reason, se.Op, se.Code)
}
```

`StatusError` works with `errors.As` and with `google.golang.org/grpc/status`'s
`status.Code` / `status.Convert`. `Reason`/`Op` are decoded from the broker's
`BrokerErrorInfo` status detail. `basil.FromError(err)` normalizes any gRPC
error into a `*basil.StatusError` (used for errors from the raw go-spiffe client
returned by `(*spiffe.Client).Workload()`).

The full error model is documented in [docs/errors.md](docs/errors.md):
status-code/reason mapping, retry/reconnection guidance, and SPIFFE-specific
failure modes (no SVID, denied resource, socket unavailable, rotation gap).

## Example command

`cmd/basil-sign` is a runnable example:

```sh
go run ./cmd/basil-sign -socket /tmp/basil.sock -key web.tls.signing_key -message hello
```

## Regenerating the gRPC stubs

The generated stubs (`internal/pb/*.pb.go`) are checked in, so consumers need no
`protoc`. Regenerate only when
`crates/basil-proto/proto/basil/broker/v1/broker.proto` changes:

```sh
GOPLUG="$(nix build --no-link --print-out-paths \
  nixpkgs#protoc-gen-go nixpkgs#protoc-gen-go-grpc | sed 's,$,/bin,' | paste -sd:)"
PATH="$GOPLUG:$PATH" scripts/gen-proto.sh
```

`broker.proto` carries no `option go_package` (it is consumed by the Rust
build); the Go package is supplied entirely via `protoc --go_opt=M…` mappings,
so the Rust build is never perturbed.

## Tests

```sh
go test ./...          # unit tests; the live interop test skips when BASIL_SOCKET is unset
```

Unit tests run an in-process gRPC server over a real Unix socket and cover
request building, response mapping, error decoding, the dialer, and timeouts.
No live agent required. The `stream` package tests are fully self-contained
(round-trips for all five suites over multi-chunk payloads plus fail-closed
cases); they need neither an agent nor a broker.

The streaming **cross-language interop** test proves the Go container is
byte-identical to the Rust `basil::stream`. It is gated behind the `interop`
build tag and the path to the Rust reference CLI:

```sh
cargo build -p basil --example stream_cli   # from the repo root
BASIL_STREAM_RUST_CLI="$PWD/target/debug/examples/stream_cli" \
  go test -tags interop -run Interop ./stream/...
```

It drives both directions (Go-encrypt → Rust-decrypt and Rust-encrypt →
Go-decrypt) for AES-256-GCM and ChaCha20-Poly1305, and a best-effort ML-KEM-768
round-trip in both directions.

The interop tests round-trip against a **live** `basil-agent` and are gated on
`BASIL_SOCKET` (they skip when it is unset). Boot an agent and run them end to
end with:

```sh
scripts/interop-agent.sh
```

which builds `basil`, boots a dev OpenBao backend, provisions the fixtures,
launches the agent on a socket, and runs every `Interop` test:

- `TestInteropSignVerify`: sign/verify/get-public-key, including an independent
  `crypto/ed25519` verification of a broker-produced signature.
- `TestInteropAEAD`: AEAD encrypt/decrypt round trip on `app.aead` (broker-owned
  nonce), with an AAD-mismatch negative.
- `TestInteropStatus`: `Status` + `Health` agree on the broker version.
- `TestInteropSecret`: read `app.db_password`, then a set/rotate version cycle.
- `TestInteropIssueCertificate`: issue an X.509 leaf from `web.tls.cert_issuer`.
- `TestInteropSPIFFE` (in `./spiffe`): fetch a real X.509-SVID and JWT-SVID,
  validate the JWT-SVID, and fetch the X.509/JWT trust bundles, all over the
  agent socket. The agent must be built with the `spiffe` feature (it is in the
  default set) and the prefill provisions the SPIFFE issuers
  (`spiffe.x509_issuer`, `spiffe.jwt_issuer`, trust domain `example.org`). It is
  gated on `BASIL_SOCKET`; override the expected trust domain / requested
  audience with `BASIL_SPIFFE_TRUST_DOMAIN` / `BASIL_SPIFFE_AUDIENCE`.

The catalog ids default to the `scripts/prefill-test-store.sh` fixtures; override
them via `BASIL_KEY_ID` / `BASIL_AEAD_KEY_ID` / `BASIL_SECRET_ID` /
`BASIL_CERT_ISSUER_ID`. Or point the tests at an already-running agent:

```sh
BASIL_SOCKET=/path/to/agent.sock go test -run Interop -v ./...
```

## Layout

- `client.go`: `Client`, `Dial`, options, Unix-socket transport, sub-clients.
- `signing.go`: `Sign` / `Verify` / `GetPublicKey` and the `PublicKey` type.
- `aead.go`: `Encrypt` / `Decrypt` / `WrapEnvelope` / `UnwrapEnvelope`, the
  `Ciphertext` / `KemEnvelope` types, and the AEAD/KEM/envelope enums.
- `secret.go`: `GetSecret` / `SetSecret` / `RotateSecret` / `ListCatalog`, the
  `Secret` / `CatalogEntry` types, and the `CatalogKind` enum.
- `minting.go`: `MintJwt`, the NATS minters, `SignNatsJwt`,
  `ValidateNatsJwt`, `EncryptNatsCurve` / `DecryptNatsCurve`,
  `IssueCertificate`, the request structs, and the `Credential` /
  `Certificate` types. NATS calls route to the broker `NatsService`.
- `admin.go`: `Status` / `Health` / `Readiness` and their result types.
- `stream/`: streaming/file encryption (`EncryptAEAD` / `DecryptAEAD` /
  `EncryptMLKEM` / `DecryptMLKEM`, the `Suite` ids, `CEKSource`, and the
  `CEKRecovery` seam). Byte-identical to the Rust `basil::stream`; isolated from
  the lean root package so it alone carries the post-quantum crypto deps.
- `keytype.go`: `KeyType` and `SigningAlgorithm` enums.
- `errors.go`: `StatusError`, `FromError`, and broker-detail decoding.
- `spiffe/`: SPIFFE Workload API helpers (`Dial`, `FetchX509SVID` /
  `FetchJWTSVID` / `Validate` / bundles, `NewX509Source` / `NewJWTSource`,
  `Watch*`). Wraps go-spiffe; isolated from the lean root package.
- `docs/errors.md`: the end-to-end error model.
- `cmd/basil-sign/`: example command.
- `internal/pb/`: generated gRPC stubs (checked in).
- `scripts/`: `gen-proto.sh` (codegen) and `interop-agent.sh` (live boot).
