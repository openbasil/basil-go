# web-service (Go)

> **Basil is a host-local secrets broker: your app never touches the key.** The kernel attests who's
> calling, a default-deny policy decides, the key is used where it lives (OpenBao/Vault, KMS, or a
> sealed local store), and every operation is audited.

A minimal `net/http` token service that issues signed JWTs — **your app can't
leak a key it never held**.

## Why

The classic way a service signs tokens is to mount the signing key into the
process: a PEM file, a `JWT_SECRET` env var, a cloud credential. From that
moment every dependency, log line, and memory dump in the service is one hop
from the key. Basil inverts this: the Ed25519 key stays in the broker's
backend and the service asks Basil to **mint** the token via
`Client.MintJwt`. The service holds a socket path, nothing else. Compromise
the whole web process and there is still no key material to steal — the only
standing authority is "mint short-lived tokens under policy".

## What it demonstrates

1. **A keyless token endpoint**: `POST /token` calls `MintJwt` with the
   catalog id `web.signing_key`; the broker builds and signs the JWT in place
   and returns only the compact token (three base64url segments, which
   `run.sh` asserts).
2. **Attested, not configured, identity**: the broker authorizes the request
   by the service's kernel-verified uid (`SO_PEERCRED`); the service presents
   no API key or password.
3. **Least privilege, proven**: policy grants exactly `mint` +
   `get_public_key` on `web.signing_key`. `run.sh` then runs
   `basil get --key-id web.signing_key` under the **same uid** and asserts it
   fails with a typed `PermissionDenied` — minting under a key never implies
   reading it.

## Basil pillars

- **Attestation**: the policy subject matches the caller's `SO_PEERCRED` uid.
- **Secrets**: the signing operation is brokered; the key never crosses the
  socket.
- **Leases**: each token carries a 5-minute TTL — authority that expires on
  its own instead of a standing secret.
- **Least privilege**: `mint` and `get` are distinct grants; the deny half of
  the run proves an ungranted read fails closed.

## Prerequisites

- `go` and `curl` on `PATH`
- `basil` on `PATH` (or `BASIL_BIN` pointing at a prebuilt binary). If it is
  missing, `run.sh` points to the latest release at
  <https://github.com/openbasil/basil/releases>. Default builds include the
  zero-dependency `db-keystore` backend this example runs on — no OpenBao
  required.

## How to run

```bash
./run.sh
```

`run.sh` scaffolds a throwaway db-keystore broker (catalog, policy for your
uid, sealed bundle), launches `basil agent`, builds and starts the web service
with `BASIL_SOCKET` set, curls `POST /token`, and demonstrates the denial. It
cleans up every process it started, even on failure.

Environment overrides (all optional): `WEB_SERVICE_GO_WORKDIR` (default
`/tmp/basil-web-go`), `WEB_SERVICE_GO_PORT` (default `8096`), `BASIL_BIN`.

## Expected output

```
== mint: POST /token returns a broker-signed JWT
token: eyJhbGciOiJFZERTQSIsImtpZCI6...<snip>...VfmnDA
PASS mint web.signing_key token-shape=header.claims.signature
== deny: the same uid may NOT read the key it mints under
PASS deny get web.signing_key: Error: agent status [PermissionDenied/UNAUTHORIZED]: not authorized
== OK: web-service example passed all assertions
PASS
```

## See also

- [`examples/web-service-axum`](../../../../examples/web-service-axum): the
  same keyless token service in Rust/axum.
- [`secrets-and-aead`](../secrets-and-aead): the KV + AEAD data plane from the
  Go client.
- [`clients/go/README.md`](../../README.md): the full Go client surface,
  including `MintJwt` and the NATS minters.
