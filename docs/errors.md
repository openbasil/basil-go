# Error handling in the Basil Go client

This is the end-to-end error model for `github.com/openbasil/basil-go`
(the broker data plane) and its `spiffe` subpackage (the SPIFFE Workload API).
Both surfaces return the **same** typed error, so one handling path covers
everything.

## The shape: `*basil.StatusError`

Every broker rejection (signing, AEAD, secrets, minting, admin, and the SPIFFE
Workload API) comes back as a `*basil.StatusError`:

```go
type StatusError struct {
    Code    codes.Code // canonical gRPC status code
    Reason  string     // broker machine-readable token, e.g. "UNAUTHORIZED" ("" if absent)
    Op      string     // broker operation that failed, e.g. "sign" ("" if absent)
    Message string     // human-readable status message
}
```

- `Code` is the canonical [`google.golang.org/grpc/codes`] code.
- `Reason` and `Op` are decoded from the broker's `BrokerErrorInfo` status
  detail (a `google.rpc.Status` `Any`). They are empty when the broker attached
  no detail, for example a transport-level failure that never reached policy.
- `StatusError` implements `GRPCStatus()`, so `status.Code(err)` and
  `status.Convert(err)` recover the canonical code, and it works with
  `errors.As`.

### Matching errors

```go
sig, err := client.Sign(ctx, "app.signing", msg)

// Typed match (preferred):
if se, ok := basil.AsStatusError(err); ok {
    switch se.Reason {
    case "UNAUTHORIZED":
        // policy denied this caller for this key+op
    case "BACKEND_UNAVAILABLE":
        // the backend (OpenBao/Vault) is unreachable, retry with backoff
    }
}

// Or by canonical code, through the gRPC helpers:
if status.Code(err) == codes.PermissionDenied {
    // ...
}
```

`basil.FromError(err)` is the single normalizer: it turns any gRPC error
(including one returned verbatim by the go-spiffe client) into a
`*basil.StatusError`, decoding `BrokerErrorInfo` when present, and returns a
non-gRPC error (a client-side parse failure, a bare `context.DeadlineExceeded`)
unchanged. The broker sub-clients and the `spiffe` helpers already apply it, so
you normally only call it on errors from `(*spiffe.Client).Workload()` (the raw
go-spiffe client).

## gRPC status code ⇄ reason token

The broker maps every fault to a canonical code plus a stable `Reason` token:

| Reason                | Code                  | Meaning                                                        |
| --------------------- | --------------------- | -------------------------------------------------------------- |
| `INVALID_REQUEST`     | `InvalidArgument`     | Malformed/invalid input or a request that cannot be satisfied. |
| `DECRYPT_FAILED`      | `InvalidArgument`     | AEAD/decrypt failed (wrong key version, AAD, or ciphertext).   |
| `UNAUTHORIZED`        | `PermissionDenied`    | Policy denied this caller for this key + operation.            |
| `PAYLOAD_TOO_LARGE`   | `ResourceExhausted`   | Input exceeds the broker's size limit.                         |
| `UNSUPPORTED`         | `Unimplemented`       | Operation not supported by the backend/key.                    |
| `UNSUPPORTED_ALGORITHM` | `Unimplemented`     | Requested algorithm not supported by the key.                  |
| `BACKEND_UNAVAILABLE` | `Unavailable`         | The backend (OpenBao/Vault) is unreachable, **retryable**.     |
| `BACKEND_ERROR`       | `Internal`            | The backend returned an error.                                 |
| `INTERNAL`            | `Internal`            | Unexpected broker-internal fault.                              |

A transport failure that never reached the broker (socket missing, connection
refused) surfaces as `codes.Unavailable` with an empty `Reason`/`Op`, since no
`BrokerErrorInfo` is attached.

## Retry and reconnection guidance

The broker authenticates by `SO_PEERCRED` over a local Unix socket; there is no
token to refresh and no auth retry to perform. Retry decisions are about
*transport* and *backend* availability, not authorization.

- **Retryable:** `codes.Unavailable`, both `BACKEND_UNAVAILABLE` (the backend
  is down or sealed) and a bare transport `Unavailable` (the agent is starting
  up or the socket is not yet listening). Use bounded exponential backoff.
- **Not retryable without a change:** `PermissionDenied` (`UNAUTHORIZED`),
  `InvalidArgument`, `Unimplemented`, `ResourceExhausted`. Retrying sends the
  same denial; fix the policy grant, the input, or the key instead.
- **`Internal` / `BACKEND_ERROR`:** usually not worth a tight retry; log and
  surface. A single delayed retry is reasonable if the cause may be transient.

The connection is lazy and self-healing: one `Client`/`spiffe.Client` multiplexes
calls and gRPC re-establishes the underlying connection on the next call after a
drop, so you do not close and re-dial on a transient `Unavailable`. Just retry
the call. Always pass a `context` with a deadline (or rely on the client's
default timeout) so a stuck call cannot block forever.

## SPIFFE Workload API failure modes

The `spiffe` subpackage returns the same `*basil.StatusError`. The cases worth
handling explicitly:

- **No SVID / not entitled.** When policy does not grant the caller a mintable
  SVID for the requested issuer, the fetch fails `UNAUTHORIZED`
  (`PermissionDenied`). This is fail-closed and not retryable; grant the
  workload `mint` over the SPIFFE issuer key (`role:minter`).
- **Denied resource (validate).** `ValidateJWTSVID` requires a grant
  (`role:validator`) over the JWT issuer; absence is `UNAUTHORIZED`.
- **Socket unavailable.** A missing or not-yet-listening agent socket surfaces
  as `codes.Unavailable` on the first call. `Dial` itself is lazy and returns
  before the connection is proven, so the error appears at first use. Retry with
  backoff while the agent comes up.
- **Mandatory header.** The Workload API fail-closes any request lacking the
  `workload.spiffe.io: true` metadata header with `InvalidArgument`. This client
  injects the header automatically (via go-spiffe), so you should never see it;
  if you do, you are bypassing the helpers with a raw gRPC client.
- **Rotation gap.** SVIDs are short-lived and rotate before expiry. A one-shot
  `FetchX509SVID` returns the SVID valid *now*; it does not refresh. For a
  long-running workload use a rotation-aware source
  (`spiffe.NewX509Source` / `spiffe.NewJWTSource`) or `WatchX509Context`, which
  reconnect with backoff and keep the current SVID. Never cache a fetched SVID
  past its `NotAfter`; always read the freshest material from the source at use
  time.

## Verification semantics (`Verify`)

`SigningService.Verify` is the one call where a *negative result is not an
error*: `Verify` returns `(false, nil)` when the broker authoritatively rejects
a signature. A non-nil error means verification could not be performed at all
(denied, unknown key, transport failure) and is a `*basil.StatusError` as above.
Treat `(false, nil)` and `(_, err)` as distinct outcomes.
