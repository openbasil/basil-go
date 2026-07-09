# cose-nats-telemetry (Go)

> **Basil is a host-local secrets broker: your app never touches the key.** The kernel attests who's
> calling, a default-deny policy decides, the key is used where it lives (OpenBao/Vault, KMS, or a
> sealed local store), and every operation is audited.

Two services exchange **COSE-signed telemetry over NATS** using nothing but
Basil-minted leases and in-place signatures. No NKey seed and no signing key ever
leaves the vault.

## Why this matters

This is the **Identity + Leases + Secrets** pillars working together on a real
message bus:

- **Leases, not standing credentials.** Basil mints the whole NATS trust chain
  (operator, account, and a short-lived **user** JWT) in place. The workload
  connects with that user lease; when it expires, the authority is simply gone.
  Nothing durable is baked into the image or config.
- **The NKey seed never leaves the vault.** NATS authenticates a client by having
  it sign a server-issued nonce with its user NKey. Here the signature callback
  routes that nonce through the broker's `Sign` RPC on the user's custodied NKey,
  so the seed is used in place and never released. A connecting client proves its
  identity without ever holding its own key.
- **End-to-end message authenticity with COSE.** The publisher signs each
  telemetry payload as a bare `COSE_Sign1` (RFC 9052) via `veraison/go-cose`,
  backed by a remote signer that calls the broker: the Ed25519 signing key stays
  in the vault. The subscriber verifies against the broker's *published public
  key* and asserts payload equality; a tampered message is rejected. Transport
  auth (NATS) and message auth (COSE) are independent layers, so a compromised
  broker-to-service hop still cannot forge a telemetry record.

This example is deliberately different from the
[`nats-cose-courier`](../nats-cose-courier) demo, which showcases **sealed
invocations via the `basil-nats-bridge`**. Here there is no bridge: two directly
connected NATS clients exchange bare `COSE_Sign1` application messages, with Basil
supplying the credentials and the in-place signatures.

## How it runs

`run.sh` wires the pieces in order because an operator-mode `nats-server` must be
configured from the minted JWTs before any client can connect:

1. Boot OpenBao + a `basil agent` holding four catalog keys: the operator,
   account, and user NKeys (`ed25519-nkey`) and an Ed25519 COSE signing key.
2. `EXAMPLE_MODE=provision` mints the operator -> account -> user chain via the Go
   client and writes the JWTs.
3. `run.sh` starts `nats-server` in **operator mode** with a **memory resolver**
   preloaded with the account JWT.
4. `EXAMPLE_MODE=telemetry` connects two authenticated clients (publisher +
   subscriber), signs a telemetry payload as `COSE_Sign1` through the broker,
   verifies it on the subscriber, and proves a tampered message is rejected.

## What it proves (assertions)

`run.sh` exits `0` only when it observes:

- `PASS minted operator/account/user …`: the full credential chain is minted.
- `PASS nats connect authenticated via minted user JWT + in-place nonce signing`:
  the connection succeeds with the seed staying in the vault.
- `PASS cose_sign1 built …` and `PASS subscriber verified cose_sign1 and payload
  matches`: the round-trip verifies against the broker's published public key.
- `PASS subscriber rejected tampered cose_sign1`. One flipped byte fails
  verification.

## Prerequisites

- [`bao`](https://openbao.org) (OpenBao) or [`vault`](https://developer.hashicorp.com/vault), and
  [`nats-server`](https://nats.io) on `PATH`.
- `go` on `PATH`.
- `basil` on `PATH` (or `BASIL_BIN` pointing at a prebuilt binary). If it is missing, `run.sh` points to the latest release at
  <https://github.com/openbasil/basil/releases>.

## Run it

```bash
./run.sh
```

Default ports: OpenBao `8232` (`BAO_PORT`), `nats-server` `4250` (`NATS_PORT`).
`run.sh` tears down every process it started, even on failure.

## Expected output

```
PASS minted operator O=OBF4BZ3EVVA6...
PASS minted account A=AA3PZYQWMMQS... (lease exp=never)
PASS minted user U=UBPDDE72QTXH... (lease exp=2026-07-03T20:56:45Z)
PASS nats connect authenticated via minted user JWT + in-place nonce signing
PASS cose_sign1 built bytes=156
PASS subscriber verified cose_sign1 and payload matches
PASS subscriber rejected tampered cose_sign1
== OK: cose-nats-telemetry example passed all assertions
```

## Rough edge (worth knowing)

The account JWT is minted with `SignNatsJwt`, not `MintNatsAccount`. An
operator-mode `nats-server` enforces account limits. `MintNatsAccount` now emits
an **unlimited** `nats.limits` block by default (`-1` connection/subscription
limits, matching a standard `nsc` account), so it accepts clients; earlier it
emitted no limits block, which the server reads as *zero* connections and the
account could accept none. That deny-all default was fixed in br `basil-1qvt`.
This example still uses `SignNatsJwt` to attach an explicit limits block, since
`MintNatsAccount` takes no limits parameter. The operator and user JWTs need no
special handling (`MintNatsOperator` / `MintNatsUser` are used directly; the user
JWT already carries `-1` limits).

## Related examples

- [`nats-cose-courier`](../nats-cose-courier): sealed invocations over the
  `basil-nats-bridge` (the other COSE-over-NATS pattern).
- [`secrets-and-aead`](../secrets-and-aead) and
  [`stream-file-encryption`](../stream-file-encryption): the KV/AEAD and
  streaming data planes.
