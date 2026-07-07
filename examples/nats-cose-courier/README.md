# nats-cose-courier (Go)

Send a Basil sealed invocation over NATS through `basil-nats-bridge`. The Go
client builds a signed and sealed `application/basil.sign-request`, publishes it
to the bridge subject, opens the broker's sealed response, and verifies the
returned Ed25519 signature locally.

## What it proves

`run.sh` exits `0` only when it observes:

- the request was carried by NATS to `basil-nats-bridge`;
- Basil accepted the sealed actor proof and decrypted the request;
- the broker signed the requested message with `workload.signing`;
- the Go client verified the sealed response and the returned signature.

## Prerequisites

- [`bao`](https://openbao.org) (or [`vault`](https://developer.hashicorp.com/vault)), [`nats-server`](https://nats.io), and `go` on
  `PATH`.
- `basil` and `basil-nats-bridge` on `PATH` (or `BASIL_BIN` / `BASIL_NATS_BRIDGE_BIN` overrides). If either is missing, `run.sh`
  points to the latest release at <https://github.com/openbasil/basil/releases>.

## Run it

```bash
./run.sh
```

Default ports: OpenBao `8233` (`BAO_PORT`), `nats-server` `4251`
(`NATS_PORT`). The bridge subject defaults to `basil.invoke.go`
(`BASIL_NATS_SUBJECT`). `run.sh` tears down every process it started, even on
failure.

## Expected output

```
PASS sealed sign invocation via basil-nats-bridge key=workload.signing policy_generation=... signature_len=64
== OK: nats-cose-courier example passed all assertions
```
