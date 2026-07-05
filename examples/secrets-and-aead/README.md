# secrets-and-aead (Go)

A guided tour of Basil's **KV + AEAD data plane** from the Go client: version a
KV-v2 secret and encrypt/decrypt a payload under a broker-owned key, without
the calling process ever holding the key.

## Why this matters

The whole point of Basil is that **secret material stays in the vault and is
used in place**. This example makes that concrete on the two most common data-
plane operations:

- **Versioned secrets, not sprawl.** `SetSecret` / `GetSecret` / `RotateSecret`
  move opaque bytes through a KV-v2 secret whose history the broker tracks. The
  application reads back exactly what it wrote, and a broker-side rotate mints a
  fresh generated value at a strictly higher version. Old readers pinned to an
  old version keep working while new writers advance.
- **AEAD with no nonce footgun.** `Encrypt` / `Decrypt` run against an
  AES-256-GCM key the broker owns. **Basil owns the nonce**, so there is no
  caller-supplied path to reuse or incorrectly generate one: the class of bug that
  silently destroys AES-GCM confidentiality is removed by construction. The
  additional-authenticated-data (AAD) is bound to the ciphertext but not
  encrypted; decrypting with a *different* AAD **fails closed**, which the
  example asserts.

Mapped to the Basil pillars, this is **Secrets** end to end: sign/verify aside,
these are the fetch/store/rotate and encrypt/decrypt operations Basil brokers so
that keys never leave the vault. Authorization is **least privilege**: the
policy grants read+write on the one secret and encrypt+decrypt on the one AEAD
key, nothing else.

## What it proves (assertions)

`run.sh` exits `0` only when the program prints every line below:

- `PASS set …` twice: two writes advance the KV version.
- `PASS get … roundtrip`: a read returns the exact bytes and version written.
- `PASS rotate …` + `PASS version cycle 1<2<3 rotated-value-differs`: rotate
  bumps the version and replaces the value with a freshly generated one.
- `PASS encrypt …` / `PASS decrypt roundtrip matching-aad`: AEAD round-trips.
- `PASS decrypt rejected mismatched-aad`: a wrong AAD is rejected.

## Prerequisites

- [`bao`](https://openbao.org) (OpenBao) on `PATH`: the storage backend.
- `go` on `PATH`: to build and run the example.
- A `basil` broker binary. `run.sh` uses `$BASIL_BIN` when set (a prebuilt
  binary); otherwise it builds one with `cargo` from the repo root.

## Run it

```bash
# With a prebuilt broker:
BASIL_BIN=/path/to/basil ./run.sh

# Or let it build basil from source:
./run.sh
```

`run.sh` boots an OpenBao dev server (default port `8230`, override with
`BAO_PORT`), provisions the catalog/policy, seals a credential bundle, launches
`basil agent`, runs the example against the agent socket, and asserts the output.
It cleans up every process it started, even on failure.

## Expected output

```
PASS set app.session_token version=1
PASS get app.session_token roundtrip version=1
PASS set app.session_token version=2
PASS rotate app.session_token version=3
PASS version cycle 1<2<3 rotated-value-differs
PASS encrypt app.aead alg=AEAD_ALGORITHM_AES_256_GCM ciphertext_len=73
PASS decrypt roundtrip matching-aad
PASS decrypt rejected mismatched-aad
== OK: secrets-and-aead example passed all assertions
```

## Related examples

- [`stream-file-encryption`](../stream-file-encryption): large-file AEAD and
  post-quantum ML-KEM envelope recovery through the broker.
- [`cose-nats-telemetry`](../cose-nats-telemetry): leases + in-place signatures
  over NATS.
