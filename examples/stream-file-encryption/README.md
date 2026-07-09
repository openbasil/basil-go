# stream-file-encryption (Go)

> **Basil is a host-local secrets broker: your app never touches the key.** The kernel attests who's
> calling, a default-deny policy decides, the key is used where it lives (OpenBao/Vault, KMS, or a
> sealed local store), and every operation is audited.

Encrypt a large file with Basil's streaming, chunked AEAD (`basil/stream`) and
prove it round-trips byte-for-byte: first with symmetric AES-256-GCM, then with
post-quantum ML-KEM-768 whose key stays custodied in the vault.

## Why this matters

Encrypting *files* is where nonce-reuse and truncation bugs usually creep in.
Basil removes both by construction:

- **Basil owns the container and every nonce.** The caller picks a suite and
  hands Basil an `io.Reader`/`io.Writer`; there is no caller-supplied nonce path
  to get wrong. Each chunk is sealed under a per-stream key with a counter nonce,
  and its AAD binds the format version, suite, a random per-stream id, the chunk
  index, a final-chunk marker, and the chunk length. Streams are therefore
  non-reorderable, non-truncatable, non-replayable, and non-downgradable. Any
  tampering **fails closed** (asserted here by flipping one ciphertext byte).
- **The private key never leaves the vault (post-quantum path).** The ML-KEM-768
  suite wraps a fresh content-encryption key against the recipient's public
  encapsulation key: encryption needs only the public key and never contacts the
  broker. Decryption recovers the CEK through the broker's `UnwrapEnvelope`; the
  ML-KEM *decapsulation* key is software-custodied and used in place. This is the
  **Secrets** pillar applied to bulk data, and a forward-looking hedge against
  "harvest now, decrypt later."

## Byte-identical interop with Rust

The container format is **wire-identical** to the Rust reference `basil::stream`
and is specified byte-for-byte in
[`docs/specs/streaming-encryption-format.md`](../../../../docs/specs/streaming-encryption-format.md)
(the normative cross-language spec). A file encrypted by this Go program decrypts
unchanged with the Rust client, and vice versa: the two implementations share
the same header layout, HKDF labels, per-chunk AAD, and ML-KEM envelope
encoding. The Go `stream` package's own interop tests exercise exactly this
against the Rust CLI.

## What it proves (assertions)

`run.sh` exits `0` only when the program prints:

- `PASS aes-256-gcm roundtrip byte-identical`: AES round-trip over a 4 MiB,
  multi-chunk file.
- `PASS ml-kem-768 provisioned key=…`: a custodied ML-KEM-768 key is minted via
  `NewKey` and its 1184-byte public encapsulation key fetched via `GetPublicKey`.
- `PASS ml-kem-768 roundtrip byte-identical broker-recovered-cek`: the CEK is
  recovered through the broker (`NewBrokerCEKRecovery`) and the file round-trips.
- `PASS tamper fails-closed ErrAuthFailed`: a single flipped byte is rejected.

## Prerequisites

- [`bao`](https://openbao.org) (OpenBao) or [`vault`](https://developer.hashicorp.com/vault) on `PATH`.
- `go` on `PATH`.
- `basil` on `PATH` (or `BASIL_BIN` pointing at a prebuilt binary). If it is missing, `run.sh` points to the latest release at
  <https://github.com/openbasil/basil/releases>.

## Run it

```bash
./run.sh
```

`run.sh` boots an OpenBao dev server (default port `8231`, override with
`BAO_PORT`), provisions the ML-KEM custody prerequisites (a transit wrap key and
the catalog/policy), launches `basil agent`, runs the example, and asserts the
output. It tears down everything it started, even on failure.

## Expected output

```
PASS input file bytes=4194304 chunk_size=65536
PASS aes-256-gcm encrypt multi-chunk
PASS aes-256-gcm roundtrip byte-identical
PASS ml-kem-768 provisioned key=app.stream_seal public_len=1184
PASS ml-kem-768 encrypt multi-chunk
PASS ml-kem-768 roundtrip byte-identical broker-recovered-cek
PASS tamper fails-closed ErrAuthFailed
== OK: stream-file-encryption example passed all assertions
```

## Related examples

- [`secrets-and-aead`](../secrets-and-aead): the single-shot KV + AEAD data
  plane.
- [`cose-nats-telemetry`](../cose-nats-telemetry): COSE-signed messaging over
  NATS with basil-minted leases.
