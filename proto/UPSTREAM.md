# Vendored protobuf source

`basil/broker/v1/broker.proto` is the wire contract for the Basil broker. It is
the single source from which the checked-in Go stubs under `internal/pb/` are
generated (see `scripts/gen-proto.sh`).

**Upstream:** [`openbasil/basil`](https://github.com/openbasil/basil) at
`crates/basil-proto/proto/basil/broker/v1/broker.proto`.

This copy is vendored so the Go client is self-contained: generating the stubs
requires only this repo plus `protoc`, not a checkout of the server repo. It
imports only the `google/protobuf/*` well-known types that ship with `protoc`.

To sync after the contract changes upstream:

```sh
cp <basil-repo>/crates/basil-proto/proto/basil/broker/v1/broker.proto \
   proto/basil/broker/v1/broker.proto
scripts/gen-proto.sh   # regenerate internal/pb/
```
