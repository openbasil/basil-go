#!/usr/bin/env bash
# Regenerate the Go gRPC stubs for the Basil broker contract.
#
# The generated *.pb.go / *_grpc.pb.go files are checked into the repo under
# internal/pb, so consumers do not need protoc. Re-run this script only when the
# vendored proto/basil/broker/v1/broker.proto changes (see proto/UPSTREAM.md for
# how it is synced from the openbasil/basil server repo).
#
# Requirements:
#   * protoc on PATH (provides the well-known-type includes).
#   * protoc-gen-go and protoc-gen-go-grpc on PATH. In this repo's Nix shell:
#       GOPLUG="$(nix build --no-link --print-out-paths \
#         nixpkgs#protoc-gen-go nixpkgs#protoc-gen-go-grpc \
#         | sed 's,$,/bin,' | paste -sd:)"
#       PATH="$GOPLUG:$PATH" scripts/gen-proto.sh
#
# Notes on mappings:
#   * broker.proto has NO `option go_package` (it is consumed by the Rust
#     build, which must not be perturbed). The Go package is supplied entirely
#     via --go_opt=M.../--go-grpc_opt=M... module-relative mappings here.
#   * google/rpc/status.proto is mapped to the genproto module rather than
#     regenerated locally (defensive: broker.proto references it only in prose).
#   * The google/protobuf/* well-known types are auto-mapped by protoc-gen-go
#     to google.golang.org/protobuf/types/known/*; we only add protoc's bundled
#     include dir to -I so the imports resolve.
set -euo pipefail

GO_MODULE="github.com/openbasil/basil-go"
PB_IMPORT="${GO_MODULE}/internal/pb"

# This client's Go module root is the parent of scripts/. The .proto source is
# vendored in-repo under proto/ (see proto/UPSTREAM.md), so regeneration needs
# only this repo plus protoc -- no checkout of the server repo.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROTO_ROOT="${GO_ROOT}/proto"
PROTO_FILE="basil/broker/v1/broker.proto"

# protoc's bundled well-known-type includes live next to the binary.
PROTOC_BIN="$(readlink -f "$(command -v protoc)")"
WKT_INCLUDE="$(dirname "$(dirname "${PROTOC_BIN}")")/include"

for tool in protoc-gen-go protoc-gen-go-grpc; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "error: ${tool} not on PATH (see header for the nix build incantation)" >&2
    exit 1
  }
done

OUT_DIR="${GO_ROOT}"
mkdir -p "${OUT_DIR}/internal/pb"

protoc \
  -I "${PROTO_ROOT}" \
  -I "${WKT_INCLUDE}" \
  --go_out="${OUT_DIR}" \
  --go_opt=module="${GO_MODULE}" \
  --go_opt=M"${PROTO_FILE}"="${PB_IMPORT}" \
  --go_opt=Mgoogle/rpc/status.proto=google.golang.org/genproto/googleapis/rpc/status \
  --go-grpc_out="${OUT_DIR}" \
  --go-grpc_opt=module="${GO_MODULE}" \
  --go-grpc_opt=M"${PROTO_FILE}"="${PB_IMPORT}" \
  --go-grpc_opt=Mgoogle/rpc/status.proto=google.golang.org/genproto/googleapis/rpc/status \
  "${PROTO_ROOT}/${PROTO_FILE}"

echo "generated stubs under ${OUT_DIR}/internal/pb"
