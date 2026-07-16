#!/usr/bin/env bash
# Boot a live basil-agent against a dev backend, then run the Go interop tests
# (every `go test -run Interop`: signing, AEAD, status/health, secrets, and
# certificate issuance) against it and tear everything down.
#
# This reuses scripts/prefill-test-store.sh, which builds `basil`
# (--features pqc), starts an OpenBao dev server, and provisions all the
# fixtures the interop tests use: the transit Ed25519 key web.tls.signing_key,
# the AEAD key app.aead, the KV secret app.db_password, and the pki issue role
# web.tls.cert_issuer, plus the agent config + sealed bundle. We then launch
# `basil agent` on the fixture socket and run `go test -run Interop` with
# BASIL_SOCKET pointed at it.
#
# Usage:
#   scripts/interop-agent.sh [--engine openbao|vault] [--keep]
#
#   --keep   leave the backend + agent running after the test (prints how to
#            stop them); otherwise everything is torn down on exit.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${GO_ROOT}/../.." && pwd)"

ENGINE="openbao"
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --engine) ENGINE="$2"; shift 2 ;;
    --keep)   KEEP=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

WORKDIR="$(mktemp -d /tmp/basil-go-interop.XXXXXX)"
ADDR="http://127.0.0.1:8222"
SOCKET="${WORKDIR}/agent.sock"
AGENT_CONFIG="${WORKDIR}/fixtures/basil-agent.toml"
SERVER_PIDFILE="${WORKDIR}/server.pid"
AGENT_BIN="${REPO_ROOT}/target/debug/basil"
AGENT_PID=""

cleanup() {
  if [ "${KEEP}" -eq 1 ]; then
    echo
    echo "[--keep] left running:"
    echo "  agent  pid ${AGENT_PID}  socket ${SOCKET}"
    echo "  server pid $(cat "${SERVER_PIDFILE}" 2>/dev/null || echo '?')  addr ${ADDR}"
    echo "  stop: kill -INT ${AGENT_PID}; kill -INT \$(cat ${SERVER_PIDFILE})"
    return
  fi
  [ -n "${AGENT_PID}" ] && kill -INT "${AGENT_PID}" 2>/dev/null || true
  [ -f "${SERVER_PIDFILE}" ] && kill -INT "$(cat "${SERVER_PIDFILE}")" 2>/dev/null || true
  sleep 0.5
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

echo "== step 1: prefill backend + fixtures (engine=${ENGINE}, workdir=${WORKDIR})"
bash "${REPO_ROOT}/scripts/prefill-test-store.sh" \
  --engine "${ENGINE}" \
  --workdir "${WORKDIR}" \
  --addr "${ADDR}" \
  --token root

echo "== step 2: launch basil agent on ${SOCKET}"
"${AGENT_BIN}" agent \
  --config "${AGENT_CONFIG}" \
  >"${WORKDIR}/agent.log" 2>&1 &
AGENT_PID=$!

echo "== step 3: wait for the socket"
for _ in $(seq 1 100); do
  [ -S "${SOCKET}" ] && break
  if ! kill -0 "${AGENT_PID}" 2>/dev/null; then
    echo "FATAL: agent exited early; log:" >&2
    cat "${WORKDIR}/agent.log" >&2
    exit 1
  fi
  sleep 0.1
done
[ -S "${SOCKET}" ] || { echo "FATAL: socket never appeared" >&2; cat "${WORKDIR}/agent.log" >&2; exit 1; }
echo "   socket ready"

echo "== step 4: run Go interop test"
( cd "${GO_ROOT}" && BASIL_SOCKET="${SOCKET}" BASIL_KEY_ID="web.tls.signing_key" \
    go test -run Interop -v ./... )

echo "== interop test passed"
