#!/usr/bin/env bash
# run.sh: boot a Basil agent on the zero-dependency db-keystore backend, start
# the Go web service against its socket, then prove both halves of the story:
# POST /token returns a broker-minted JWT, and the SAME uid is denied a plain
# read of the signing key.
#
# Exit 0 only when all assertions pass. Honors BASIL_BIN (a prebuilt `basil`),
# then `basil` on PATH; fails with install guidance when neither is present.
#
# Env overrides (all optional):
#   WEB_SERVICE_GO_WORKDIR  scratch dir           (default /tmp/basil-web-go)
#   WEB_SERVICE_GO_PORT     HTTP port             (default 8096)
#   BASIL_BIN               prebuilt basil binary (default: basil on PATH)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_URL="https://github.com/openbasil/basil/releases"

WORKDIR="${WEB_SERVICE_GO_WORKDIR:-/tmp/basil-web-go}"
PORT="${WEB_SERVICE_GO_PORT:-8096}"
KEY_ID="web.signing_key"

FIXTURES="${WORKDIR}/fixtures"
CATALOG="${FIXTURES}/catalog.json"
POLICY="${FIXTURES}/policy.json"
BUNDLE="${FIXTURES}/bundle.sealed"
PASS_FILE="${FIXTURES}/passphrase.txt"
DEK_FILE="${FIXTURES}/db-keystore-dek.bin"
DB_PATH="${FIXTURES}/keystore.db"
AGENT_CONFIG="${FIXTURES}/agent.toml"
SOCKET="${WORKDIR}/agent.sock"
AGENT_LOG="${WORKDIR}/agent.log"
SVC_LOG="${WORKDIR}/service.log"
SVC_BIN="${WORKDIR}/web-service"

AGENT_PID=""
SVC_PID=""

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }

need_basil() {
  if [ -n "${BASIL_BIN:-}" ]; then
    [ -x "${BASIL_BIN}" ] || { echo "BASIL_BIN=${BASIL_BIN} is not executable" >&2; exit 1; }
    echo "== using prebuilt basil: ${BASIL_BIN}"
    return
  fi
  if ! command -v basil >/dev/null 2>&1; then
    cat >&2 <<EOF
missing required Basil binary: basil

Install the latest Basil release from:
  ${INSTALL_URL}

Then set BASIL_BIN or make sure 'basil' is on PATH and rerun this script.
EOF
    exit 1
  fi
  BASIL_BIN="$(command -v basil)"
  echo "== using basil: ${BASIL_BIN}"
}

cleanup() {
  for pid in "${SVC_PID}" "${AGENT_PID}"; do
    [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
  done
}
trap cleanup EXIT

write_catalog() {
  cat >"${CATALOG}" <<JSON
{
  "schemaVersion": 1,
  "backends": {
    "local-db": {
      "kind": "keystore",
      "addr": "${DB_PATH}",
      "engines": ["transit"],
      "mintKeyTypes": ["ed25519"]
    }
  },
  "keys": {
    "${KEY_ID}": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "local-db",
      "engine": "transit", "path": "web/signing-key",
      "writable": true, "missing": "generate",
      "description": "Ed25519 JWT-signing key; the web service mints under it but never reads it."
    }
  }
}
JSON
}

write_policy() {
  local uid user; uid="$(id -u)"; user="$(id -un)"
  cat >"${POLICY}" <<JSON
{
  "schemaVersion": 2,
  "roles": {
    "token-minter": ["mint", "get_public_key"]
  },
  "subjects": {
    "web-service": { "domain": "host-process", "match": { "all": [ { "process.uid": ${uid} } ] } }
  },
  "rules": [
    {
      "id": "web-service-mints-only",
      "subjects": ["web-service"],
      "action": ["role:token-minter"],
      "target": ["${KEY_ID}"],
      "comment": "Mint + public key only. No get/sign: the same uid cannot read the key material."
    }
  ],
  "config": {
    "names": { "users": { "${uid}": "${user}" }, "groups": {} },
    "memberships": { "${uid}": [] }
  }
}
JSON
}

main() {
  need go
  need curl
  need_basil

  rm -rf "${WORKDIR}"
  mkdir -p "${FIXTURES}"
  chmod 700 "${WORKDIR}"

  echo "== scaffolding the db-keystore broker"
  umask 077
  printf 'web-service-go-passphrase\n' >"${PASS_FILE}"
  # The bundle DEK must be exactly 32 raw bytes; `bundle create` strips one
  # trailing newline/CR from secret files, so avoid those as the last byte.
  while :; do
    head -c 32 /dev/urandom >"${DEK_FILE}"
    last="$(tail -c 1 "${DEK_FILE}" | od -An -tu1 | tr -d ' ')"
    [ "${last}" != 10 ] && [ "${last}" != 13 ] && break
  done
  write_catalog
  write_policy
  "${BASIL_BIN}" bundle create "${BUNDLE}" \
    --slot "passphrase:file=${PASS_FILE}" \
    --backend "id=local-db,type=db-keystore,path=${DB_PATH},dek-file=${DEK_FILE}" >/dev/null

  cat >"${AGENT_CONFIG}" <<TOML
catalog = "${CATALOG}"
policy = "${POLICY}"
bundle = "${BUNDLE}"
socket = "${SOCKET}"
db-keystore-cipher = "aegis256"

[unlock]
unlock-passphrase-file = "${PASS_FILE}"
TOML

  echo "== launching basil agent on ${SOCKET}"
  "${BASIL_BIN}" agent --config "${AGENT_CONFIG}" >"${AGENT_LOG}" 2>&1 &
  AGENT_PID="$!"
  for _ in $(seq 1 120); do
    [ -S "${SOCKET}" ] && break
    kill -0 "${AGENT_PID}" 2>/dev/null || { echo "agent exited early:" >&2; cat "${AGENT_LOG}" >&2; exit 1; }
    sleep 0.1
  done
  [ -S "${SOCKET}" ] || { echo "socket never appeared:" >&2; cat "${AGENT_LOG}" >&2; exit 1; }

  echo "== building and starting the web service"
  ( cd "${SCRIPT_DIR}" && go build -o "${SVC_BIN}" . )
  BASIL_SOCKET="${SOCKET}" BIND_ADDR="127.0.0.1:${PORT}" BASIL_SIGNING_KEY_ID="${KEY_ID}" \
    "${SVC_BIN}" >"${SVC_LOG}" 2>&1 &
  SVC_PID="$!"
  for _ in $(seq 1 100); do
    curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 && break
    kill -0 "${SVC_PID}" 2>/dev/null || { echo "service exited early:" >&2; cat "${SVC_LOG}" >&2; exit 1; }
    sleep 0.1
  done
  curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null

  echo "== mint: POST /token returns a broker-signed JWT"
  token="$(curl -fsS -X POST "http://127.0.0.1:${PORT}/token")"
  echo "token: ${token}"
  # A compact JWT is exactly three dot-separated base64url segments.
  if [[ ! "${token}" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
    echo "FAIL: response is not a compact JWT: ${token}" >&2
    exit 1
  fi
  echo "PASS mint ${KEY_ID} token-shape=header.claims.signature"

  echo "== deny: the same uid may NOT read the key it mints under"
  set +e
  deny_out="$("${BASIL_BIN}" --socket "${SOCKET}" get --key-id "${KEY_ID}" 2>&1)"
  deny_status=$?
  set -e
  if [ "${deny_status}" -eq 0 ]; then
    echo "FAIL: 'basil get --key-id ${KEY_ID}' succeeded; expected PermissionDenied" >&2
    exit 1
  fi
  echo "${deny_out}" | grep -qiE 'permission[ _-]?denied|unauthorized' || {
    echo "FAIL: expected a PermissionDenied error, got: ${deny_out}" >&2
    exit 1
  }
  echo "PASS deny get ${KEY_ID}: ${deny_out}"

  echo "== OK: web-service example passed all assertions"
  echo "PASS"
}

main "$@"
