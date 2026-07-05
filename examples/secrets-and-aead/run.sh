#!/usr/bin/env bash
# run.sh: boot OpenBao + a Basil agent, provision a KV-v2 secret and an AEAD
# key, run the secrets-and-aead example, and assert every proven property.
#
# Exit 0 only when all assertions pass. Honors BASIL_BIN (a prebuilt `basil`);
# falls back to `cargo build` from the repo root when it is unset.
#
# Env overrides (all optional):
#   SECRETS_AEAD_WORKDIR   scratch dir           (default /tmp/basil-secrets-aead)
#   BASIL_BIN              prebuilt basil binary (default: cargo build)
#   BAO_PORT               OpenBao dev port      (default 8230)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${GO_ROOT}/../.." && pwd)"

WORKDIR="${SECRETS_AEAD_WORKDIR:-/tmp/basil-secrets-aead}"
BAO_PORT="${BAO_PORT:-8230}"
ADDR="http://127.0.0.1:${BAO_PORT}"
TOKEN="root"

FIXTURES="${WORKDIR}/fixtures"
CATALOG="${FIXTURES}/catalog.json"
POLICY="${FIXTURES}/policy.json"
BUNDLE="${FIXTURES}/bundle.sealed"
PASS_FILE="${FIXTURES}/passphrase.txt"
TOKEN_FILE="${FIXTURES}/bao-token.txt"
AGENT_CONFIG="${FIXTURES}/agent.toml"
SOCKET="${WORKDIR}/agent.sock"
BAO_LOG="${WORKDIR}/openbao.log"
AGENT_LOG="${WORKDIR}/agent.log"

BAO_PID=""
AGENT_PID=""

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }

cleanup() {
  local pids="${AGENT_PID} ${BAO_PID}"
  # Dev servers (bao) ignore a plain SIGTERM; SIGINT stops them cleanly.
  for pid in ${pids}; do [ -n "${pid}" ] && kill -INT "${pid}" 2>/dev/null || true; done
  sleep 0.3
  for pid in ${pids}; do [ -n "${pid}" ] && kill -KILL "${pid}" 2>/dev/null || true; done
}
trap cleanup EXIT

resolve_basil_bin() {
  if [ -n "${BASIL_BIN:-}" ]; then
    [ -x "${BASIL_BIN}" ] || { echo "BASIL_BIN=${BASIL_BIN} is not executable" >&2; exit 1; }
    echo "== using prebuilt basil: ${BASIL_BIN}"
    return
  fi
  echo "== BASIL_BIN unset; building basil via cargo (repo root ${REPO_ROOT})"
  ( cd "${REPO_ROOT}" && cargo build -p basil-bin --features pqc )
  BASIL_BIN="${REPO_ROOT}/target/debug/basil"
  [ -x "${BASIL_BIN}" ] || { echo "cargo build did not produce ${BASIL_BIN}" >&2; exit 1; }
}

write_catalog() {
  cat >"${CATALOG}" <<JSON
{
  "schemaVersion": 1,
  "backends": {
    "bao": {
      "kind": "vault",
      "addr": "${ADDR}",
      "engines": ["transit", "kv2"]
    }
  },
  "keys": {
    "app.session_token": {
      "class": "value", "backend": "bao", "engine": "kv2",
      "path": "secret/data/example/session-token",
      "writable": true, "missing": "warn",
      "generate": { "format": "base64", "bytes": 32 },
      "description": "KV-v2 session token; SetSecret writes versions, RotateSecret mints a fresh generated value."
    },
    "app.aead": {
      "class": "symmetric", "keyType": "aes-256-gcm", "backend": "bao",
      "engine": "transit", "path": "app-aead",
      "writable": true, "missing": "generate",
      "description": "AES-256-GCM AEAD key; the broker owns the nonce on every encrypt."
    }
  }
}
JSON
}

write_policy() {
  local uid; uid="$(id -u)"
  cat >"${POLICY}" <<JSON
{
  "schemaVersion": 2,
  "roles": {
    "reader":   ["get", "list", "get_public_key"],
    "operator": ["set", "rotate", "import", "new_key"],
    "crypter":  ["encrypt", "decrypt"]
  },
  "subjects": {
    "local": { "allOf": [ { "kind": "unix", "uid": ${uid} } ] }
  },
  "rules": [
    { "id": "secret-rw", "subjects": ["local"], "action": ["role:reader", "role:operator"], "target": ["app.session_token"] },
    { "id": "aead-crypt", "subjects": ["local"], "action": ["role:crypter"], "target": ["app.aead"] }
  ],
  "config": {
    "names": { "users": { "${uid}": "local" }, "groups": {} },
    "memberships": { "${uid}": [] }
  }
}
JSON
}

main() {
  need bao
  need go
  resolve_basil_bin

  rm -rf "${WORKDIR}"
  mkdir -p "${FIXTURES}"
  chmod 700 "${WORKDIR}"

  echo "== starting OpenBao dev server at ${ADDR}"
  bao server -dev -dev-root-token-id="${TOKEN}" -dev-listen-address="127.0.0.1:${BAO_PORT}" >"${BAO_LOG}" 2>&1 &
  BAO_PID="$!"
  for _ in $(seq 1 80); do
    VAULT_ADDR="${ADDR}" bao status >/dev/null 2>&1 && break
    kill -0 "${BAO_PID}" 2>/dev/null || { echo "OpenBao exited early:" >&2; cat "${BAO_LOG}" >&2; exit 1; }
    sleep 0.1
  done
  export VAULT_ADDR="${ADDR}" VAULT_TOKEN="${TOKEN}"
  bao status >/dev/null

  echo "== enabling transit + kv-v2"
  bao secrets enable transit >/dev/null 2>&1 || true
  bao secrets enable -path=secret -version=2 kv >/dev/null 2>&1 || true

  umask 077
  printf '%s\n' "${TOKEN}" >"${TOKEN_FILE}"
  printf 'secrets-and-aead-passphrase\n' >"${PASS_FILE}"

  write_catalog
  write_policy

  echo "== sealing the credential bundle (passphrase slot + OpenBao token cred)"
  "${BASIL_BIN}" bundle create "${BUNDLE}" \
    --slot "passphrase:file=${PASS_FILE}" \
    --backend "id=bao,type=openbao,token-file=${TOKEN_FILE},addr=${ADDR}" >/dev/null
  chmod 600 "${BUNDLE}"

  cat >"${AGENT_CONFIG}" <<TOML
catalog = "${CATALOG}"
policy = "${POLICY}"
bundle = "${BUNDLE}"
vault-addr = "${ADDR}"
socket = "${SOCKET}"

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

  echo "== running the example"
  OUT="${WORKDIR}/example.out"
  set +e
  ( cd "${SCRIPT_DIR}" && BASIL_SOCKET="${SOCKET}" \
      BASIL_SECRET_ID="app.session_token" BASIL_AEAD_KEY_ID="app.aead" \
      go run . ) | tee "${OUT}"
  status="${PIPESTATUS[0]}"
  set -e
  [ "${status}" -eq 0 ] || { echo "FAIL: example exited ${status}" >&2; exit 1; }

  echo "== asserting proven properties"
  assert() { grep -qF "$1" "${OUT}" || { echo "FAIL: missing assertion: $1" >&2; exit 1; }; }
  assert "PASS set app.session_token version="
  assert "PASS get app.session_token roundtrip version="
  assert "PASS rotate app.session_token version="
  assert "PASS version cycle "
  assert "PASS encrypt app.aead alg="
  assert "PASS decrypt roundtrip matching-aad"
  assert "PASS decrypt rejected mismatched-aad"

  echo "== OK: secrets-and-aead example passed all assertions"
}

main "$@"
