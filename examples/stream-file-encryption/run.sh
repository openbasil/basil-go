#!/usr/bin/env bash
# run.sh boots OpenBao + a Basil agent with a custodied ML-KEM-768 sealing key,
# then run the stream-file-encryption example and assert every proven property.
#
# Exit 0 only when all assertions pass. Honors BASIL_BIN (a prebuilt `basil`);
# falls back to `cargo build` from the repo root when it is unset.
#
# Env overrides (all optional):
#   STREAM_FILE_WORKDIR   scratch dir           (default /tmp/basil-stream-file)
#   BASIL_BIN             prebuilt basil binary (default: cargo build)
#   BAO_PORT              OpenBao dev port      (default 8231)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${GO_ROOT}/../.." && pwd)"

WORKDIR="${STREAM_FILE_WORKDIR:-/tmp/basil-stream-file}"
BAO_PORT="${BAO_PORT:-8231}"
ADDR="http://127.0.0.1:${BAO_PORT}"
TOKEN="root"
KEM_KEY_ID="app.stream_seal"

FIXTURES="${WORKDIR}/fixtures"
CATALOG="${FIXTURES}/catalog.json"
POLICY="${FIXTURES}/policy.json"
BUNDLE="${FIXTURES}/bundle.sealed"
PASS_FILE="${FIXTURES}/passphrase.txt"
TOKEN_FILE="${FIXTURES}/bao-token.txt"
AGENT_CONFIG="${FIXTURES}/agent.toml"
SOCKET="${WORKDIR}/agent.sock"
DATA_DIR="${WORKDIR}/data"
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
    "app.stream_seal": {
      "class": "sealing", "keyType": "ml-kem-768", "backend": "bao",
      "engine": "kv2", "path": "secret/data/example/ml-kem-768",
      "publicPath": "secret/data/example/ml-kem-768-public",
      "writable": true, "missing": "warn",
      "labels": ["crypto_provider=local-software", "crypto_provider_policy=local-software", "pqc_custody=software-encrypted", "pqc_storage_key=stream-aead", "pqc_algorithm=ml-kem-768", "crypto_provider_version=1"],
      "description": "ML-KEM-768 software-custodied sealing key. NewKey mints the seed, AEAD-seals it under transit 'stream-aead', and records the public encapsulation key; the client wraps the CEK against that public and the broker recovers it via UnwrapEnvelope. The decapsulation key never leaves the vault."
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
  "rules": [
    {
      "id": "stream-seal",
      "subjects": ["local"],
      "action": ["op:new_key", "op:get_public_key", "op:encrypt", "op:decrypt", "op:use_software_custody"],
      "target": ["app.stream_seal"]
    }
  ],
  "subjects": {
    "local": { "allOf": [ { "kind": "unix", "uid": ${uid} } ] }
  },
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
  mkdir -p "${FIXTURES}" "${DATA_DIR}"
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

  echo "== enabling transit + kv-v2 and provisioning ML-KEM custody prerequisites"
  bao secrets enable transit >/dev/null 2>&1 || true
  bao secrets enable -path=secret -version=2 kv >/dev/null 2>&1 || true
  # transit AES key that wraps every custodied PQC seed at rest.
  bao write -f transit/keys/stream-aead type=aes256-gcm96 >/dev/null
  # publicPath marker so the sealing reconcile probe is non-fatal before NewKey.
  bao kv put secret/example/ml-kem-768-public "value=$(printf 'unused' | base64 | tr -d '\n')" >/dev/null

  umask 077
  printf '%s\n' "${TOKEN}" >"${TOKEN_FILE}"
  printf 'stream-file-encryption-passphrase\n' >"${PASS_FILE}"

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
  ( cd "${SCRIPT_DIR}" && BASIL_SOCKET="${SOCKET}" BASIL_KEM_KEY_ID="${KEM_KEY_ID}" \
      STREAM_FILE_DIR="${DATA_DIR}" go run . ) | tee "${OUT}"
  status="${PIPESTATUS[0]}"
  set -e
  [ "${status}" -eq 0 ] || { echo "FAIL: example exited ${status}" >&2; exit 1; }

  echo "== asserting proven properties"
  assert() { grep -qF "$1" "${OUT}" || { echo "FAIL: missing assertion: $1" >&2; exit 1; }; }
  assert "PASS input file bytes=4194304"
  assert "PASS aes-256-gcm roundtrip byte-identical"
  assert "PASS ml-kem-768 provisioned key=app.stream_seal"
  assert "PASS ml-kem-768 roundtrip byte-identical broker-recovered-cek"
  assert "PASS tamper fails-closed ErrAuthFailed"

  echo "== OK: stream-file-encryption example passed all assertions"
}

main "$@"
