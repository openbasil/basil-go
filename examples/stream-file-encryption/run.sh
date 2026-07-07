#!/usr/bin/env bash
# run.sh boots OpenBao + a Basil agent with a custodied ML-KEM-768 sealing key,
# then run the stream-file-encryption example and assert every proven property.
#
# Exit 0 only when all assertions pass. Honors BASIL_BIN (a prebuilt `basil`),
# then `basil` on PATH; fails with install guidance when neither is present.
#
# Env overrides (all optional):
#   STREAM_FILE_WORKDIR   scratch dir           (default /tmp/basil-stream-file)
#   BASIL_BIN             prebuilt basil binary (default: basil on PATH)
#   BAO_PORT              OpenBao dev port      (default 8231)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_URL="https://github.com/openbasil/basil/releases"

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
  local pids="${AGENT_PID} ${BAO_PID}"
  # Dev servers (bao) ignore a plain SIGTERM; SIGINT stops them cleanly.
  for pid in ${pids}; do [ -n "${pid}" ] && kill -INT "${pid}" 2>/dev/null || true; done
  sleep 0.3
  for pid in ${pids}; do [ -n "${pid}" ] && kill -KILL "${pid}" 2>/dev/null || true; done
}
trap cleanup EXIT

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
  BAO="$(command -v bao || command -v vault || true)"
  [ -n "${BAO}" ] || { echo "missing required command: bao (or vault)" >&2; exit 1; }
  need go
  need_basil

  rm -rf "${WORKDIR}"
  mkdir -p "${FIXTURES}" "${DATA_DIR}"
  chmod 700 "${WORKDIR}"

  echo "== starting ${BAO##*/} dev server at ${ADDR}"
  "$BAO" server -dev -dev-root-token-id="${TOKEN}" -dev-listen-address="127.0.0.1:${BAO_PORT}" >"${BAO_LOG}" 2>&1 &
  BAO_PID="$!"
  for _ in $(seq 1 80); do
    VAULT_ADDR="${ADDR}" "$BAO" status >/dev/null 2>&1 && break
    kill -0 "${BAO_PID}" 2>/dev/null || { echo "bao/vault server exited early:" >&2; cat "${BAO_LOG}" >&2; exit 1; }
    sleep 0.1
  done
  export VAULT_ADDR="${ADDR}" VAULT_TOKEN="${TOKEN}"
  "$BAO" status >/dev/null

  echo "== enabling transit + kv-v2 and provisioning ML-KEM custody prerequisites"
  "$BAO" secrets enable transit >/dev/null 2>&1 || true
  "$BAO" secrets enable -path=secret -version=2 kv >/dev/null 2>&1 || true
  # transit AES key that wraps every custodied PQC seed at rest.
  "$BAO" write -f transit/keys/stream-aead type=aes256-gcm96 >/dev/null
  # publicPath marker so the sealing reconcile probe is non-fatal before NewKey.
  "$BAO" kv put secret/example/ml-kem-768-public "value=$(printf 'unused' | base64 | tr -d '\n')" >/dev/null

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
