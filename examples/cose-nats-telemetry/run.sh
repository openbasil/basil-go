#!/usr/bin/env bash
# run.sh: boot OpenBao + a Basil agent, mint a NATS operator/account/user chain
# through the broker, start an operator-mode nats-server with a memory resolver
# preloaded from those minted JWTs, then run the COSE-over-NATS telemetry example
# and assert every proven property.
#
# Exit 0 only when all assertions pass. Honors BASIL_BIN (a prebuilt `basil`);
# falls back to `cargo build` from the repo root when it is unset.
#
# Env overrides (all optional):
#   COSE_NATS_WORKDIR   scratch dir           (default /tmp/basil-cose-nats)
#   BASIL_BIN           prebuilt basil binary (default: cargo build)
#   BAO_PORT            OpenBao dev port      (default 8232)
#   NATS_PORT           nats-server port      (default 4250)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${GO_ROOT}/../.." && pwd)"

WORKDIR="${COSE_NATS_WORKDIR:-/tmp/basil-cose-nats}"
BAO_PORT="${BAO_PORT:-8232}"
NATS_PORT="${NATS_PORT:-4250}"
ADDR="http://127.0.0.1:${BAO_PORT}"
NATS_URL="nats://127.0.0.1:${NATS_PORT}"
TOKEN="root"

FIXTURES="${WORKDIR}/fixtures"
CATALOG="${FIXTURES}/catalog.json"
POLICY="${FIXTURES}/policy.json"
BUNDLE="${FIXTURES}/bundle.sealed"
PASS_FILE="${FIXTURES}/passphrase.txt"
TOKEN_FILE="${FIXTURES}/bao-token.txt"
AGENT_CONFIG="${FIXTURES}/agent.toml"
NATS_CONF="${FIXTURES}/nats-server.conf"
SOCKET="${WORKDIR}/agent.sock"
BAO_LOG="${WORKDIR}/openbao.log"
AGENT_LOG="${WORKDIR}/agent.log"
NATS_LOG="${WORKDIR}/nats.log"

BAO_PID=""
AGENT_PID=""
NATS_PID=""

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }

cleanup() {
  local pids="${NATS_PID} ${AGENT_PID} ${BAO_PID}"
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
      "engines": ["transit", "kv2"],
      "mintKeyTypes": ["ed25519", "ed25519-nkey"]
    }
  },
  "keys": {
    "nats.operator": {
      "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
      "engine": "transit", "path": "nats-operator",
      "writable": true, "missing": "generate",
      "labels": ["nats_type=O"],
      "description": "NATS operator NKey; the broker self-signs the operator JWT and signs account JWTs in place. The seed never leaves the vault."
    },
    "nats.account": {
      "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
      "engine": "transit", "path": "nats-account",
      "writable": true, "missing": "generate",
      "labels": ["nats_type=A"],
      "description": "NATS account NKey; the broker signs user JWTs in place with it."
    },
    "nats.user": {
      "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
      "engine": "transit", "path": "nats-user",
      "writable": true, "missing": "generate",
      "description": "NATS user NKey; the broker signs the server connect nonce in place, so the seed never leaves the vault."
    },
    "telemetry.sign": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "transit", "path": "telemetry-sign",
      "writable": true, "missing": "generate",
      "description": "Ed25519 signing key for bare COSE_Sign1 telemetry. The broker signs the COSE ToBeSigned in place; verifiers use the published public key."
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
    "signer": ["sign", "verify", "get_public_key"]
  },
  "subjects": {
    "local": { "allOf": [ { "kind": "unix", "uid": ${uid} } ] }
  },
  "rules": [
    { "id": "nats-signer", "subjects": ["local"], "action": ["role:signer"], "target": ["nats.operator", "nats.account", "nats.user", "telemetry.sign"] },
    { "id": "nats-operator-mint", "subjects": ["local"], "action": ["op:mint", "op:sign_nats_jwt"], "target": ["nats.operator"] },
    { "id": "nats-account-mint", "subjects": ["local"], "action": ["op:mint"], "target": ["nats.account"] }
  ],
  "config": {
    "names": { "users": { "${uid}": "local" }, "groups": {} },
    "memberships": { "${uid}": [] }
  }
}
JSON
}

write_nats_conf() {
  local account_nkey account_jwt
  account_nkey="$(cat "${FIXTURES}/account.nkey")"
  account_jwt="$(cat "${FIXTURES}/account.jwt")"
  cat >"${NATS_CONF}" <<CONF
port: ${NATS_PORT}
operator: "${FIXTURES}/operator.jwt"
resolver: MEMORY
resolver_preload: {
  ${account_nkey}: "${account_jwt}"
}
CONF
}

run_example() {
  local mode="$1"
  ( cd "${SCRIPT_DIR}" && EXAMPLE_MODE="${mode}" BASIL_SOCKET="${SOCKET}" \
      BASIL_NATS_URL="${NATS_URL}" NATS_FIXTURES_DIR="${FIXTURES}" \
      GOPROXY=off go run . )
}

main() {
  need bao
  need nats-server
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
  printf 'cose-nats-telemetry-passphrase\n' >"${PASS_FILE}"

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

  echo "== provisioning the NATS operator/account/user chain via the broker"
  PROV_OUT="${WORKDIR}/provision.out"
  set +e
  run_example provision | tee "${PROV_OUT}"
  status="${PIPESTATUS[0]}"
  set -e
  [ "${status}" -eq 0 ] || { echo "FAIL: provision exited ${status}" >&2; exit 1; }
  for f in operator.jwt account.jwt account.nkey user.jwt; do
    [ -s "${FIXTURES}/${f}" ] || { echo "FAIL: provision did not write ${f}" >&2; exit 1; }
  done

  echo "== starting operator-mode nats-server on ${NATS_URL}"
  write_nats_conf
  nats-server -c "${NATS_CONF}" >"${NATS_LOG}" 2>&1 &
  NATS_PID="$!"
  for _ in $(seq 1 100); do
    grep -q "Server is ready" "${NATS_LOG}" && break
    kill -0 "${NATS_PID}" 2>/dev/null || { echo "nats-server exited early:" >&2; cat "${NATS_LOG}" >&2; exit 1; }
    sleep 0.1
  done
  grep -q "Server is ready" "${NATS_LOG}" || { echo "nats-server not ready:" >&2; cat "${NATS_LOG}" >&2; exit 1; }

  echo "== running the telemetry example"
  RUN_OUT="${WORKDIR}/telemetry.out"
  set +e
  run_example telemetry | tee "${RUN_OUT}"
  status="${PIPESTATUS[0]}"
  set -e
  [ "${status}" -eq 0 ] || { echo "FAIL: telemetry exited ${status}" >&2; cat "${NATS_LOG}" >&2; exit 1; }

  echo "== asserting proven properties"
  assert() { grep -qF "$1" "$2" || { echo "FAIL: missing assertion: $1" >&2; exit 1; }; }
  assert "PASS minted operator O=" "${PROV_OUT}"
  assert "PASS minted account A=" "${PROV_OUT}"
  assert "PASS minted user U=" "${PROV_OUT}"
  assert "PASS nats connect authenticated via minted user JWT" "${RUN_OUT}"
  assert "PASS cose_sign1 built" "${RUN_OUT}"
  assert "PASS subscriber verified cose_sign1 and payload matches" "${RUN_OUT}"
  assert "PASS subscriber rejected tampered cose_sign1" "${RUN_OUT}"

  echo "== OK: cose-nats-telemetry example passed all assertions"
}

main "$@"
