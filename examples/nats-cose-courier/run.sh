#!/usr/bin/env bash
# run.sh: boot OpenBao + a Basil agent with sealed invocation enabled, start a
# local NATS server and basil-nats-bridge, then run the Go sealed sign
# invocation courier example through the bridge.
#
# Exit 0 only when all assertions pass. Honors BASIL_BIN and
# BASIL_NATS_BRIDGE_BIN (prebuilt binaries), then `basil` /
# `basil-nats-bridge` on PATH; fails with install guidance when missing.
#
# Env overrides (all optional):
#   NATS_COSE_COURIER_WORKDIR   scratch dir           (default /tmp/basil-nats-cose-courier)
#   BASIL_BIN                   prebuilt basil binary (default: basil on PATH)
#   BASIL_NATS_BRIDGE_BIN       prebuilt bridge binary (default: basil-nats-bridge on PATH)
#   BAO_PORT                    OpenBao dev port      (default 8233)
#   NATS_PORT                   nats-server port      (default 4251)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_URL="https://github.com/openbasil/basil/releases"

WORKDIR="${NATS_COSE_COURIER_WORKDIR:-/tmp/basil-nats-cose-courier}"
BAO_PORT="${BAO_PORT:-8233}"
NATS_PORT="${NATS_PORT:-4251}"
ADDR="http://127.0.0.1:${BAO_PORT}"
NATS_URL="nats://127.0.0.1:${NATS_PORT}"
BRIDGE_SUBJECT="${BASIL_NATS_SUBJECT:-basil.invoke.go}"
TOKEN="root"

FIXTURES="${WORKDIR}/fixtures"
CATALOG="${FIXTURES}/catalog.json"
POLICY="${FIXTURES}/policy.json"
BUNDLE="${FIXTURES}/bundle.sealed"
PASS_FILE="${FIXTURES}/passphrase.txt"
TOKEN_FILE="${FIXTURES}/bao-token.txt"
AGENT_CONFIG="${FIXTURES}/agent.toml"
BRIDGE_CONFIG="${FIXTURES}/bridge.toml"
SOCKET="${WORKDIR}/agent.sock"
BAO_LOG="${WORKDIR}/openbao.log"
AGENT_LOG="${WORKDIR}/agent.log"
NATS_LOG="${WORKDIR}/nats.log"
BRIDGE_LOG="${WORKDIR}/bridge.log"

BASIL_BIN="${BASIL_BIN:-}"
BRIDGE_BIN=""
BAO_PID=""
AGENT_PID=""
NATS_PID=""
BRIDGE_PID=""

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }

need_basil_binary() {
  local name="$1" override="${2:-}"
  if [ -n "${override}" ]; then
    [ -x "${override}" ] || { echo "${name} override '${override}' is not executable" >&2; exit 1; }
    return
  fi
  if ! command -v "${name}" >/dev/null 2>&1; then
    cat >&2 <<EOF
missing required Basil binary: ${name}

Install the latest Basil release from:
  ${INSTALL_URL}

Then set BASIL_BIN / BASIL_NATS_BRIDGE_BIN or make sure '${name}' is on
PATH and rerun this script.
EOF
    exit 1
  fi
}

bao_cmd() {
  VAULT_ADDR="${ADDR}" VAULT_TOKEN="${TOKEN}" "$BAO" "$@"
}

cleanup() {
  local pids="${BRIDGE_PID} ${NATS_PID} ${AGENT_PID} ${BAO_PID}"
  for pid in ${pids}; do [ -n "${pid}" ] && kill -INT "${pid}" 2>/dev/null || true; done
  sleep 0.3
  for pid in ${pids}; do [ -n "${pid}" ] && kill -KILL "${pid}" 2>/dev/null || true; done
}
trap cleanup EXIT

wait_for_socket() {
  local path="$1" log="$2" pid="$3"
  for _ in $(seq 1 120); do
    [ -S "${path}" ] && return
    kill -0 "${pid}" 2>/dev/null || { echo "process exited while waiting for ${path}:" >&2; cat "${log}" >&2; exit 1; }
    sleep 0.1
  done
  echo "timed out waiting for ${path}:" >&2
  cat "${log}" >&2
  exit 1
}

wait_for_nats() {
  for _ in $(seq 1 120); do
    grep -q "Server is ready" "${NATS_LOG}" 2>/dev/null && return
    kill -0 "${NATS_PID}" 2>/dev/null || { echo "nats-server exited early:" >&2; cat "${NATS_LOG}" >&2; exit 1; }
    sleep 0.1
  done
  echo "nats-server not ready:" >&2
  cat "${NATS_LOG}" >&2
  exit 1
}

write_kv_value() {
  local path="$1" value="$2" logical
  logical="${path/\/data\//\/}"
  bao_cmd kv put "${logical}" "value=${value}" >/dev/null
}

write_catalog() {
  cat >"${CATALOG}" <<JSON
{
  "schemaVersion": 1,
  "backends": {
    "bao": {
      "kind": "vault",
      "addr": "${ADDR}",
      "engines": ["kv2"]
    }
  },
  "keys": {
    "broker.signing": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "kv2", "path": "secret/data/go-courier/broker-signing",
      "publicPath": "secret/data/go-courier/broker-signing-public",
      "writable": false, "missing": "error",
      "labels": ["broker_key_use=response-signing"],
      "description": "Broker response-signing key for sealed invocation responses."
    },
    "broker.request": {
      "class": "sealing", "keyType": "x25519", "backend": "bao",
      "engine": "kv2", "path": "secret/data/go-courier/request-sealing",
      "publicPath": "secret/data/go-courier/request-sealing-public",
      "writable": false, "missing": "error",
      "labels": ["broker_key_use=request-encryption"],
      "description": "Broker request-encryption X25519 key for NATS bridged sealed invocations."
    },
    "response.sealing": {
      "class": "sealing", "keyType": "x25519", "backend": "bao",
      "engine": "kv2", "path": "secret/data/go-courier/response-sealing",
      "publicPath": "secret/data/go-courier/response-sealing-public",
      "writable": false, "missing": "error",
      "labels": ["broker_key_use=response-encryption"],
      "description": "Client response-encryption X25519 key for broker replies."
    },
    "workload.signing": {
      "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
      "engine": "kv2", "path": "secret/data/go-courier/workload-signing",
      "publicPath": "secret/data/go-courier/workload-signing-public",
      "writable": false, "missing": "error",
      "description": "Target key signed through the sealed invocation."
    }
  }
}
JSON
}

write_policy() {
  local uid; uid="$(id -u)"
  cat >"${POLICY}" <<JSON
{
  "schema": "policy",
  "roles": {
    "local_admin": ["get_public_key", "sign", "verify"],
    "invoker": ["decrypt", "sign"]
  },
  "subjects": {
    "local": { "domain": "host-process", "match": { "all": [ { "process.uid": ${uid} } ] } },
    "go.client": {
      "domain": "host-process",
      "match": { "all": [
        { "process.uid": ${uid} },
        { "invocation.signature-key": { "algorithm": "ed25519", "public": "${CLIENT_SIGNING_PUBLIC_B64}" } }
      ] }
    }
  },
  "rules": [
    { "id": "local-admin", "subjects": ["local"], "action": ["role:local_admin"], "target": ["broker.signing", "broker.request", "response.sealing", "workload.signing"] },
    { "id": "go-client-can-invoke", "subjects": ["go.client"], "action": ["role:invoker"], "target": ["broker.request", "workload.signing"] }
  ],
  "config": {
    "names": { "users": { "${uid}": "local" }, "groups": {} },
    "memberships": { "${uid}": [] }
  }
}
JSON
}

write_agent_config() {
  cat >"${AGENT_CONFIG}" <<TOML
catalog = "${CATALOG}"
policy = "${POLICY}"
bundle = "${BUNDLE}"
vault-addr = "${ADDR}"
socket = "${SOCKET}"

[unlock]
unlock-passphrase-file = "${PASS_FILE}"

[broker-identity]
id = "basil://example/nats-cose-courier"
response-signing-key-id = "broker.signing"

[invocation]
enable = true
audience = ["basil://example/nats-cose-courier"]
request-encryption-key-id = "broker.request"
max-ttl-secs = 180
clock-skew-secs = 30
replay-cache-capacity = 128
TOML
}

write_bridge_config() {
  cat >"${BRIDGE_CONFIG}" <<TOML
[nats]
url = "${NATS_URL}"

[basil]
socket = "${SOCKET}"

[bridge]
request-subject = "${BRIDGE_SUBJECT}"
max-message-bytes = 1048576
TOML
}

main() {
  BAO="$(command -v bao || command -v vault || true)"
  [ -n "${BAO}" ] || { echo "missing required command: bao (or vault)" >&2; exit 1; }
  need nats-server
  need go
  need_basil_binary basil "${BASIL_BIN}"
  need_basil_binary basil-nats-bridge "${BASIL_NATS_BRIDGE_BIN:-}"
  BASIL_BIN="${BASIL_BIN:-$(command -v basil)}"
  BRIDGE_BIN="${BASIL_NATS_BRIDGE_BIN:-$(command -v basil-nats-bridge)}"
  echo "== using basil: ${BASIL_BIN}"
  echo "== using basil-nats-bridge: ${BRIDGE_BIN}"

  rm -rf "${WORKDIR}"
  mkdir -p "${FIXTURES}"
  chmod 700 "${WORKDIR}"

  eval "$(cd "${SCRIPT_DIR}" && EXAMPLE_MODE=fixtures go run .)"

  echo "== starting ${BAO##*/} dev server at ${ADDR}"
  "$BAO" server -dev -dev-root-token-id="${TOKEN}" -dev-listen-address="127.0.0.1:${BAO_PORT}" >"${BAO_LOG}" 2>&1 &
  BAO_PID="$!"
  for _ in $(seq 1 80); do
    bao_cmd status >/dev/null 2>&1 && break
    kill -0 "${BAO_PID}" 2>/dev/null || { echo "bao/vault server exited early:" >&2; cat "${BAO_LOG}" >&2; exit 1; }
    sleep 0.1
  done
  bao_cmd status >/dev/null

  echo "== enabling kv-v2"
  bao_cmd secrets enable -path=secret -version=2 kv >/dev/null 2>&1 || true
  write_kv_value "secret/data/go-courier/request-sealing" "${REQUEST_SEALING_PRIVATE_B64}"
  write_kv_value "secret/data/go-courier/request-sealing-public" "${REQUEST_SEALING_PUBLIC_B64}"
  write_kv_value "secret/data/go-courier/response-sealing" "${RESPONSE_SEALING_PRIVATE_B64}"
  write_kv_value "secret/data/go-courier/response-sealing-public" "${RESPONSE_SEALING_PUBLIC_B64}"
  write_kv_value "secret/data/go-courier/broker-signing" "${BROKER_SIGNING_PRIVATE_B64}"
  write_kv_value "secret/data/go-courier/broker-signing-public" "${BROKER_SIGNING_PUBLIC_B64}"
  write_kv_value "secret/data/go-courier/workload-signing" "${TARGET_SIGNING_PRIVATE_B64}"
  write_kv_value "secret/data/go-courier/workload-signing-public" "${TARGET_SIGNING_PUBLIC_B64}"

  umask 077
  printf '%s\n' "${TOKEN}" >"${TOKEN_FILE}"
  printf 'nats-cose-courier-passphrase\n' >"${PASS_FILE}"

  write_catalog
  write_policy

  echo "== sealing the credential bundle (passphrase slot + OpenBao token cred)"
  "${BASIL_BIN}" bundle create "${BUNDLE}" \
    --slot "passphrase:file=${PASS_FILE}" \
    --backend "id=bao,type=openbao,token-file=${TOKEN_FILE},addr=${ADDR}" >/dev/null
  chmod 600 "${BUNDLE}"
  write_agent_config

  echo "== starting nats-server on ${NATS_URL}"
  nats-server -p "${NATS_PORT}" >"${NATS_LOG}" 2>&1 &
  NATS_PID="$!"
  wait_for_nats

  echo "== launching basil agent on ${SOCKET}"
  "${BASIL_BIN}" agent --config "${AGENT_CONFIG}" >"${AGENT_LOG}" 2>&1 &
  AGENT_PID="$!"
  wait_for_socket "${SOCKET}" "${AGENT_LOG}" "${AGENT_PID}"

  echo "== launching basil-nats-bridge on subject ${BRIDGE_SUBJECT}"
  write_bridge_config
  "${BRIDGE_BIN}" --config "${BRIDGE_CONFIG}" >"${BRIDGE_LOG}" 2>&1 &
  BRIDGE_PID="$!"
  sleep 0.5
  kill -0 "${BRIDGE_PID}" 2>/dev/null || { echo "bridge exited early:" >&2; cat "${BRIDGE_LOG}" >&2; exit 1; }

  echo "== running the Go courier example"
  OUT="${WORKDIR}/example.out"
  set +e
  ( cd "${SCRIPT_DIR}" && \
      BASIL_NATS_URL="${NATS_URL}" \
      BASIL_NATS_SUBJECT="${BRIDGE_SUBJECT}" \
      BASIL_REQUEST_RECIPIENT_PUBLIC_HEX="${REQUEST_SEALING_PUBLIC_HEX}" \
      BASIL_BROKER_SIGNING_PUBLIC_HEX="${BROKER_SIGNING_PUBLIC_HEX}" \
      BASIL_TARGET_SIGNING_PUBLIC_HEX="${TARGET_SIGNING_PUBLIC_HEX}" \
      go run . ) | tee "${OUT}"
  status="${PIPESTATUS[0]}"
  set -e
  [ "${status}" -eq 0 ] || { echo "FAIL: example exited ${status}" >&2; cat "${BRIDGE_LOG}" >&2; exit 1; }

  grep -qF "PASS sealed sign invocation via basil-nats-bridge" "${OUT}" || {
    echo "FAIL: courier success assertion was not printed" >&2
    exit 1
  }
  echo "== OK: nats-cose-courier example passed all assertions"
}

main "$@"
