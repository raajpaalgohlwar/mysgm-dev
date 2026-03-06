#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONFIG="${SCRIPT_DIR}/churn_nodes.conf"
CONFIG_PATH="${1:-$DEFAULT_CONFIG}"

if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "Config not found: $CONFIG_PATH"
  echo "Copy ${SCRIPT_DIR}/churn_nodes.conf.example to ${SCRIPT_DIR}/churn_nodes.conf and edit it."
  exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_PATH"

required_vars=(
  DHT_HOST DHT_PORT
  CONTROLLER_STATE CONTROLLER_BIN CONTROLLER_LOG_FILE CONTROLLER_GID_PREFIX
  REMOTE_BIN REMOTE_STATE_DIR REMOTE_LOG_FILE
  CHURN_ROUNDS REMOVE_READD_PER_ROUND GROUP_UPDATE_PER_ROUND
  SECRET_LABEL SECRET_LENGTH RETRY_MAX RETRY_DELAY_SEC
)

for v in "${required_vars[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "Missing required config var: $v"
    exit 1
  fi
done

if [[ ${#NODES[@]} -lt 1 ]]; then
  echo "NODES must include at least one host alias."
  exit 1
fi

if [[ ! -x "$CONTROLLER_BIN" ]]; then
  echo "Controller binary not executable: $CONTROLLER_BIN"
  echo "Build it first (example): cargo build --release -p mysgm"
  exit 1
fi

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

retry_run() {
  local attempt=1
  local max_attempts="$RETRY_MAX"
  local delay="$RETRY_DELAY_SEC"

  while true; do
    if "$@"; then
      return 0
    fi

    if (( attempt >= max_attempts )); then
      echo "Command failed after ${max_attempts} attempts: $*" >&2
      return 1
    fi

    log "Retry ${attempt}/${max_attempts} failed. Sleeping ${delay}s before retry."
    attempt=$((attempt + 1))
    sleep "$delay"
  done
}

controller_cmd() {
  "$CONTROLLER_BIN" "$CONTROLLER_STATE" \
    --adapter dht --dht-host "$DHT_HOST" --dht-port "$DHT_PORT" \
    --log-file "$CONTROLLER_LOG_FILE" "$@"
}

remote_run() {
  local host="$1"
  shift
  ssh "$host" "$@"
}

remote_cmd() {
  local host="$1"
  shift
  local state_path="${REMOTE_STATE_DIR}/${host}.json"
  remote_run "$host" "$REMOTE_BIN" "$state_path" \
    --adapter dht --dht-host "$DHT_HOST" --dht-port "$DHT_PORT" \
    --log-file "$REMOTE_LOG_FILE" "$@"
}

extract_last_line() {
  awk 'NF {line=$0} END {print line}'
}

setup_remote_binaries() {
  if [[ "${COPY_BINARY_TO_NODES}" != "1" ]]; then
    return
  fi

  for host in "${NODES[@]}"; do
    log "Copying binary to ${host}:${REMOTE_BIN}"
    scp "$CONTROLLER_BIN" "${host}:${REMOTE_BIN}"
    remote_run "$host" chmod +x "$REMOTE_BIN"
  done
}

bootstrap_nodes() {
  NODE_PIDS=()

  for host in "${NODES[@]}"; do
    log "Bootstrapping node ${host}"

    if [[ "${RESET_NODES}" == "1" ]]; then
      retry_run remote_cmd "$host" --reset --pid "$host" Me >/dev/null
    fi

    retry_run remote_cmd "$host" Advertise >/dev/null

    local pid
    pid="$(remote_cmd "$host" Me | extract_last_line)"
    if [[ -z "$pid" ]]; then
      echo "Failed to resolve PID for host ${host}" >&2
      exit 1
    fi

    NODE_PIDS+=("$pid")
    log "Node ${host} PID: ${pid}"
  done
}

bootstrap_controller() {
  if [[ "${RESET_CONTROLLER}" == "1" ]]; then
    log "Resetting controller state"
    retry_run controller_cmd --reset --pid "${CONTROLLER_NAME:-controller}" Me >/dev/null
  fi

  retry_run controller_cmd Advertise >/dev/null

  CONTROLLER_PID="$(controller_cmd Me | extract_last_line)"
  if [[ -z "$CONTROLLER_PID" ]]; then
    echo "Failed to resolve controller PID" >&2
    exit 1
  fi

  log "Controller PID: ${CONTROLLER_PID}"
}

create_group() {
  log "Creating controller group"
  GROUP_ID="$(controller_cmd CreateGroup --gid "$CONTROLLER_GID_PREFIX" | extract_last_line)"

  if [[ -z "$GROUP_ID" ]]; then
    echo "Failed to create group" >&2
    exit 1
  fi

  log "Group ID: ${GROUP_ID}"
}

sync_all_nodes() {
  for host in "${NODES[@]}"; do
    retry_run remote_cmd "$host" Groups >/dev/null
  done
}

controller_sync() {
  # Any command causes startup sync; Agents is lightweight.
  controller_cmd Agents >/dev/null || true
}

add_all_nodes() {
  log "Adding all node PIDs to ${GROUP_ID}"
  controller_sync
  retry_run controller_cmd Group "$GROUP_ID" Add "${NODE_PIDS[@]}" >/dev/null
  sync_all_nodes
}

export_secrets_snapshot() {
  local tag="$1"

  log "Secret snapshot: ${tag}"
  local controller_secret
  controller_secret="$(controller_cmd Group "$GROUP_ID" ExportSecret --label "$SECRET_LABEL" --length "$SECRET_LENGTH" | extract_last_line)"
  printf 'controller\t%s\t%s\n' "$tag" "$controller_secret"

  local i host secret
  for i in "${!NODES[@]}"; do
    host="${NODES[$i]}"
    secret="$(remote_cmd "$host" Group "$GROUP_ID" ExportSecret --label "$SECRET_LABEL" --length "$SECRET_LENGTH" | extract_last_line || true)"
    printf '%s\t%s\t%s\n' "$host" "$tag" "${secret:-ERROR}"
  done
}

member_index_for_pid() {
  local pid="$1"
  controller_cmd Group "$GROUP_ID" Members \
    | awk -v target="$pid" '$2==target {print $1; exit}'
}

remove_pid_from_group() {
  local pid="$1"
  local idx
  idx="$(member_index_for_pid "$pid")"

  if [[ -z "$idx" ]]; then
    log "PID not found in members list (skip remove): $pid"
    return 1
  fi

  log "Removing pid=${pid} index=${idx}"
  retry_run controller_cmd Group "$GROUP_ID" Remove "$idx" >/dev/null
  sync_all_nodes
  return 0
}

readd_pid_to_group() {
  local host="$1"
  local pid="$2"

  log "Re-advertise and re-add pid=${pid} host=${host}"
  retry_run remote_cmd "$host" Advertise >/dev/null
  controller_sync
  retry_run controller_cmd Group "$GROUP_ID" Add "$pid" >/dev/null
  sync_all_nodes
}

node_group_update() {
  local host="$1"
  log "Node self-update from ${host}"
  retry_run remote_cmd "$host" Group "$GROUP_ID" Update >/dev/null
  sync_all_nodes
}

run_churn_rounds() {
  local round op pick host pid

  for round in $(seq 1 "$CHURN_ROUNDS"); do
    log "==== Churn round ${round}/${CHURN_ROUNDS} ===="

    for op in $(seq 1 "$REMOVE_READD_PER_ROUND"); do
      if [[ ${#NODE_PIDS[@]} -lt 1 ]]; then
        break
      fi

      pick=$((RANDOM % ${#NODE_PIDS[@]}))
      host="${NODES[$pick]}"
      pid="${NODE_PIDS[$pick]}"

      if remove_pid_from_group "$pid"; then
        readd_pid_to_group "$host" "$pid"
      fi
    done

    for op in $(seq 1 "$GROUP_UPDATE_PER_ROUND"); do
      pick=$((RANDOM % ${#NODES[@]}))
      host="${NODES[$pick]}"
      node_group_update "$host"
    done

    export_secrets_snapshot "round_${round}"
  done
}

main() {
  log "Starting churn orchestrator using config: ${CONFIG_PATH}"
  setup_remote_binaries
  bootstrap_nodes
  bootstrap_controller
  create_group
  add_all_nodes
  export_secrets_snapshot "post_add"
  run_churn_rounds
  log "Completed churn orchestration for group ${GROUP_ID}"
}

main "$@"
