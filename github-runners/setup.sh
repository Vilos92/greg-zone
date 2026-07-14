#!/usr/bin/env bash
# Install / manage native macOS ARM64 GitHub Actions runners for Vilos92/scriptlancer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREG_ZONE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_URL="${REPO_URL:-https://github.com/Vilos92/scriptlancer}"
REPO_API="${REPO_API:-https://api.github.com/repos/Vilos92/scriptlancer}"
RUNNER_ROOT="${RUNNER_ROOT:-$HOME/actions-runners}"
RUNNER_PREFIX="${RUNNER_PREFIX:-scriptlancer}"
LABELS="${LABELS:-greg-zone}"
# Match Continuous Integration's parallel job count.
COUNT="${COUNT:-6}"
# Pin so re-runs are reproducible; bump when upgrading the runner agent.
RUNNER_VERSION="${RUNNER_VERSION:-2.335.1}"

usage() {
  cat <<'EOF'
Usage: ./setup.sh [--count N] [--status|--start|--stop|--remove]

Installs native macOS ARM64 runners (not Docker). Requires GITHUB_RUNNER_ACCESS_TOKEN
in ../.env (Administration: Read and write on Vilos92/scriptlancer).
EOF
}

load_token() {
  if [[ -f "$GREG_ZONE_DIR/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$GREG_ZONE_DIR/.env"
    set +a
  fi
  if [[ -z "${GITHUB_RUNNER_ACCESS_TOKEN:-}" || "$GITHUB_RUNNER_ACCESS_TOKEN" == "hunterrunner15" ]]; then
    echo "error: set GITHUB_RUNNER_ACCESS_TOKEN in $GREG_ZONE_DIR/.env" >&2
    exit 1
  fi
}

registration_token() {
  curl -fsSL -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $GITHUB_RUNNER_ACCESS_TOKEN" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$REPO_API/actions/runners/registration-token" \
    | python3 -c 'import json,sys; data=json.load(sys.stdin); token=data.get("token");
assert token, data; print(token)'
}

runner_dir() {
  local index="$1"
  echo "$RUNNER_ROOT/$RUNNER_PREFIX-$index"
}

download_runner() {
  local dest="$1"
  local archive="actions-runner-osx-arm64-${RUNNER_VERSION}.tar.gz"
  local url="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${archive}"
  mkdir -p "$dest"
  curl -fsSL -o "$dest/$archive" "$url"
  tar xzf "$dest/$archive" -C "$dest"
  rm -f "$dest/$archive"
}

install_one() {
  local index="$1"
  local dir
  dir="$(runner_dir "$index")"
  local name="${RUNNER_PREFIX}-greg-zone-${index}"

  if [[ -f "$dir/.runner" ]]; then
    echo "skip: $name already configured ($dir)"
    return 0
  fi

  echo "installing $name → $dir"
  download_runner "$dir"
  (
    cd "$dir"
    ./config.sh --unattended \
      --url "$REPO_URL" \
      --token "$(registration_token)" \
      --name "$name" \
      --labels "$LABELS" \
      --work "_work" \
      --replace
    ./svc.sh install
    ./svc.sh start
  )
  echo "started $name"
}

cmd_status() {
  local index dir
  for index in $(seq 1 "$COUNT"); do
    dir="$(runner_dir "$index")"
    if [[ -x "$dir/svc.sh" ]]; then
      echo "=== $(basename "$dir") ==="
      (cd "$dir" && ./svc.sh status) || true
    else
      echo "=== $(basename "$dir") === missing"
    fi
  done
}

cmd_start() {
  local index dir
  for index in $(seq 1 "$COUNT"); do
    dir="$(runner_dir "$index")"
    [[ -x "$dir/svc.sh" ]] && (cd "$dir" && ./svc.sh start)
  done
}

cmd_stop() {
  local index dir
  for index in $(seq 1 "$COUNT"); do
    dir="$(runner_dir "$index")"
    [[ -x "$dir/svc.sh" ]] && (cd "$dir" && ./svc.sh stop) || true
  done
}

cmd_remove() {
  load_token
  local index dir
  for index in $(seq 1 "$COUNT"); do
    dir="$(runner_dir "$index")"
    if [[ -x "$dir/svc.sh" ]]; then
      (cd "$dir" && ./svc.sh stop || true)
      (cd "$dir" && ./svc.sh uninstall || true)
    fi
    if [[ -x "$dir/config.sh" && -f "$dir/.runner" ]]; then
      (cd "$dir" && ./config.sh remove --token "$(registration_token)" || true)
    fi
    rm -rf "$dir"
    echo "removed $(basename "$dir")"
  done
}

cmd_install() {
  if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
    echo "error: native runners must be installed on macOS arm64" >&2
    exit 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to parse the registration-token JSON" >&2
    exit 1
  fi
  load_token
  mkdir -p "$RUNNER_ROOT"
  local index
  for index in $(seq 1 "$COUNT"); do
    install_one "$index"
  done
  echo "done: $COUNT runners under $RUNNER_ROOT (labels: self-hosted,macOS,ARM64,$LABELS)"
}

ACTION="install"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --count)
      COUNT="$2"
      shift 2
      ;;
    --status)
      ACTION="status"
      shift
      ;;
    --start)
      ACTION="start"
      shift
      ;;
    --stop)
      ACTION="stop"
      shift
      ;;
    --remove)
      ACTION="remove"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      usage
      exit 1
      ;;
  esac
done

case "$ACTION" in
  install) cmd_install ;;
  status) cmd_status ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  remove) cmd_remove ;;
esac
