#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-18080}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
PID=""
WAIT_SECONDS="${SMOKE_WAIT_SECONDS:-90}"

cleanup() {
  if [[ -n "${PID}" ]]; then
    kill "${PID}" >/dev/null 2>&1 || true
    wait "${PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

mkdir -p "${TMP_DIR}/cache" "${TMP_DIR}/pinned" "${TMP_DIR}/fallbacks"

# Build first so health polling only measures app startup, not compilation time.
(
  cd "${ROOT_DIR}"
  cargo build --quiet
)

BIN_PATH="${ROOT_DIR}/target/debug/proj-renderer"
if [[ ! -x "${BIN_PATH}" ]]; then
  echo "Smoke test failed. Missing executable: ${BIN_PATH}" >&2
  exit 1
fi

(
  cd "${ROOT_DIR}"
  ADMIN_PASSWORD=ci \
  DB_PATH="${TMP_DIR}/renderer.db" \
  CACHE_DIR="${TMP_DIR}/cache" \
  PINNED_DIR="${TMP_DIR}/pinned" \
  FALLBACKS_DIR="${TMP_DIR}/fallbacks" \
  PINNING_ENABLED=false \
  LOCAL_IPFS_ENABLED=false \
  ACCESS_MODE=open \
  I_KNOW_WHAT_I_AM_DOING=true \
  REQUIRE_APPROVAL=false \
  PORT="${PORT}" \
  "${BIN_PATH}" >"${TMP_DIR}/smoke.log" 2>&1
) &
PID=$!

for _ in $(seq 1 "${WAIT_SECONDS}"); do
  if curl --fail --silent --show-error "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

echo "Smoke test failed. Renderer did not become healthy on port ${PORT} within ${WAIT_SECONDS}s." >&2
echo "---- renderer smoke log ----" >&2
cat "${TMP_DIR}/smoke.log" >&2
exit 1
