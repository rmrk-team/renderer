#!/usr/bin/env bash
set -euo pipefail

REDOCLY_VERSION="2.19.2"
SPEC_PATH="${1:-openapi.yaml}"
PKG="@redocly/cli@${REDOCLY_VERSION}"

run_npx() {
  if ! command -v npx >/dev/null 2>&1; then
    return 127
  fi
  npx --yes "${PKG}" lint "${SPEC_PATH}"
}

if command -v bunx >/dev/null 2>&1; then
  tmp_file="$(mktemp)"
  set +e
  bunx "${PKG}" lint "${SPEC_PATH}" >"${tmp_file}" 2>&1
  bunx_rc=$?
  set -e
  cat "${tmp_file}"

  if [[ ${bunx_rc} -eq 0 ]]; then
    rm -f "${tmp_file}"
    exit 0
  fi

  if grep -Eq "error: GET .*registry\\.npmjs\\.org/@redocly%2fcli.* - 403" "${tmp_file}"; then
    echo "bunx failed to fetch ${PKG} (403). Falling back to npx." >&2
    rm -f "${tmp_file}"
    run_npx
    exit $?
  fi

  rm -f "${tmp_file}"
  exit "${bunx_rc}"
fi

run_npx || {
  echo "OpenAPI lint requires either bunx (Bun) or npx (Node.js)." >&2
  exit 1
}
