#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 ]]; then
  cat <<'USAGE'
Usage:
  probe-render.sh <base_url> <chain> <collection> <token_id> <format> [asset_id] [query]

Examples:
  probe-render.sh http://127.0.0.1:8085 base 0xabc... 5157 png
  probe-render.sh https://renderer.rmrk.app base 0xabc... 5157 png 34 "fresh=1&debug=1"
USAGE
  exit 1
fi

BASE_URL="${1%/}"
CHAIN="$2"
COLLECTION="$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')"
TOKEN_ID="$4"
FORMAT="$5"
ASSET_ID="${6:-}"
QUERY="${7:-}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

show_headers() {
  local file="$1"
  local prefix="$2"
  echo "${prefix}status: $(head -n 1 "$file" | tr -d '\r')"
  local location
  location="$(awk 'BEGIN{IGNORECASE=1} /^location:/{sub(/\r$/, "", $0); print substr($0, 11)}' "$file" | tail -n 1)"
  if [[ -n "$location" ]]; then
    echo "${prefix}location: $location"
  fi
  awk 'BEGIN{IGNORECASE=1}
    /^x-renderer-/ || /^content-type:/ || /^cache-control:/ || /^retry-after:/ || /^content-length:/ {
      sub(/\r$/, "", $0)
      print
    }' "$file" | sed "s/^/${prefix}/"
}

build_url() {
  local path="$1"
  if [[ -n "$QUERY" ]]; then
    echo "${BASE_URL}${path}?${QUERY}"
  else
    echo "${BASE_URL}${path}"
  fi
}

if [[ -n "$ASSET_ID" ]]; then
  REQUEST_PATH="/render/${CHAIN}/${COLLECTION}/${TOKEN_ID}/${ASSET_ID}/${FORMAT}"
else
  REQUEST_PATH="/render/${CHAIN}/${COLLECTION}/${TOKEN_ID}.${FORMAT}"
fi

REQUEST_URL="$(build_url "$REQUEST_PATH")"
echo "request: $REQUEST_URL"
curl -sS --max-time 75 -D "$TMP_DIR/first.h" -o "$TMP_DIR/first.b" "$REQUEST_URL"
show_headers "$TMP_DIR/first.h" "first: "

FIRST_CT="$(awk 'BEGIN{IGNORECASE=1} /^content-type:/{sub(/\r$/, "", $0); print tolower(substr($0, 14)); exit}' "$TMP_DIR/first.h")"
if [[ "$FIRST_CT" == application/json* ]]; then
  echo "first: json-body: $(tr '\n' ' ' < "$TMP_DIR/first.b")"
fi

LOCATION="$(awk 'BEGIN{IGNORECASE=1} /^location:/{sub(/\r$/, "", $0); print substr($0, 11)}' "$TMP_DIR/first.h" | tail -n 1)"
if [[ -z "$LOCATION" ]]; then
  exit 0
fi

if [[ "$LOCATION" =~ ^https?:// ]]; then
  FOLLOW_URL="$LOCATION"
else
  FOLLOW_URL="${BASE_URL}${LOCATION}"
fi

echo "follow: $FOLLOW_URL"
curl -sS --max-time 75 -D "$TMP_DIR/follow.h" -o "$TMP_DIR/follow.b" "$FOLLOW_URL"
show_headers "$TMP_DIR/follow.h" "follow: "

FOLLOW_CT="$(awk 'BEGIN{IGNORECASE=1} /^content-type:/{sub(/\r$/, "", $0); print tolower(substr($0, 14)); exit}' "$TMP_DIR/follow.h")"
if [[ "$FOLLOW_CT" == application/json* ]]; then
  echo "follow: json-body: $(tr '\n' ' ' < "$TMP_DIR/follow.b")"
else
  local_size="$(wc -c < "$TMP_DIR/follow.b" | tr -d ' ')"
  echo "follow: body-bytes: $local_size"
fi
