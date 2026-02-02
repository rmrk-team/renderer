#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <version>"
  echo "Example: $0 0.3.5"
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

version="$1"
version="${version#v}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid version: $version"
  exit 1
fi

for cmd in git gh python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd"
    exit 1
  fi
done

if [[ ! -f Cargo.toml ]]; then
  echo "Run this script from the repo root."
  exit 1
fi

branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$branch" != "master" ]]; then
  echo "Expected branch master; current: $branch"
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is dirty; commit or stash changes first."
  exit 1
fi

git fetch origin master --tags

if ! git merge-base --is-ancestor origin/master HEAD; then
  echo "Local master is behind origin/master. Pull first."
  exit 1
fi

if git rev-parse "refs/tags/$version" >/dev/null 2>&1; then
  echo "Tag already exists locally: $version"
  exit 1
fi

if [[ -n "$(git ls-remote --tags origin "refs/tags/$version")" ]]; then
  echo "Tag already exists on origin: $version"
  exit 1
fi

python3 - "$version" <<'PY'
import re
import sys
from pathlib import Path

version = sys.argv[1]

cargo = Path("Cargo.toml")
text = cargo.read_text()
text, count = re.subn(
    r'(?m)^version\s*=\s*"[^"]+"$',
    f'version = "{version}"',
    text,
    count=1,
)
if count != 1:
    raise SystemExit("Failed to update Cargo.toml version")
cargo.write_text(text)

lock = Path("Cargo.lock")
if lock.exists():
    lock_text = lock.read_text()
    pattern = r'(\[\[package\]\]\nname = "proj-renderer"\nversion = )"[^"]+"'
    lock_text, count = re.subn(pattern, r'\1"' + version + '"', lock_text, count=1)
    if count != 1:
        raise SystemExit("Failed to update Cargo.lock version")
    lock.write_text(lock_text)
PY

git add Cargo.toml Cargo.lock
git commit -m "chore(release): $version"

git tag "$version"
git push origin master
git push origin "$version"

gh release create "$version" --title "$version" --notes "Release $version"
