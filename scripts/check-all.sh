#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/verify-historical-math.py
mvn -q test
cargo test --locked --manifest-path rust/Cargo.toml
cargo run --quiet --locked --manifest-path rust/Cargo.toml --bin tmto -- smoke

(
  cd research-note
  make clean
  make
  make clean
)

git diff --check

echo "ALL_RESEARCH_CHECKS=PASS"
