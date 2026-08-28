#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo run --release --quiet --locked \
  --manifest-path rust/Cargo.toml \
  --bin tmto -- verified-small

{
  echo "generated_at_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo
  uname -a
  echo
  if command -v sw_vers >/dev/null 2>&1; then
    sw_vers
    echo
  fi
  rustc -Vv
  echo
  cargo -V
} > experiments/results/rust-verified-small-environment.txt

python3 scripts/summarize_rust_results.py \
  --results experiments/results/rust-verified-small.csv \
  --coverage experiments/results/rust-verified-small-coverage.csv \
  --environment experiments/results/rust-verified-small-environment.txt \
  --output docs/RUST_VERIFIED_RESULTS.md

echo "RUST_VERIFIED_SMALL=PASS"
