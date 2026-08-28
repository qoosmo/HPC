#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p experiments/results

echo "===== TESTS ====="
mvn -q test

echo "===== WARMUP ====="
rm -f /tmp/hpc-warmup.csv
mvn -q exec:java \
  -Dexec.mainClass=io.github.qoosmo.hpc.ExperimentRunner \
  -Dexec.args="--state-bits 12 --trials 5 --seed 99 --hellman-chains 256 --hellman-chain-length 16 --dp-chains 256 --dp-bits 4 --dp-max-chain 64 --output /tmp/hpc-warmup.csv"

echo "===== ENVIRONMENT ====="
{
  date -u +"timestamp_utc=%Y-%m-%dT%H:%M:%SZ"
  uname -a
  sw_vers 2>/dev/null || true
  java -version 2>&1
  mvn -version
} > experiments/results/verified-small-environment.txt

echo "===== VERIFIED SMALL BENCHMARK ====="
rm -f experiments/results/verified-small.csv
mvn -q exec:java \
  -Dexec.mainClass=io.github.qoosmo.hpc.ExperimentRunner \
  -Dexec.args="--state-bits 16 --trials 30 --seed 20260828 --hellman-chains 1024 --hellman-chain-length 64 --dp-chains 1024 --dp-bits 6 --dp-max-chain 256 --output experiments/results/verified-small.csv"

echo "===== EXACT TABLE COVERAGE ====="
rm -f experiments/results/verified-small-coverage.csv
mvn -q exec:java \
  -Dexec.mainClass=io.github.qoosmo.hpc.ExactCoverageRunner \
  -Dexec.args="--state-bits 16 --trials 30 --seed 20260828 --hellman-chains 1024 --hellman-chain-length 64 --dp-chains 1024 --dp-bits 6 --dp-max-chain 256 --output experiments/results/verified-small-coverage.csv"

python3 scripts/summarize_results.py \
  experiments/results/verified-small.csv \
  experiments/results/verified-small-coverage.csv \
  docs/VERIFIED_RESULTS.md

echo "===== VERIFIED SUMMARY ====="
cat docs/VERIFIED_RESULTS.md

echo
echo "===== DIFF CHECK ====="
git diff --check

echo
echo "===== STATUS ====="
git status --short
