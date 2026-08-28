#!/usr/bin/env python3
import csv
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 4:
    raise SystemExit(
        "usage: summarize_results.py RESULTS.csv COVERAGE.csv OUTPUT.md"
    )

results_path = Path(sys.argv[1])
coverage_path = Path(sys.argv[2])
output_path = Path(sys.argv[3])

with results_path.open(newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

with coverage_path.open(newline="", encoding="utf-8") as f:
    coverage_rows = list(csv.DictReader(f))

if not rows or not coverage_rows:
    raise SystemExit("missing result or coverage rows")

groups = defaultdict(list)
for row in rows:
    groups[row["method"]].append(row)

coverage_groups = defaultdict(list)
for row in coverage_rows:
    coverage_groups[row["method"]].append(row)

def ints(rs, field):
    return [int(r[field]) for r in rs]

def floats(rs, field):
    return [float(r[field]) for r in rs]

def median_ms(rs, field):
    return statistics.median(ints(rs, field)) / 1_000_000.0

def pct(n, d):
    return 100.0 * n / d if d else 0.0

def median_coverage(method):
    return statistics.median(
        floats(coverage_groups[method], "coverage_fraction")
    )

state_bits = int(rows[0]["state_bits"])
trials = len(groups["exhaustive"])
N = 1 << state_bits

lines = []
lines.append("# Verified small benchmark")
lines.append("")
lines.append(
    "This document is generated from "
    "`experiments/results/verified-small.csv` and "
    "`experiments/results/verified-small-coverage.csv`. "
    "It reports measurements produced by the modern implementation, not the "
    "historical presentation."
)
lines.append("")
lines.append(f"- Effective state dimension: **{state_bits} bits** (`N = {N:,}`)")
lines.append(f"- Seeded independent trials: **{trials}**")
lines.append(
    "- Timing: `System.nanoTime()` end-to-end JVM measurements after a separate "
    "warm-up run"
)
lines.append(
    "- Coverage: exact unique reduced states represented by the generated "
    "table chains, computed outside the timed path"
)
lines.append("")

lines.append("## Summary")
lines.append("")
lines.append(
    "| Method | Exact recovery | Median exact coverage | Median offline | "
    "Median online | Median stored chains | Median distinct endpoints |"
)
lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")

for method in ("exhaustive", "hellman", "distinguished_points"):
    rs = groups[method]
    success = sum(r["exact_recovery"] == "true" for r in rs)
    stored = statistics.median(ints(rs, "stored_chains"))
    endpoints = statistics.median(ints(rs, "distinct_endpoints"))
    coverage = median_coverage(method)
    lines.append(
        f"| {method.replace('_', ' ')} | "
        f"{success}/{len(rs)} ({pct(success, len(rs)):.1f}%) | "
        f"{100*coverage:.1f}% | "
        f"{median_ms(rs, 'offline_ns'):.3f} ms | "
        f"{median_ms(rs, 'online_ns'):.3f} ms | "
        f"{stored:g} | {endpoints:g} |"
    )

lines.append("")

hellman = groups["hellman"]
if hellman:
    m = int(hellman[0]["configured_chains"])
    t = int(hellman[0]["chain_parameter"])
    independent_reference = 1.0 - math.exp(-(m * t) / N)
    coverage_values = floats(
        coverage_groups["hellman"], "coverage_fraction"
    )
    success = sum(r["exact_recovery"] == "true" for r in hellman)
    ep = statistics.median(ints(hellman, "distinct_endpoints"))

    lines.append("## Hellman observations")
    lines.append("")
    lines.append(f"- Parameters: `m = {m}`, `t = {t}`, so `m t / N = {(m*t)/N:.3f}`.")
    lines.append(
        f"- Independent-sample occupancy reference: "
        f"`1 - exp(-m t / N) = {independent_reference:.3f}` "
        f"({100*independent_reference:.1f}%)."
    )
    lines.append(
        "- That 63.2% value is **not** an expected coverage formula for these "
        "iterated chains. States within a chain are linked by one fixed "
        "mapping, so chain merging makes the independent-sample model "
        "optimistic."
    )
    lines.append(
        f"- Exact table coverage across the 30 generated tables: median "
        f"{100*statistics.median(coverage_values):.1f}%, range "
        f"{100*min(coverage_values):.1f}%–{100*max(coverage_values):.1f}%."
    )
    lines.append(
        f"- Random-target exact recovery: {success}/{len(hellman)} "
        f"({pct(success, len(hellman)):.1f}%)."
    )
    lines.append(
        f"- Median distinct endpoints: {ep:g}/{m}; endpoint collisions and "
        "chain merging are directly visible."
    )
    lines.append("")

dp = groups["distinguished_points"]
if dp:
    m = int(dp[0]["configured_chains"])
    max_chain = int(dp[0]["chain_parameter"])
    d = int(dp[0]["dp_difficulty_bits"])
    success = sum(r["exact_recovery"] == "true" for r in dp)
    truncated = sum(int(r["truncated_chains"]) for r in dp)
    stored = sum(int(r["stored_chains"]) for r in dp)
    endpoints = statistics.median(ints(dp, "distinct_endpoints"))
    coverage_values = floats(
        coverage_groups["distinguished_points"], "coverage_fraction"
    )

    lines.append("## Distinguished-point observations")
    lines.append("")
    lines.append(
        f"- Parameters: `{m}` starts, `d = {d}`, maximum chain length "
        f"`{max_chain}`."
    )
    lines.append(
        f"- Uniform-state waiting-time reference: `2^d = {1<<d}` transitions."
    )
    lines.append(
        f"- Exact stored-table coverage across the 30 generated tables: median "
        f"{100*statistics.median(coverage_values):.1f}%, range "
        f"{100*min(coverage_values):.1f}%–{100*max(coverage_values):.1f}%."
    )
    lines.append(
        f"- Random-target exact recovery: {success}/{len(dp)} "
        f"({pct(success, len(dp)):.1f}%)."
    )
    lines.append(
        f"- Stored chains across all trials: {stored:,}; truncated chains: "
        f"{truncated:,}."
    )
    lines.append(
        f"- Median distinct distinguished endpoints: {endpoints:g}/{m}; "
        "many chains merge onto the same distinguished endpoint."
    )
    lines.append("")

lines.append("## Limits")
lines.append("")
lines.append(
    "This is a small reproducibility benchmark, not a cryptanalytic security "
    "estimate. DES is obsolete; the state space is deliberately reduced; JVM "
    "timings are machine-dependent; and random-target recovery uses a finite "
    "sample. Exact coverage is included specifically so conclusions do not "
    "depend only on those 30 target samples."
)
lines.append("")
lines.append(
    "See `METHODOLOGY.md` for the exact state model and "
    "`HISTORICAL_RESULTS.md` for the original presentation values."
)

output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"WROTE {output_path}")
