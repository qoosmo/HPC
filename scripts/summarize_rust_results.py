#!/usr/bin/env python3
import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def median_ms(rows, key):
    return statistics.median(int(row[key]) for row in rows) / 1_000_000.0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--coverage", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    results = read_csv(args.results)
    coverage = read_csv(args.coverage)

    by_method = defaultdict(list)
    for row in results:
        by_method[row["method"]].append(row)

    cov_by_method = defaultdict(list)
    for row in coverage:
        cov_by_method[row["method"]].append(row)

    order = ["exhaustive", "hellman", "distinguished_points"]
    labels = {
        "exhaustive": "Exhaustive",
        "hellman": "Hellman",
        "distinguished_points": "Distinguished points",
    }

    lines = [
        "# Verified Rust results",
        "",
        "This file records the first committed Rust benchmark run for the project.",
        "The Rust implementation passed the shared Java/Rust semantic vectors before",
        "these measurements were collected.",
        "",
        "Timing values are machine-dependent. The Rust benchmark currently uses a",
        "deterministic SplitMix64 experiment generator; it does **not yet** consume",
        "the exact Java `SplittableRandom` trial plan. Therefore the Java and Rust",
        "timings below should not yet be treated as an apples-to-apples speedup claim.",
        "",
        "## Configuration",
        "",
        "- effective state dimension: **16 bits**, `N = 65,536`;",
        "- trials: **30**;",
        "- seed: `20260828`;",
        "- Hellman: `m = 1024`, `t = 64`;",
        "- distinguished points: 1024 starts, `d = 6`, maximum chain length 256;",
        "- a separate warm-up run is executed before measurements;",
        "- exact coverage is computed outside each timed build/lookup interval.",
        "",
        "## Results",
        "",
        "| Method | Exact recovery | Median exact coverage | Median offline | Median online |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]

    for method in order:
        rows = by_method[method]
        cov_rows = cov_by_method[method]
        exact = sum(row["exact_recovery"].lower() == "true" for row in rows)
        median_cov = statistics.median(
            float(row["coverage_fraction"]) for row in cov_rows
        ) * 100.0
        offline = median_ms(rows, "offline_ns")
        online = median_ms(rows, "online_ns")
        lines.append(
            f"| {labels[method]} | {exact}/{len(rows)} | {median_cov:.1f}% | "
            f"{offline:.3f} ms | {online:.3f} ms |"
        )

    lines.extend([
        "",
        "## Interpretation",
        "",
        "The algorithmic quantities to compare first are exact recovery, endpoint",
        "statistics, and exact coverage. A direct Java-versus-Rust timing claim is",
        "deferred until both implementations consume one committed shared experiment",
        "plan (identical targets and identical Hellman/DP start sets).",
        "",
        "## Files",
        "",
        f"- `{args.results}`",
        f"- `{args.coverage}`",
        f"- `{args.environment}`",
        "",
    ])

    Path(args.output).write_text("\n".join(lines), encoding="utf-8")

if __name__ == "__main__":
    main()
