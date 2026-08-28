#!/usr/bin/env python3
import csv
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
src = ROOT / "experiments/results/shared-plan-java.csv"
out = Path(__file__).resolve().parent.parent / "generated/shared-plan-summary.txt"

with src.open() as f:
    rows = list(csv.DictReader(f))

h_cov = [int(r["hellman_coverage"]) / 65536 for r in rows]
d_cov = [int(r["dp_coverage"]) / 65536 for r in rows]
h_success = sum(r["hellman_exact_recovery"] == "true" for r in rows)
d_success = sum(r["dp_exact_recovery"] == "true" for r in rows)

text = "\n".join([
    f"trials={len(rows)}",
    f"hellman_exact_recovery={h_success}/{len(rows)}",
    f"hellman_median_coverage={statistics.median(h_cov):.12f}",
    f"dp_exact_recovery={d_success}/{len(rows)}",
    f"dp_median_coverage={statistics.median(d_cov):.12f}",
]) + "\n"

out.write_text(text)
print(text, end="")
