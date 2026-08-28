#!/usr/bin/env python3
import csv
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
src = ROOT / "experiments/results/paper-hellman-sweep.csv"
generated = Path(__file__).resolve().parent.parent / "generated"

with src.open() as f:
    rows = list(csv.DictReader(f))

groups = defaultdict(list)
for row in rows:
    groups[(row["config"], row["map_type"])].append(row)

summary_rows = []
for (config, map_type), group in sorted(groups.items()):
    coverage = [float(r["coverage_fraction"]) for r in group]
    residual = [float(r["residual_vs_ma_hong"]) for r in group]
    endpoints = [int(r["distinct_endpoints"]) for r in group]
    first = group[0]
    summary_rows.append({
        "config": config,
        "map_type": map_type,
        "b": first["b"],
        "m": first["m"],
        "t": first["t"],
        "trials": len(group),
        "ma_hong_fraction": first["ma_hong_fraction"],
        "median_coverage": f"{statistics.median(coverage):.12f}",
        "mean_coverage": f"{statistics.mean(coverage):.12f}",
        "pstdev_coverage": f"{statistics.pstdev(coverage):.12f}",
        "median_residual": f"{statistics.median(residual):.12f}",
        "mean_residual": f"{statistics.mean(residual):.12f}",
        "median_distinct_endpoints": f"{statistics.median(endpoints):.1f}",
    })

csv_path = generated / "hellman-sweep-summary.csv"
with csv_path.open("w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=list(summary_rows[0]),
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(summary_rows)

# Matched DES-vs-random median table.
by_config = defaultdict(dict)
for row in summary_rows:
    by_config[row["config"]][row["map_type"]] = row

tex_path = generated / "hellman-sweep-summary.tex"
with tex_path.open("w") as f:
    f.write("\\begin{tabular}{lrrrrr}\n")
    f.write("\\toprule\n")
    f.write("Configuration & $b$ & $m$ & $t$ & DES median & Random median \\\\\n")
    f.write("\\midrule\n")
    for config in sorted(by_config):
        pair = by_config[config]
        if "des" not in pair or "random" not in pair:
            continue
        d = pair["des"]
        r = pair["random"]
        f.write(
            f"{config} & {d['b']} & {d['m']} & {d['t']} & "
            f"{100*float(d['median_coverage']):.3f}\\% & "
            f"{100*float(r['median_coverage']):.3f}\\% \\\\\n"
        )
    f.write("\\bottomrule\n")
    f.write("\\end{tabular}\n")

# Human-readable anchor lines.
current = by_config["stress-b16-current"]
text_path = generated / "hellman-sweep-key-results.txt"
with text_path.open("w") as f:
    f.write("rows=%d\n" % len(rows))
    f.write("configurations=%d\n" % len(by_config))
    f.write("trials_per_map=30\n")
    f.write("stress_ma_hong=%s\n" % current["des"]["ma_hong_fraction"])
    f.write("stress_des_median=%s\n" % current["des"]["median_coverage"])
    f.write("stress_random_median=%s\n" % current["random"]["median_coverage"])

print(text_path.read_text(), end="")
