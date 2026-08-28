#!/usr/bin/env python3
from __future__ import annotations

import csv
import random
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PAPER = Path(__file__).resolve().parent.parent
GENERATED = PAPER / "generated"

HELLMAN = ROOT / "experiments/results/paper-hellman-sweep.csv"
DP = ROOT / "experiments/results/paper-dp-sweep.csv"
SHARED = ROOT / "experiments/results/shared-plan-java.csv"

BOOTSTRAP_SEED = 20260828
BOOTSTRAP_REPS = 20000


def percentile(values, q):
    values = sorted(values)
    pos = (len(values) - 1) * q
    low = int(pos)
    high = min(low + 1, len(values) - 1)
    frac = pos - low
    return values[low] * (1 - frac) + values[high] * frac


def bootstrap_mean_ci(values, reps=BOOTSTRAP_REPS):
    rng = random.Random(BOOTSTRAP_SEED)
    n = len(values)
    samples = []
    for _ in range(reps):
        samples.append(statistics.mean(values[rng.randrange(n)] for _ in range(n)))
    return percentile(samples, 0.025), percentile(samples, 0.975)


with HELLMAN.open() as f:
    hellman_rows = list(csv.DictReader(f))

h_by = defaultdict(dict)
for row in hellman_rows:
    h_by[(row["config"], int(row["trial"]))][row["map_type"]] = row

h_config_pairs = defaultdict(list)
for (config, trial), pair in h_by.items():
    if set(pair) != {"des", "random"}:
        raise SystemExit(f"incomplete Hellman pair {config}/{trial}")
    d = float(pair["des"]["coverage_fraction"])
    r = float(pair["random"]["coverage_fraction"])
    h_config_pairs[config].append(d - r)

h_summary = {}
for config, values in h_config_pairs.items():
    example = h_by[(config, 0)]["des"]
    des = [float(h_by[(config, trial)]["des"]["coverage_fraction"]) for trial in range(30)]
    rnd = [float(h_by[(config, trial)]["random"]["coverage_fraction"]) for trial in range(30)]
    ci_low, ci_high = bootstrap_mean_ci(values)
    h_summary[config] = {
        "b": int(example["b"]),
        "m": int(example["m"]),
        "t": int(example["t"]),
        "ma_hong": float(example["ma_hong_fraction"]),
        "des_median": statistics.median(des),
        "random_median": statistics.median(rnd),
        "des_mean": statistics.mean(des),
        "random_mean": statistics.mean(rnd),
        "paired_mean_delta": statistics.mean(values),
        "paired_median_delta": statistics.median(values),
        "paired_mean_ci_low": ci_low,
        "paired_mean_ci_high": ci_high,
    }

with DP.open() as f:
    dp_rows = list(csv.DictReader(f))

dp_groups = defaultdict(list)
for row in dp_rows:
    dp_groups[(row["config"], row["map_type"])].append(row)

dp_summary = {}
for (config, map_type), rows in dp_groups.items():
    example = rows[0]
    dp_summary[(config, map_type)] = {
        "d": int(example["d"]),
        "limit": int(example["limit"]),
        "limit_over_mean": float(example["limit_over_mean"]),
        "theory_trunc": float(example["theory_truncation_fraction"]),
        "median_coverage": statistics.median(float(r["coverage_fraction"]) for r in rows),
        "mean_coverage": statistics.mean(float(r["coverage_fraction"]) for r in rows),
        "median_trunc": statistics.median(float(r["truncation_fraction"]) for r in rows),
        "mean_trunc": statistics.mean(float(r["truncation_fraction"]) for r in rows),
        "median_endpoints": statistics.median(int(r["distinct_endpoints"]) for r in rows),
        "median_stored_transitions": statistics.median(
            float(r["mean_stored_transitions"]) for r in rows
        ),
    }

with SHARED.open() as f:
    shared_rows = list(csv.DictReader(f))

shared_h_success = sum(r["hellman_exact_recovery"] == "true" for r in shared_rows)
shared_d_success = sum(r["dp_exact_recovery"] == "true" for r in shared_rows)
shared_h_cov = statistics.median(int(r["hellman_coverage"]) / 65536 for r in shared_rows)
shared_d_cov = statistics.median(int(r["dp_coverage"]) / 65536 for r in shared_rows)

paired_csv = GENERATED / "hellman-paired-analysis.csv"
with paired_csv.open("w", newline="") as f:
    fields = [
        "config", "b", "m", "t", "ma_hong", "des_median", "random_median",
        "paired_mean_delta", "paired_median_delta",
        "paired_mean_ci_low", "paired_mean_ci_high",
    ]
    writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for config in sorted(h_summary):
        row = {"config": config, **h_summary[config]}
        writer.writerow({key: row[key] for key in fields})

hellman_tex = GENERATED / "hellman-main-results.tex"
with hellman_tex.open("w") as f:
    f.write("\\begin{tabular}{lrrrrr}\n")
    f.write("\\toprule\n")
    f.write("Configuration & $m$ & $t$ & Ma--Hong & DES median & Random median \\\\\n")
    f.write("\\midrule\n")
    order = [
        "stop-b16-a", "stop-b16-b", "stop-b16-c",
        "budget-b16-t16", "budget-b16-t32",
        "stress-b16-current", "budget-b16-t128",
    ]
    for config in order:
        r = h_summary[config]
        f.write(
            f"{config} & {r['m']} & {r['t']} & "
            f"{100*r['ma_hong']:.3f}\\% & "
            f"{100*r['des_median']:.3f}\\% & "
            f"{100*r['random_median']:.3f}\\% \\\\\n"
        )
    f.write("\\bottomrule\n")
    f.write("\\end{tabular}\n")

dp_tex = GENERATED / "dp-main-results.tex"
with dp_tex.open("w") as f:
    f.write("\\begin{tabular}{lrrrrr}\n")
    f.write("\\toprule\n")
    f.write("$d$ & $L$ & Fresh trunc. & DES trunc. & Random trunc. & DES coverage \\\\\n")
    f.write("\\midrule\n")
    for d in (4, 6, 8):
        for multiplier in (1, 2, 4):
            limit = (1 << d) * multiplier
            config = f"dp-d{d}-l{limit}"
            des = dp_summary[(config, "des")]
            rnd = dp_summary[(config, "random")]
            f.write(
                f"{d} & {limit} & "
                f"{100*des['theory_trunc']:.2f}\\% & "
                f"{100*des['median_trunc']:.2f}\\% & "
                f"{100*rnd['median_trunc']:.2f}\\% & "
                f"{100*des['median_coverage']:.2f}\\% \\\\\n"
            )
    f.write("\\bottomrule\n")
    f.write("\\end{tabular}\n")

stress = h_summary["stress-b16-current"]
largest_config, largest_row = max(
    h_summary.items(),
    key=lambda item: abs(item[1]["paired_mean_delta"]),
)

d6 = dp_summary[("dp-d6-l256", "des")]
d6r = dp_summary[("dp-d6-l256", "random")]

macros = GENERATED / "result-macros.tex"
with macros.open("w") as f:
    f.write(f"\\newcommand{{\\StressMH}}{{{100*stress['ma_hong']:.3f}\\%}}\n")
    f.write(f"\\newcommand{{\\StressDES}}{{{100*stress['des_median']:.3f}\\%}}\n")
    f.write(f"\\newcommand{{\\StressRandom}}{{{100*stress['random_median']:.3f}\\%}}\n")
    f.write(f"\\newcommand{{\\StressPairedMeanPP}}{{{100*stress['paired_mean_delta']:.3f}}}\n")
    f.write(f"\\newcommand{{\\StressPairedCILowPP}}{{{100*stress['paired_mean_ci_low']:.3f}}}\n")
    f.write(f"\\newcommand{{\\StressPairedCIHighPP}}{{{100*stress['paired_mean_ci_high']:.3f}}}\n")
    f.write(f"\\newcommand{{\\LargestDeltaConfig}}{{\\texttt{{{largest_config}}}}}\n")
    f.write(f"\\newcommand{{\\LargestPairedMeanPP}}{{{100*largest_row['paired_mean_delta']:.3f}}}\n")
    f.write(f"\\newcommand{{\\SharedHellmanSuccess}}{{{shared_h_success}/30}}\n")
    f.write(f"\\newcommand{{\\SharedDPSuccess}}{{{shared_d_success}/30}}\n")
    f.write(f"\\newcommand{{\\SharedHellmanCoverage}}{{{100*shared_h_cov:.3f}\\%}}\n")
    f.write(f"\\newcommand{{\\SharedDPCoverage}}{{{100*shared_d_cov:.3f}\\%}}\n")
    f.write(f"\\newcommand{{\\DPDsixTheoryTrunc}}{{{100*d6['theory_trunc']:.2f}\\%}}\n")
    f.write(f"\\newcommand{{\\DPDsixDESTrunc}}{{{100*d6['median_trunc']:.2f}\\%}}\n")
    f.write(f"\\newcommand{{\\DPDsixRandomTrunc}}{{{100*d6r['median_trunc']:.2f}\\%}}\n")
    f.write(f"\\newcommand{{\\DPDsixDESCoverage}}{{{100*d6['median_coverage']:.2f}\\%}}\n")

key = GENERATED / "result-key-findings.txt"
with key.open("w") as f:
    f.write(f"stress_ma_hong={stress['ma_hong']:.12f}\n")
    f.write(f"stress_des_median={stress['des_median']:.12f}\n")
    f.write(f"stress_random_median={stress['random_median']:.12f}\n")
    f.write(f"stress_paired_mean_delta={stress['paired_mean_delta']:.12f}\n")
    f.write(
        "stress_paired_mean_ci95="
        f"[{stress['paired_mean_ci_low']:.12f},"
        f"{stress['paired_mean_ci_high']:.12f}]\n"
    )
    f.write(f"largest_abs_paired_mean_config={largest_config}\n")
    f.write(f"largest_abs_paired_mean_delta={largest_row['paired_mean_delta']:.12f}\n")
    f.write(f"dp_d6_l256_theory_trunc={d6['theory_trunc']:.12f}\n")
    f.write(f"dp_d6_l256_des_median_trunc={d6['median_trunc']:.12f}\n")
    f.write(f"dp_d6_l256_random_median_trunc={d6r['median_trunc']:.12f}\n")

print(key.read_text(), end="")
