#!/usr/bin/env python3
import csv
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PAPER = Path(__file__).resolve().parent.parent
GENERATED = PAPER / "generated"
SRC = ROOT / "experiments/results/paper-dp-graph.csv"

with SRC.open() as f:
    rows = list(csv.DictReader(f))

des = {}
rnd = defaultdict(list)

for row in rows:
    key = (int(row["d"]), int(row["limit"]))
    if row["map_type"] == "des":
        des[key] = row
    else:
        rnd[key].append(row)

for key in des:
    if len(rnd[key]) != 30:
        raise SystemExit(f"missing random rows for {key}")

table = GENERATED / "dp-graph-results.tex"
with table.open("w") as f:
    f.write("\\begin{tabular}{lrrrr}\n")
    f.write("\\toprule\n")
    f.write("$d$ & $L$ & DES exact trunc. & Random median & DES eventual floor \\\\\n")
    f.write("\\midrule\n")
    for d in (4, 6, 8):
        for mult in (1, 2, 4):
            limit = (1 << d) * mult
            key = (d, limit)
            drow = des[key]
            random_exact = statistics.median(
                float(r["exact_truncation_fraction"]) for r in rnd[key]
            )
            f.write(
                f"{d} & {limit} & "
                f"{100*float(drow['exact_truncation_fraction']):.2f}\\% & "
                f"{100*random_exact:.2f}\\% & "
                f"{100*float(drow['eventual_truncation_floor']):.2f}\\% \\\\\n"
            )
    f.write("\\bottomrule\n")
    f.write("\\end{tabular}\n")

macros = GENERATED / "dp-graph-macros.tex"
with macros.open("w") as f:
    names = {4: "Four", 6: "Six", 8: "Eight"}
    for d in (4, 6, 8):
        suffix = names[d]
        key = (d, 1 << d)
        drow = des[key]
        random_floor = statistics.median(
            float(r["eventual_truncation_floor"]) for r in rnd[key]
        )
        f.write(
            f"\\newcommand{{\\DPGraphDESFloorD{suffix}}}"
            f"{{{100*float(drow['eventual_truncation_floor']):.2f}\\%}}\n"
        )
        f.write(
            f"\\newcommand{{\\DPGraphRandomFloorD{suffix}}}"
            f"{{{100*random_floor:.2f}\\%}}\n"
        )
        f.write(
            f"\\newcommand{{\\DPGraphDESMaxHitD{suffix}}}"
            f"{{{int(drow['max_finite_hitting_transitions'])}}}\n"
        )

key = GENERATED / "dp-graph-key-findings.txt"
with key.open("w") as f:
    for d in (4, 6, 8):
        drow = des[(d, 1 << d)]
        random_floor = statistics.median(
            float(r["eventual_truncation_floor"])
            for r in rnd[(d, 1 << d)]
        )
        f.write(
            f"d{d}_des_eventual_floor="
            f"{float(drow['eventual_truncation_floor']):.12f}\n"
        )
        f.write(
            f"d{d}_random_median_eventual_floor="
            f"{random_floor:.12f}\n"
        )
        f.write(
            f"d{d}_des_max_finite_hit="
            f"{int(drow['max_finite_hitting_transitions'])}\n"
        )

print(key.read_text(), end="")
