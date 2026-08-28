#!/usr/bin/env python3
"""Generate theory-only candidate configurations for the paper.

No measured DES/Rust/Java value is created here. The CSV records the
Ma--Hong random-function approximation and the naive iid occupancy reference.
"""
from __future__ import annotations

import csv
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "generated"


def ma_hong_fraction(N: int, m: int, t: int) -> float:
    s = 0.0
    for _ in range(t):
        s = 1.0 - math.exp(-m / N) * math.exp(-s)
    return s


def row(label: str, b: int, m: int, t: int):
    N = 1 << b
    mh = ma_hong_fraction(N, m, t)
    iid = 1.0 - math.exp(-(m * t) / N)
    return {
        "label": label,
        "b": b,
        "N": N,
        "m": m,
        "t": t,
        "mt_over_N": (m * t) / N,
        "mt2_over_N": (m * t * t) / N,
        "ma_hong_state_fraction": mh,
        "ma_hong_expected_states": mh * N,
        "iid_occupancy_fraction": iid,
    }


configs = [
    ("stop-b12-a", 12, 64, 8),
    ("stop-b12-b", 12, 16, 16),
    ("stop-b14-a", 14, 64, 16),
    ("stop-b14-b", 14, 16, 32),
    ("stop-b16-a", 16, 256, 16),
    ("stop-b16-b", 16, 64, 32),
    ("stop-b16-c", 16, 16, 64),
    ("stop-b18-a", 18, 256, 32),
    ("stop-b18-b", 18, 64, 64),
    ("stop-b18-c", 18, 16, 128),
    ("budget-b16-t16", 16, 4096, 16),
    ("budget-b16-t32", 16, 2048, 32),
    ("stress-b16-current", 16, 1024, 64),
    ("budget-b16-t128", 16, 512, 128),
]

rows = [row(*cfg) for cfg in configs]

OUT.mkdir(parents=True, exist_ok=True)

csv_path = OUT / "theory-grid.csv"
with csv_path.open("w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=list(rows[0]),
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)

tex_path = OUT / "theory-grid.tex"
with tex_path.open("w") as f:
    f.write("\\begin{tabular}{lrrrrr}\n")
    f.write("\\toprule\n")
    f.write("Configuration & $b$ & $m$ & $t$ & $mt/N$ & $\\rho_{\\rm MH}$ \\\\\n")
    f.write("\\midrule\n")
    for r in rows:
        f.write(
            f"{r['label']} & {r['b']} & {r['m']} & {r['t']} & "
            f"{r['mt_over_N']:.4f} & "
            f"{100 * r['ma_hong_state_fraction']:.3f}\\% \\\\\n"
        )
    f.write("\\bottomrule\n")
    f.write("\\end{tabular}\n")

print(csv_path)
print(tex_path)
