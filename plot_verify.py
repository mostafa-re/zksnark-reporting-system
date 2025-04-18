#!/usr/bin/env python3
"""
Plot Groth16 verify benchmark time (ps).
"""

import os
import json
import pathlib
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import ScalarFormatter, FixedLocator

plot = pathlib.Path("./docs/bench_groth16_verify.pdf")
root = pathlib.Path("./docs/benchmark_data/groth16")
rows = []

for verify_path in (root / "verify").glob("*/new"):
    n = int(verify_path.parent.name)

    with open(verify_path / "estimates.json") as f:
        verify_ns = json.load(f)["mean"]["point_estimate"]

    # convert ns to μs
    rows.append((n, verify_ns * 1e-3))

# build DataFrame sorted by n
df = (
    pd.DataFrame(rows, columns=["n", "verify_μs"])
    .sort_values("n")
    .reset_index(drop=True)
)

print(df.to_string(index=False))

fig, ax = plt.subplots()
ax.plot(df.n, df.verify_μs, marker=".", color='orange', label="Verify")

ax.set_xscale("log", base=2)
ax.set_xlabel("Values of n (log₂)")
ax.set_ylabel("Avg. Verify Time (μs)")
ax.set_title("Groth16 Verify Benchmark")
ax.grid(True, which="both")

ax.xaxis.set_major_locator(FixedLocator(df.n))
ax.xaxis.set_major_formatter(ScalarFormatter())
ax.tick_params(axis="x", rotation=45)
ax.legend()
fig.tight_layout()

if plot.exists():
    os.remove(plot)
fig.savefig(plot, format='pdf')
print(f"Plot saved to {plot}")
