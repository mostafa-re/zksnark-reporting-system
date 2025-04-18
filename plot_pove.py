#!/usr/bin/env python3
"""
Plot Groth16 prove benchmark time (ms).
"""

import os
import json
import pathlib
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import ScalarFormatter, FixedLocator

plot = pathlib.Path("./docs/bench_groth16_prove.pdf")
root = pathlib.Path("./docs/benchmark_data/groth16")
rows = []

for prove_path in (root / "prove").glob("*/new"):
    n = int(prove_path.parent.name)

    with open(prove_path / "estimates.json") as f:
        prove_ns = json.load(f)["mean"]["point_estimate"]

    # convert ns to ms
    rows.append((n, prove_ns * 1e-6))

# build DataFrame sorted by n
df = (
    pd.DataFrame(rows, columns=["n", "prove_ms"])
    .sort_values("n")
    .reset_index(drop=True)
)

print(df.to_string(index=False))

fig, ax = plt.subplots()
ax.plot(df.n, df.prove_ms, marker=".", color='blue', label="Prove")

ax.set_xscale("log", base=2)
ax.set_xlabel("Values of n (log₂)")
ax.set_ylabel("Avg. Prove Time (ms)")
ax.set_title("Groth16 Prove Benchmark")
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
