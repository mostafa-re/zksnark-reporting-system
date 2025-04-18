#!/usr/bin/env python3
"""
Read Groth16 bench summaries produced by Criterion-style data
writer in:

    ./docs/benchmark_data/groth16/prove/<n>/new
    ./docs/benchmark_data/groth16/verify/<n>/new

Each file is JSON that looks like
{
  "mean": { "point_estimate": 77752955.894375, ... },
  ...
}

`point_estimate` is the mean run-time ns.
The script builds a table and plots prove / verify time versus `n`.
"""

import json
import pathlib
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import ScalarFormatter, FixedLocator

root = pathlib.Path("./docs/benchmark_data/groth16")
rows = []

for prove_path in (root / "prove").glob("*/new"):
    n = int(prove_path.parent.name)
    verify_path = root / "verify" / str(n) / "new"
    if not verify_path.exists():
        continue

    with open(prove_path / "estimates.json") as f:
        prove_ns = json.load(f)["mean"]["point_estimate"]
    with open(verify_path / "estimates.json") as f:
        verify_ns = json.load(f)["mean"]["point_estimate"]

    # convert ns to sec
    rows.append((n, prove_ns * 1e-9, verify_ns * 1e-9))

# build DataFrame sorted by n
df = (
    pd.DataFrame(rows, columns=["n", "prove_s", "verify_s"])
    .sort_values("n")
    .reset_index(drop=True)
)
print(df.to_string(index=False))

fig, ax = plt.subplots()
ax.plot(df.n, df.prove_s, marker=".", label="Prove")
ax.plot(df.n, df.verify_s, marker=".", label="Verify")

ax.set_xscale("log", base=2)
ax.set_xlabel("Values of n (log₂)")
ax.set_ylabel("Avg. run time (seconds)")
ax.set_title("Groth16 prove & verify benchmark")
ax.grid(True, which="both")

# show every n as a tick 
ax.xaxis.set_major_locator(FixedLocator(df.n))
ax.xaxis.set_major_formatter(ScalarFormatter())
ax.tick_params(axis="x", rotation=45)

ax.legend()
fig.tight_layout()
fig.savefig("./docs/bench_groth16_plot.png", dpi=300)
