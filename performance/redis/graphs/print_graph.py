import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import sys
import os
import numpy as np

NUM_STREAMS = 40

if len(sys.argv) <= 2:
    print('Missing file arguments\nUsage: python3 redis_plotter.py file1.csv file2.csv')
    sys.exit(0)

file1 = sys.argv[1]
file2 = sys.argv[2]

out_name = "TCP_vs_RDMA_hist_" + str(NUM_STREAMS)

# --- Lettura CSV ---
df1 = pd.read_csv(file1)
df2 = pd.read_csv(file2)

# --- Merge sulle operazioni (assumiamo stesse operation) ---
merged = pd.merge(df1, df2, on="operation", suffixes=("_1", "_2"))

# --- Set stile professionale ---
sns.set_style("whitegrid")

plt.figure(figsize=(10,6))

x = np.arange(len(merged["operation"]))  # indici
width = 0.35  # larghezza delle barre

# Colori distinti
colors = sns.color_palette("tab10", 2)

# --- Plot barre affiancate ---
plt.bar(x - width/2, merged["ops_per_sec_1"], width, label="TCP", color=colors[0], alpha=0.9)
plt.bar(x + width/2, merged["ops_per_sec_2"], width, label="RDMA", color=colors[1], alpha=0.9)

# --- Label e titolo ---
plt.title("Redis Operations Performance Comparison with " + str(NUM_STREAMS) + " streams", fontsize=16, fontweight='bold')
plt.xlabel("Operation", fontsize=14)
plt.ylabel("Ops/sec", fontsize=14)
plt.xticks(x, merged["operation"], fontsize=12)
plt.yticks(fontsize=12)

plt.legend(fontsize=12, loc="upper left")
plt.tight_layout()
plt.savefig(f"{out_name}.png", dpi=300)

print("Comparison histogram completed.")
