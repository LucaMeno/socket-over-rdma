import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np

# --- File CSV ---
files = {
    "10 Streams": {
        "TCP": "redis_benchmark_TCP_10.csv",
        "RDMA": "redis_benchmark_RDMA_10.csv"
    },
    "30 Streams": {
        "TCP": "redis_benchmark_TCP_30.csv",
        "RDMA": "redis_benchmark_RDMA_30.csv"
    }
}

sns.set_style("whitegrid")

# --- Lettura dati e preparazione posizione barre ---
dfs_tcp = [pd.read_csv(files[label]["TCP"]) for label in files]
dfs_rdma = [pd.read_csv(files[label]["RDMA"]) for label in files]

operations = dfs_tcp[0]["operation"].tolist()
num_ops = len(operations)

# --- Parametri barre ---
bar_width = 0.35
gap_between_blocks = 1.0  # spazio tra 10 e 30 stream

# Posizioni barre per 10 stream
x_10 = np.arange(num_ops)
# Posizioni barre per 30 stream
x_30 = x_10 + num_ops + gap_between_blocks

# Uniamo tutte le X e le etichette
xticks = np.concatenate([x_10, x_30])
xtick_labels = operations + operations

# --- Creazione figura ---
plt.figure(figsize=(14,6))
colors = {"TCP": sns.color_palette("tab10")[0],
          "RDMA": sns.color_palette("tab10")[1]}

# Barre 10 stream
plt.bar(x_10 - bar_width/2, dfs_tcp[0]["ops_per_sec"], width=bar_width, label="TCP", color=colors["TCP"])
plt.bar(x_10 + bar_width/2, dfs_rdma[0]["ops_per_sec"], width=bar_width, label="RDMA", color=colors["RDMA"])

# Barre 30 stream
plt.bar(x_30 - bar_width/2, dfs_tcp[1]["ops_per_sec"], width=bar_width, color=colors["TCP"])
plt.bar(x_30 + bar_width/2, dfs_rdma[1]["ops_per_sec"], width=bar_width, color=colors["RDMA"])

# Linea verticale grigia tra blocchi
divider_x = x_10[-1] + 0.5 + gap_between_blocks/2
plt.axvline(x=divider_x, color='gray', linestyle='--', linewidth=1.5, alpha=0.7)

# --- Etichette sopra i blocchi ---
# Centro blocco 10 stream
center_10 = (x_10[0] + x_10[-1]) / 2
plt.text(center_10, max(max(dfs_tcp[0]["ops_per_sec"]), max(dfs_rdma[0]["ops_per_sec"])) * 1.05,
         "10 Streams", ha='center', fontsize=14, fontweight='bold')

# Centro blocco 30 stream
center_30 = (x_30[0] + x_30[-1]) / 2
plt.text(center_30, max(max(dfs_tcp[1]["ops_per_sec"]), max(dfs_rdma[1]["ops_per_sec"])) * 1.05,
         "30 Streams", ha='center', fontsize=14, fontweight='bold')

# --- Asse X ---
plt.xticks(xticks, xtick_labels, fontsize=12)
plt.xlabel("Operation", fontsize=14)
plt.ylabel("Ops/sec", fontsize=14)

# --- Titolo e legenda (una sola) ---
plt.title("Redis Operations Performance (TCP vs RDMA, 10 vs 30 streams)", fontsize=16, fontweight='bold')
plt.legend(fontsize=12)
plt.grid(True, linestyle='--', alpha=0.7)

plt.tight_layout()
plt.savefig("TCP_RDMA_10_vs_30_singleplot_labeled.png", dpi=300)
plt.show()

print("Unified plot completed with block labels.")
