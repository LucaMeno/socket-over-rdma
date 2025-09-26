import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import sys
import os

# Controllo argomento file
if len(sys.argv) <= 1:
    print('Missing file name argument\nUsage: python3 port_plotter.py memory_log.csv')
    sys.exit(0)

input_file_name = sys.argv[1]
output_file_name = os.path.splitext(input_file_name)[0]

# Legge CSV
df = pd.read_csv(input_file_name)

# Converti tempo in secondi a partire da zero
df['time_dt'] = pd.to_datetime(df['time'], format='%H:%M:%S.%f')
df['time_seconds'] = (df['time_dt'] - df['time_dt'].min()).dt.total_seconds()

# Seaborn style
sns.set_style("whitegrid")

# Seleziona la colonna r e converti in GB
df['Rmem_GB'] = df['r'] / (1024 ** 3)  # r in byte → GB

# Trova tutte le coppie di porte uniche
port_pairs = df[['portsrc', 'portdest']].drop_duplicates()

for _, row in port_pairs.iterrows():
    src = row['portsrc']
    dst = row['portdest']
    pair_df = df[(df['portsrc'] == src) & (df['portdest'] == dst)]

    if pair_df.empty:
        continue

    plt.figure(figsize=(10,6))
    plt.plot(
        pair_df['time_seconds'],
        pair_df['Rmem_GB'],
        marker='o', markersize=3, linewidth=2, color='tab:blue',
        label=f'{src} → {dst}'
    )

    plt.title(f"Memory allocated for receiving data: {src} → {dst}", fontsize=16, fontweight='bold')
    plt.xlabel("Time (s)", fontsize=12)
    plt.ylabel("Memory allocated for receiving data (GB)", fontsize=12)
    plt.xticks(fontsize=10)
    plt.yticks(fontsize=10)
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(loc='upper left', fontsize=10)
    plt.tight_layout()

    output_plot_file = f"{output_file_name}_{src}_{dst}_Rmem_GB.png"
    plt.savefig(output_plot_file, dpi=300)
    plt.close()

print("All Rmem plots in GB completed.")
