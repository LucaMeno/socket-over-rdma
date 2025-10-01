import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import sys
import os

# Check arguments
if len(sys.argv) < 3:
    print('Missing file arguments\nUsage: python3 rtt_plotter.py app_lat_RDMA.csv app_lat_TCP.csv')
    sys.exit(0)

file_rdma = sys.argv[1]
file_tcp = sys.argv[2]

# Read CSV files
df_rdma = pd.read_csv(file_rdma)
df_tcp = pd.read_csv(file_tcp)

# Filter for packets n >= 400
df_rdma = df_rdma[df_rdma['n'] >= 400]
df_tcp = df_tcp[df_tcp['n'] >= 400]

# Compute averages
avg_rdma = df_rdma['RTT (us)'].mean()
avg_tcp = df_tcp['RTT (us)'].mean()

# Seaborn style
sns.set_style("whitegrid")

# Colors
color_rdma = 'tab:blue'
color_tcp = 'tab:orange'

# Create the plot
plt.figure(figsize=(10,6))


# TCP
plt.plot(
    df_tcp['n'],
    df_tcp['RTT (us)'],
    marker='x', markersize=1, linewidth=2, color=color_tcp,
    label=f'TCP (avg: {avg_tcp:.2f} us)'
)
plt.axhline(avg_tcp, color=color_tcp, linestyle='--', linewidth=2, alpha=0.4)

# RDMA
plt.plot(
    df_rdma['n'],
    df_rdma['RTT (us)'],
    marker='o', markersize=1, linewidth=2, color=color_rdma,
    label=f'RDMA (avg: {avg_rdma:.2f} us)'
)
plt.axhline(avg_rdma, color=color_rdma, linestyle='--', linewidth=2, alpha=0.4)

# Labels and title
plt.title('RTT: RDMA vs TCP', fontsize=16, fontweight='bold')
plt.xlabel("Packet Number", fontsize=14)
plt.ylabel("RTT (us)", fontsize=14)
plt.xticks(fontsize=12)
plt.yticks(fontsize=12)
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend(loc='lower right', fontsize=12)
plt.tight_layout()

# Save and show
output_file_name = os.path.splitext(file_rdma)[0]
plt.savefig(f"{output_file_name}_vs_TCP_rtt.png", dpi=300)
plt.show()

print(f"Plot saved as {output_file_name}_vs_TCP_rtt.png")
print(f"Average RDMA RTT: {avg_rdma:.2f} us")
print(f"Average TCP RTT: {avg_tcp:.2f} us")
