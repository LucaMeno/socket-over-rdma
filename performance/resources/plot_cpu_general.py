import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import os

# Check input file
if len(sys.argv) <= 1:
    print('Missing file name argument\nUsage: python3 cpu_plotter.py cpu_log.log')
    sys.exit(0)

input_file_name = sys.argv[1]
output_file_name = os.path.splitext(input_file_name)[0]

# Read log file
times = []
user_cpu = []
system_cpu = []
sections = []

with open(input_file_name, "r") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("UID"):
            continue
        parts = line.split()
        if len(parts) < 10:
            continue
        times.append(parts[0])
        user_cpu.append(float(parts[3]))    # %usr
        system_cpu.append(float(parts[4]))  # %system
        sections.append(parts[-1])          # Command

# Convert to DataFrame
df = pd.DataFrame({
    'time': times,
    'usr': user_cpu,
    'system': system_cpu,
    'section': sections
})

# Convert time to seconds
df['time_dt'] = pd.to_datetime(df['time'], format='%H:%M:%S')
df['time_seconds'] = (df['time_dt'] - df['time_dt'].min()).dt.total_seconds()

# Set Seaborn style
sns.set_style("whitegrid")

# Create combined plot
plt.figure(figsize=(12,6))
plt.plot(
    df['time_seconds'], 
    df['usr'], 
    marker='o', markersize=2, linewidth=2, color='tab:blue',
    label='% CPU User'
)
plt.plot(
    df['time_seconds'], 
    df['system'], 
    marker='o', markersize=2, linewidth=2, color='tab:orange',
    label='% CPU System'
)

# Determine top y-coordinate for labels
y_max = max(max(df['usr']), max(df['system']))
y_label_pos = y_max + (y_max * 0.05)  # 5% above max for labels

# Add vertical lines and section labels
for i in range(1, len(df)):
    if df['section'][i] != df['section'][i-1]:
        plt.axvline(x=df['time_seconds'][i], color='gray', linestyle='--', alpha=0.7)
        plt.text(
            df['time_seconds'][i], y_label_pos, df['section'][i], 
            rotation=0, verticalalignment='bottom', horizontalalignment='center',
            color='gray', fontsize=12, fontweight='bold'
        )

# Labels and title
plt.title('CPU Usage Over Time', fontsize=16, fontweight='bold', pad=30)
plt.xlabel("Time (s)", fontsize=14)
plt.ylabel("% CPU", fontsize=14)
plt.xticks(fontsize=12)
plt.yticks(fontsize=12)
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend(loc='upper left', fontsize=12)
plt.tight_layout()

# Save figure
plt.savefig(f"{output_file_name}_cpu_combined.png", dpi=300)
print(f"Plot completed and saved as {output_file_name}_cpu_combined.png")
