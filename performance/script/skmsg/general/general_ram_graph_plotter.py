import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import sys
import os

# Check for input file argument
if len(sys.argv) <= 1:
    print('Missing file name argument\nUsage: python3 ram_plotter.py ram_log.csv')
    sys.exit(0)

input_file_name = sys.argv[1]
output_file_name = os.path.splitext(input_file_name)[0]

# Read CSV with header
df = pd.read_csv(input_file_name)  # assume CSV has header 'time,KB'

# Convert time to seconds (including milliseconds) and start from 0
df['time_dt'] = pd.to_datetime(df['time'], format='%H:%M:%S.%f')
df['time_seconds'] = (df['time_dt'] - df['time_dt'].min()).dt.total_seconds()

# Convert KB to GB
df['RAM_GB'] = df['KB'] / (1024**2)

# Set professional style
sns.set_style("whitegrid")

# Create plot
plt.figure(figsize=(10,6))
plt.plot(
    df['time_seconds'], 
    df['RAM_GB'], 
    marker='o', markersize=2, linewidth=2, color='tab:blue',
    label='RAM Usage'
)

# Labels and title
plt.title('RAM Usage Over Time', fontsize=16, fontweight='bold')
plt.xlabel("Time (s)", fontsize=16)
plt.ylabel("RAM (GB)", fontsize=16)
plt.xticks(fontsize=14)
plt.yticks(fontsize=14)
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend(loc='upper left', fontsize=14)
plt.tight_layout()

# Save figure
plt.savefig(f"{output_file_name}_ram_usage.png", dpi=300)

print("Plot completed.")
