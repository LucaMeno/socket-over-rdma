import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import sys
import os

# Controllo parametro file
if len(sys.argv) <= 1:
    print('Missing file name argument\nUsage: python3 rtt_plotter.py rtt_log.txt')
    sys.exit(0)

input_file_name = sys.argv[1]
output_file_name = os.path.splitext(input_file_name)[0]

# Leggi valori RTT dal file
rtt_values = []
with open(input_file_name, 'r') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 4:
            rtt_values.append(int(parts[3]))

# DataFrame
df = pd.DataFrame({'RTT_us': rtt_values})
df['Index'] = df.index  # x-axis sarà solo l'indice

# Calcola media RTT
avg_rtt = df['RTT_us'].mean()

# Stile Seaborn
sns.set_style("whitegrid")

# Colore principale della linea
main_color = 'tab:blue'

# Crea il plot
plt.figure(figsize=(10,6))
plt.plot(
    df['Index'],
    df['RTT_us'],
    marker='o', markersize=4, linewidth=2, color=main_color,
    label=f'RTT (avg: {avg_rtt:.2f} us)'
)

# Linea media tratteggiata e sbiadita
plt.axhline(
    avg_rtt, color=main_color, linestyle='--', linewidth=2, alpha=0.4
)

# Etichette e titolo
plt.title('RTT Values', fontsize=16, fontweight='bold')
plt.xlabel("Packet Index", fontsize=14)
plt.ylabel("RTT (us)", fontsize=14)
plt.xticks(fontsize=12)
plt.yticks(fontsize=12)
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend(loc='lower right', fontsize=12)
plt.tight_layout()

# Salva immagine PNG
plt.savefig(f"{output_file_name}_rtt.png", dpi=300)

print(f"Plot saved as {output_file_name}_rtt.png")
print(f"Average RTT: {avg_rtt:.2f} us")
