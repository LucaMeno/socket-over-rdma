import subprocess
import csv
import matplotlib.pyplot as plt
import re

# ===== Configurazione =====
REDIS_HOST = "10.0.0.3"
NUM_REQUESTS = 1000000
CONCURRENCY = 10
DATA_SIZE = 2048
OPERATIONS = "SET,GET,HSET,HGET,LPUSH,LPOP"
OUTPUT_CSV = "redis_benchmark.csv"
OUTPUT_PNG = "redis_benchmark.png"

# ===== Eseguire il benchmark =====
print("Eseguendo redis-benchmark...")
benchmark_cmd = [
    "redis-benchmark",
    "-h", REDIS_HOST,
    "-n", str(NUM_REQUESTS),
    "-c", str(CONCURRENCY),
    "-d", str(DATA_SIZE),
    "-t", OPERATIONS,
    "-q"  # modalità compatta
]

try:
    process = subprocess.Popen(benchmark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Dizionario per tenere solo l'ultima riga per operazione
    last_values = {}

    print("Processo avviato, leggendo output...")
    for line in process.stdout:
        line = line.strip()
        if not line:
            continue
        print("DEBUG OUTPUT:", line)

        # Regex per catturare operation e overall ops/sec
        match = re.search(r"(\w+):\s*([\d.]+)\s*requests per second", line)
        if match:
            operation = match.group(1)
            ops_per_sec = float(match.group(2))
            last_values[operation] = ops_per_sec

    process.wait()
    print("Benchmark completato, codice di uscita:", process.returncode)

    stderr_output = process.stderr.read()
    if stderr_output:
        print("DEBUG ERROR:", stderr_output)

except Exception as e:
    print("Errore nell'esecuzione del benchmark:", e)

# ===== Salvare CSV =====
with open(OUTPUT_CSV, "w", newline="") as csvfile:
    fieldnames = ["operation", "ops_per_sec"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for op, ops in last_values.items():
        writer.writerow({"operation": op, "ops_per_sec": ops})

print(f"Dati salvati in {OUTPUT_CSV}")

# ===== Salvare grafico in PNG =====
operations = list(last_values.keys())
ops = [last_values[op] for op in operations]

plt.bar(operations, ops, color="skyblue")
plt.ylabel("Operations per second")
plt.title("Redis Benchmark")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(OUTPUT_PNG)
plt.close()

print(f"Grafico salvato in {OUTPUT_PNG}")
