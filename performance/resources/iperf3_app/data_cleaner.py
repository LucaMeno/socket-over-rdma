import csv
import argparse
from collections import defaultdict

# Set up command-line arguments
parser = argparse.ArgumentParser(description="Parse pidstat output into CSVs per thread.")
parser.add_argument("input_file", help="Path to the pidstat output file")
args = parser.parse_args()

input_file = args.input_file

# Dictionary to store data for each thread
threads_data = defaultdict(list)
scap_data = []

with open(input_file, "r") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("13:30:20"):  # Skip header or empty lines
            continue

        parts = line.split()
        # Skip scap child threads
        if parts[-1] == "|__scap":
            continue

        # Extract info
        timestamp = parts[0]
        uid = parts[1]
        tgid = parts[2]
        tid = parts[3]
        usr = parts[4]
        system = parts[5]
        guest = parts[6]
        wait = parts[7]
        cpu = parts[8]
        core = parts[9]
        command = parts[-1]

        row = [timestamp, uid, tgid, tid, usr, system, guest, wait, cpu, core]

        # Separate scap from specific threads
        if command == "scap":
            scap_data.append(row)
        else:
            threads_data[command].append(row)

# Function to write CSV if at least one %CPU > 0
def write_csv_if_active(filename, data):
    if any(float(row[8]) > 0 for row in data):
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp","UID","TGID","TID","%usr","%system","%guest","%wait","%CPU","CPU"])
            writer.writerows(data)

# Write scap CSV if active
write_csv_if_active("scap.csv", scap_data)

# Write CSV for each thread if active
for thread, data in threads_data.items():
    write_csv_if_active(f"{thread}.csv", data)

print("CSV files generated successfully (only threads with non-zero CPU).")
