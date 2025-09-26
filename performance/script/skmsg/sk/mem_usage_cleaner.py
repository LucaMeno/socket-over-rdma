import csv
import re

log_file = 'ss_log.log'
csv_file = 'output.csv'

timestamp_re = re.compile(r"=== \d{4}-\d{2}-\d{2} (\d{2}:\d{2}:\d{2}\.\d+) ===")
tcp_re = re.compile(r"tcp\s+\S+\s+\d+\s+\d+\s+\S+:(\d+)\s+\S+:(\d+)")
skmem_re = re.compile(r"skmem:\((.*?)\)")

data = []

current_time = None
last_tcp = None

with open(log_file, 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        # Timestamp
        ts_match = timestamp_re.match(line)
        if ts_match:
            current_time = ts_match.group(1)
            continue

        # TCP line
        tcp_match = tcp_re.match(line)
        if tcp_match:
            last_tcp = {
                'time': current_time,
                'portsrc': tcp_match.group(1),
                'portdest': tcp_match.group(2)
            }
            continue

        # SKMEM line
        skmem_match = skmem_re.search(line)
        if skmem_match and last_tcp:
            sk_fields = skmem_match.group(1).split(',')
            row = last_tcp.copy()
            for field in sk_fields:
                # Separate key and value
                m = re.match(r'([a-z]+)(\d*)', field)
                if m:
                    key = m.group(1)
                    value = m.group(2) if m.group(2) else '0'
                    row[key] = value
            data.append(row)
            last_tcp = None  # reset

# Determine all keys for CSV
all_keys = set()
for row in data:
    all_keys.update(row.keys())

fieldnames = sorted(all_keys)
# Optional: put time, portsrc, portdest first
fieldnames = ['time', 'portsrc', 'portdest'] + [k for k in fieldnames if k not in ('time','portsrc','portdest')]

# Write CSV
with open(csv_file, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in data:
        # Ensure all fields exist
        for key in fieldnames:
            if key not in row:
                row[key] = ''
        writer.writerow(row)

print(f"CSV generato correttamente: {csv_file}")
