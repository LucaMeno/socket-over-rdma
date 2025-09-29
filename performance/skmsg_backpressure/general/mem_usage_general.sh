#!/bin/bash

OUTPUT="ram_log.csv"

if [ ! -f "$OUTPUT" ]; then
    echo "time,KB" > "$OUTPUT"
fi

while true; do
    # Ottieni timestamp
    TIME=$(date +%H:%M:%S.%3N)
    
    RAM_USED=$(awk '/MemTotal/ {total=$2} /MemAvailable/ {avail=$2} END {print total-avail}' /proc/meminfo)
    
    echo "$TIME,$RAM_USED" >> "$OUTPUT"

    #sleep 0.05
done
