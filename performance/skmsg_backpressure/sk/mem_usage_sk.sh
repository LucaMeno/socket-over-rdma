#!/bin/bash

# Output file
OUTPUT_FILE="ss_log.log"

# Clear the file at the start
> "$OUTPUT_FILE"

# Infinite loop
while true; do
    # Add timestamp and command output
    echo "=== $(date +'%Y-%m-%d %H:%M:%S.%3N') ===" >> "$OUTPUT_FILE"
    ss -m | grep -E '5555|8888' -A 1 >> "$OUTPUT_FILE"
    # Pause for 50 ms
    # sleep 0.05
done
