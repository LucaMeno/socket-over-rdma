#!/bin/bash

OUTPUT_FILE_CPU="res_cpu_per_th.log"

# clear the file at the start
> "$OUTPUT_FILE_CPU"

PID=$(pgrep -n scap)

if [ -z "$PID" ]; then
    echo "No process named 'scap' found."
    exit 1
fi

# Log CPU usage (-u) every 1 second
pidstat -p "$PID" -u -t 1 >> "$OUTPUT_FILE_CPU" 2>&1
