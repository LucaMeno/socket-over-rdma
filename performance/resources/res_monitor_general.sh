#!/bin/bash

OUTPUT_FILE_CPU="res_cpu_general_iperf3_base.log"

# clear the file at the start
> "$OUTPUT_FILE_CPU"

print_every_10s() {
    I=0
    while true; do
        echo "I: $I - $(date)"
        echo "I: $I - $(date)" >> "$OUTPUT_FILE_CPU"
        ((I=I+1))
        sleep 10
    done
}

print_every_10s &
BG_PID=$!

mpstat 1 >> "$OUTPUT_FILE_CPU" 2>&1

kill $BG_PID