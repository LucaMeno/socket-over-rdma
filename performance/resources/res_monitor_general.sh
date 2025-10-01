#!/bin/bash

OUTPUT_FILE_CPU="res_cpu_general_iperf3_TCP.log"

# clear the file at the start
> "$OUTPUT_FILE_CPU"

#PID=3294504

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

numactl --cpunodebind=0 --membind=0 iperf3 -c 10.0.0.4 -p 9999 -t 30 &
PID=$!

#mpstat 1 >> "$OUTPUT_FILE_CPU" 2>&1

pidstat -u -p $PID 1 >> "$OUTPUT_FILE_CPU" 2>&1

kill $BG_PID