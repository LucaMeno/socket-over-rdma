#!/bin/bash

# git clone https://github.com/brendangregg/FlameGraph.git

ps -eLf | grep scap

THREADS=($(ps -eLf | awk '/scap/ && !/awk/ {print $4}'))

echo "${THREADS[@]}"

CORE=0
for TID in "${THREADS[@]}"; do
  echo "Pin TID $TID on core $CORE"
  sudo taskset -cp $CORE $TID

  OUTPUT_FILE="core_${CORE}.data"
  rm -f $OUTPUT_FILE
  echo "Profile TID $TID on core $CORE, output -> $OUTPUT_FILE"
  sudo perf record -C $CORE -F 99 -g -o $OUTPUT_FILE -- sleep 15 &

  CORE=$((CORE+1))
done
wait



N_THREADS=${#THREADS[@]}
FLAMEGRAPH_DIR=FlameGraph
OUT_DIR=flamegraphs
mkdir -p $OUT_DIR

for CORE in $(seq 0 $((N_THREADS-1))); do
    PERF_FILE="core_${CORE}.data"
    SCRIPT_OUT="out_${CORE}.perf"
    FOLDED_OUT="out_${CORE}.folded"
    FLAMEGRAPH_OUT="flamegraph_core_${CORE}.svg"

    echo "Processing $PERF_FILE ..."

    perf script -i "$PERF_FILE" > "$SCRIPT_OUT"

    "$FLAMEGRAPH_DIR/stackcollapse-perf.pl" "$SCRIPT_OUT" > "$FOLDED_OUT"

    "$FLAMEGRAPH_DIR/flamegraph.pl" "$FOLDED_OUT" > "$OUT_DIR/$FLAMEGRAPH_OUT"

    echo "Flamegraph generated: $OUT_DIR/$FLAMEGRAPH_OUT"

    rm "$SCRIPT_OUT" "$FOLDED_OUT"
    rm "$PERF_FILE"
done