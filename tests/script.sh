
lmenozzi  641534  640354    0    9 09:15 pts/1    00:00:00 ./rdma_server 3 1
lmenozzi  641534  640354    0    9 09:15 pts/1    00:00:00 ./rdma_server 3 1
lmenozzi  641534  640354   99    9 09:15 pts/1    00:00:58 ./rdma_server 3 1
lmenozzi  641534  640354   99    9 09:15 pts/1    00:00:58 ./rdma_server 3 1
lmenozzi  641534  640354   99    9 09:15 pts/1    00:00:58 ./rdma_server 3 1
lmenozzi  641534  640354   99    9 09:15 pts/1    00:00:58 ./rdma_server 3 1
lmenozzi  641534  640354   99    9 09:15 pts/1    00:00:58 ./rdma_server 3 1
lmenozzi  641534  640354    0    9 09:15 pts/1    00:00:00 ./rdma_server 3 1
lmenozzi  641534  640354   99    9 09:15 pts/1    00:00:58 ./rdma_server 3 1

ps -eLf | grep rdma_server


THREADS="641534 641535 641536 641537 641538 641539 641540 641541 641542"

CORE=0
for TID in $THREADS; do
  echo "Pin TID $TID on core $CORE"
  sudo taskset -cp $CORE $TID

  OUTPUT_FILE="core_${CORE}.data"
  rm -f $OUTPUT_FILE
  echo "Profile TID $TID on core $CORE, output -> $OUTPUT_FILE"
  sudo perf record -C $CORE -F 99 -g -o $OUTPUT_FILE -- sleep 12 &

  CORE=$((CORE+1))
done
wait



N_THREADS=$(echo $THREADS | wc -w)
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

    echo "Flamegraph generato: $OUT_DIR/$FLAMEGRAPH_OUT"

    rm "$SCRIPT_OUT" "$FOLDED_OUT"
done