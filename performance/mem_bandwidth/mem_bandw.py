import subprocess
import json
import csv
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np

def run_iperf3(nstream, server="127.0.0.1", port=5201, duration=5):
    """
    Run iperf3 with the given number of streams and return throughput in Gbps.
    """
    cmd = [
        "iperf3",
        "-c", server,
        "-p", str(port),
        "-P", str(nstream),
        "-t", str(duration),
        "--json"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        total_bps = data["end"]["sum_sent"]["bits_per_second"]
        return total_bps / 1e9  # Gbps
    except subprocess.CalledProcessError as e:
        print(f"Error running iperf3 with {nstream} streams: {e}")
        return None
    except (KeyError, json.JSONDecodeError) as e:
        print(f"Failed to parse iperf3 output for {nstream} streams: {e}")
        return None


def collect_data(min_stream, max_stream, output_csv, server, port, duration):
    """
    Run iperf3 tests and save results immediately to CSV.
    """
    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["nstream", "max throughput (Gbps)"])

        for n in range(min_stream, max_stream + 1):
            print(f"[*] Running test with {n} streams...")
            throughput = run_iperf3(n, server, port, duration)
            if throughput is not None:
                bidirectional = throughput * 2  # optional bidirectional adjustment
                writer.writerow([n, bidirectional])
                f.flush()
                print(f"   -> Recorded: {bidirectional:.2f} Gbps")


def plot_data(output_csv):
    df = pd.read_csv(output_csv)
    last_n = min(20, len(df))
    asymptote_value = df["max throughput (Gbps)"].tail(last_n).mean()

    # --- Filter outliers (±2σ) ---
    y = df["max throughput (Gbps)"].values
    mean_y = np.mean(y)
    std_y = np.std(y)
    mask = (y > mean_y - 2*std_y) & (y < mean_y + 2*std_y)
    x_filtered = df["nstream"].values[mask]
    y_filtered = y[mask]

    sns.set_style("whitegrid")
    plt.figure(figsize=(10,6))

    # Main points
    plt.plot(
        df["nstream"],
        df["max throughput (Gbps)"],
        marker='o', markersize=3, linewidth=2,
        color='tab:blue', label="Throughput"
    )

    # Asymptote line
    plt.axhline(
        asymptote_value, color="tab:blue", linestyle='--',
        linewidth=2, alpha=0.7,
        label=f"Average Max: {asymptote_value:.2f} Gbps"
    )

    plt.title("Max Throughput vs Number of Streams", fontsize=16, fontweight="bold")
    plt.xlabel("Number of Streams", fontsize=14)
    plt.ylabel("Max Throughput (Gbps)", fontsize=14)
    plt.xticks(fontsize=12)
    plt.yticks(fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(loc="best", fontsize=12)
    plt.tight_layout()

    output_file_name = os.path.splitext(output_csv)[0]
    plt.savefig(f"{output_file_name}_plot.png", dpi=300)
    print(f"[+] Plot saved as {output_file_name}_plot.png")
    print(f"Asymptote value (avg last {last_n} points): {asymptote_value:.2f} Gbps")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run iperf3 tests or plot results from CSV")
    parser.add_argument("--min_stream", type=int, default=1, help="Minimum number of streams")
    parser.add_argument("--max_stream", type=int, default=8, help="Maximum number of streams")
    parser.add_argument("--output", type=str, default="iperf3_results.csv", help="CSV filename")
    parser.add_argument("--server", type=str, default="127.0.0.1", help="Iperf3 server address")
    parser.add_argument("--port", type=int, default=5201, help="Iperf3 server port")
    parser.add_argument("--duration", type=int, default=5, help="Test duration in seconds")
    parser.add_argument("--plot-only", action="store_true", help="Skip running tests, just plot existing CSV")
    args = parser.parse_args()

    if not args.plot_only:
        collect_data(args.min_stream, args.max_stream, args.output, args.server, args.port, args.duration)

    plot_data(args.output)
