"""Experiment 4: Scalability, Memory & Graph Performance Profiling (RQ4)."""

import argparse
import time
import tracemalloc
import psutil
import pandas as pd
from app.ingestion.manager import SBOMIngestionManager
from app.sbom_quality.calculator import QualityAssessmentEngine
from app.traceability.graph import TraceabilityGraph
from app.core.config import settings

RESULTS_DIR = settings.RESULTS_DIR
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def run_experiment_4(smoke: bool = False):
    print("=== Running Experiment 4: Scalability & Graph Robustness (RQ4) ===")
    curated_dir = settings.RAW_DATA_DIR / "curated_sboms" / "extracted"
    if not curated_dir.exists():
        print("[ERROR] Curated SBOMs directory not found.")
        return

    all_files = [d / "sbom.spdx.json" for d in curated_dir.iterdir() if (d / "sbom.spdx.json").exists()]
    batch_sizes = [1, 3] if smoke else [1, 5, 10, 20, 35, len(all_files)]

    results = []
    process = psutil.Process()

    for b_size in batch_sizes:
        target_files = all_files[:b_size]
        manager = SBOMIngestionManager()
        quality_engine = QualityAssessmentEngine()
        graph = TraceabilityGraph()

        rss_start = process.memory_info().rss / (1024 * 1024)
        tracemalloc.start()
        start_time = time.perf_counter()

        total_comps = 0
        total_deps = 0

        for f in target_files:
            parsed = manager.parse_file(f)
            quality_engine.assess(parsed)
            graph.add_sbom_result(parsed)
            total_comps += len(parsed.components)
            total_deps += len(parsed.dependencies)

        elapsed_sec = time.perf_counter() - start_time
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rss_end = process.memory_info().rss / (1024 * 1024)

        peak_mb = peak_mem / (1024 * 1024)
        rss_diff_mb = max(0.0, rss_end - rss_start)
        throughput_sboms_per_sec = b_size / elapsed_sec if elapsed_sec > 0 else 0.0
        throughput_comps_per_sec = total_comps / elapsed_sec if elapsed_sec > 0 else 0.0

        results.append({
            "batch_size_sboms": b_size,
            "total_components": total_comps,
            "total_dependencies": total_deps,
            "elapsed_seconds": round(elapsed_sec, 4),
            "peak_memory_mb": round(peak_mb, 2),
            "rss_delta_mb": round(rss_diff_mb, 2),
            "sboms_per_sec": round(throughput_sboms_per_sec, 2),
            "comps_per_sec": round(throughput_comps_per_sec, 2),
            "graph_nodes": graph.graph.number_of_nodes(),
            "graph_edges": graph.graph.number_of_edges()
        })

        print(f"Batch {b_size:2d} SBOMs: {total_comps:4d} comps | Time: {elapsed_sec:.3f}s | Peak Heap: {peak_mb:.2f} MB | RSS Delta: {rss_diff_mb:.2f} MB | Throughput: {throughput_comps_per_sec:.1f} comps/s")

    df = pd.DataFrame(results)
    output_csv = RESULTS_DIR / ("experiment_4_smoke.csv" if smoke else "experiment_4_results.csv")
    df.to_csv(output_csv, index=False)
    print(f"[OK] Experiment 4 completed. Saved raw results to {output_csv}")

def main():
    parser = argparse.ArgumentParser(description="Run Experiment 4 (RQ4).")
    parser.add_argument("--smoke", action="store_true", help="Run in smoke test mode.")
    args = parser.parse_args()
    run_experiment_4(smoke=args.smoke)

if __name__ == '__main__':
    main()
