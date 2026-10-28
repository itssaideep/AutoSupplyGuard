"""Experiment 4: Scalability, Robustness, and Runtime/Memory Profiling (RQ4)."""

import time
import tracemalloc
from pathlib import Path
import pandas as pd
from app.ingestion.manager import SBOMIngestionManager
from app.sbom_quality.calculator import QualityAssessmentEngine
from app.traceability.graph import TraceabilityGraph

RESULTS_DIR = Path("research/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def run_experiment_4():
    print("=== Running Experiment 4: Scalability & Graph Robustness (RQ4) ===")
    curated_dir = Path("data/raw/curated_sboms/extracted")
    if not curated_dir.exists():
        print("[ERROR] Curated SBOMs directory not found.")
        return
        
    all_files = [d / "sbom.spdx.json" for d in curated_dir.iterdir() if (d / "sbom.spdx.json").exists()]
    batch_sizes = [1, 5, 10, 20, 35, len(all_files)]
    
    results = []
    
    for b_size in batch_sizes:
        target_files = all_files[:b_size]
        manager = SBOMIngestionManager()
        quality_engine = QualityAssessmentEngine()
        graph = TraceabilityGraph()
        
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
        
        peak_mb = peak_mem / (1024 * 1024)
        throughput_sboms_per_sec = b_size / elapsed_sec if elapsed_sec > 0 else 0.0
        throughput_comps_per_sec = total_comps / elapsed_sec if elapsed_sec > 0 else 0.0
        
        results.append({
            "batch_size_sboms": b_size,
            "total_components": total_comps,
            "total_dependencies": total_deps,
            "elapsed_seconds": round(elapsed_sec, 4),
            "peak_memory_mb": round(peak_mb, 2),
            "sboms_per_sec": round(throughput_sboms_per_sec, 2),
            "comps_per_sec": round(throughput_comps_per_sec, 2),
            "graph_nodes": graph.graph.number_of_nodes(),
            "graph_edges": graph.graph.number_of_edges()
        })
        
        print(f"Batch {b_size:2d} SBOMs: {total_comps:4d} comps | Time: {elapsed_sec:.3f}s | Peak RAM: {peak_mb:.2f} MB | Throughput: {throughput_comps_per_sec:.1f} comps/s")
    
    df = pd.DataFrame(results)
    output_csv = RESULTS_DIR / "experiment_4_results.csv"
    df.to_csv(output_csv, index=False)
    print(f"[OK] Experiment 4 completed. Saved raw results to {output_csv}")

if __name__ == '__main__':
    run_experiment_4()
