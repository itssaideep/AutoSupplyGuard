"""Reproducible dataset acquisition and SHA-256 integrity verification (A5)."""

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path
from typing import List, Dict, Any

MANIFEST_PATH = Path("data/manifests/dataset_manifest.json")

def verify_file_sha256(file_path: Path, expected_sha256: str) -> bool:
    """Computes SHA-256 of file and checks against expected digest."""
    if not file_path.exists():
        return False
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower() == expected_sha256.lower()

def fetch_and_verify_data(verify_only: bool = False, online: bool = False) -> bool:
    print("=== AutoSupplyGuard Dataset Integrity & Acquisition ===")
    if not MANIFEST_PATH.exists():
        print(f"[ERROR] Manifest not found at {MANIFEST_PATH}")
        return False

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest: List[Dict[str, Any]] = json.load(f)

    all_ok = True

    for item in manifest:
        local_path = Path(item["local_path"])
        name = item["name"]
        expected_sha = item["sha256"]
        source_url = item["source_url"]

        if local_path.exists():
            if verify_file_sha256(local_path, expected_sha):
                print(f"[OK] Verified: {name} ({local_path.name})")
            else:
                print(f"[FAIL] Checksum mismatch for {local_path}!")
                all_ok = False
        else:
            if verify_only:
                print(f"[MISSING] {name} -> {local_path}")
                all_ok = False
            elif online:
                print(f"[FETCHING] Downloading {name} from {source_url}...")
                local_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    req = urllib.request.Request(
                        source_url,
                        headers={"User-Agent": "AutoSupplyGuard-DataFetcher/1.0"}
                    )
                    with urllib.request.urlopen(req) as resp, open(local_path, "wb") as out_file:
                        out_file.write(resp.read())
                    if verify_file_sha256(local_path, expected_sha):
                        print(f"[OK] Downloaded & verified: {name}")
                    else:
                        print(f"[FAIL] Downloaded file failed SHA-256 verification: {local_path}")
                        all_ok = False
                except Exception as e:
                    print(f"[ERROR] Failed to download {name}: {e}")
                    all_ok = False
            else:
                print(f"[MISSING] {name} is absent. Run with --online to fetch.")
                all_ok = False

    return all_ok

def main():
    parser = argparse.ArgumentParser(description="Fetch and verify dataset integrity.")
    parser.add_argument("--verify-only", action="store_true", help="Only verify existing local files.")
    parser.add_argument("--online", action="store_true", help="Allow online downloading of missing datasets.")
    args = parser.parse_args()

    success = fetch_and_verify_data(verify_only=args.verify_only, online=args.online)
    if not success and args.verify_only:
        exit(1)

if __name__ == "__main__":
    main()
