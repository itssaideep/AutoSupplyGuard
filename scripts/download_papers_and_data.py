import os
import hashlib
import json
import urllib.request
import zipfile

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 AutoSupplyGuard/1.0'
}

def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()

def download_file(url, dest_path, force=False):
    if os.path.exists(dest_path) and not force and os.path.getsize(dest_path) > 0:
        print(f"[SKIP] {dest_path} already exists ({os.path.getsize(dest_path)} bytes)")
        return dest_path, calculate_sha256(dest_path), os.path.getsize(dest_path)

    print(f"[DOWNLOADING] {url} -> {dest_path}")
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=60) as resp:
            with open(dest_path, 'wb') as f:
                while chunk := resp.read(65536):
                    f.write(chunk)
        size = os.path.getsize(dest_path)
        sha = calculate_sha256(dest_path)
        print(f"[OK] Downloaded {dest_path}: {size} bytes, sha256={sha[:12]}...")
        return dest_path, sha, size
    except Exception as e:
        print(f"[ERROR] Failed to download {url}: {e}")
        if os.path.exists(dest_path):
            os.remove(dest_path)
        return None, None, 0

def main():
    manifest = []

    # 1. Zenodo 14808410 (Curated SBOMs)
    curated_url = "https://zenodo.org/api/records/14808410/files/sbom-dataset-20250205_1722.zip/content"
    curated_zip = os.path.join("data", "raw", "curated_sboms", "sbom-dataset-20250205_1722.zip")
    p, sha, sz = download_file(curated_url, curated_zip)
    if p:
        manifest.append({
            "dataset": "Curated SBOMs Benchmark",
            "source_url": curated_url,
            "local_path": curated_zip,
            "sha256": sha,
            "size_bytes": sz,
            "license": "CC-BY-4.0"
        })
        # Unzip into data/raw/curated_sboms/extracted
        extract_dir = os.path.join("data", "raw", "curated_sboms", "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(curated_zip, 'r') as zf:
                zf.extractall(extract_dir)
            print(f"[OK] Extracted curated SBOMs to {extract_dir}")
        except Exception as e:
            print(f"[ERROR] Extracting curated zip: {e}")

    # 2. Zenodo 17397281 (Wild SBOMs - metadata & README & analysis)
    wild_files = [
        ("README.md", "https://zenodo.org/api/records/17397281/files/README.md/content"),
        ("sboms-01.csv.zstd", "https://zenodo.org/api/records/17397281/files/sboms-01.csv.zstd/content"),
        ("analysis.tar.zstd", "https://zenodo.org/api/records/17397281/files/analysis.tar.zstd/content"),
        ("clear-extensions.txt.zstd", "https://zenodo.org/api/records/17397281/files/clear-extensions.txt.zstd/content"),
        ("regex-generic.txt.zstd", "https://zenodo.org/api/records/17397281/files/regex-generic.txt.zstd/content")
    ]
    for fname, url in wild_files:
        dest = os.path.join("data", "raw", "wild_sboms", fname)
        p, sha, sz = download_file(url, dest)
        if p:
            manifest.append({
                "dataset": "Wild SBOMs",
                "source_url": url,
                "local_path": dest,
                "sha256": sha,
                "size_bytes": sz,
                "license": "CC-BY-4.0"
            })

    # 3. Research Papers
    papers = [
        ("wild_sboms_msr2025.pdf", "https://upsilon.cc/~zack/research/publications/msr-2025-sbom-dataset.pdf"),
        ("curated_sboms_arxiv2504.pdf", "https://arxiv.org/pdf/2504.06880"),
        ("sbom_slr_arxiv2506.pdf", "https://arxiv.org/pdf/2506.03507"),
        ("security_assurance_cases_chalmers.pdf", "https://research.chalmers.se/publication/523713/fulltext/523713_Fulltext.pdf"),
        ("multi_tier_supply_chain_mdpi.pdf", "https://www.mdpi.com/2071-1050/12/5/1814/pdf")
    ]

    for fname, url in papers:
        dest = os.path.join("research", "papers", fname)
        p, sha, sz = download_file(url, dest)
        if p:
            manifest.append({
                "paper": fname,
                "source_url": url,
                "local_path": dest,
                "sha256": sha,
                "size_bytes": sz
            })

    # Save manifest
    manifest_file = os.path.join("data", "manifests", "initial_download_manifest.json")
    with open(manifest_file, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[OK] Manifest saved to {manifest_file} with {len(manifest)} entries.")

if __name__ == '__main__':
    main()
