# Git History Rewriting & Blob Governance Notice

## History Rewriting Rationale

In Milestone 9/Engineering Hardening (Phase 1, Step A5), the Git commit history of `AutoSupplyGuard` was rewritten using `git filter-branch` to purge an uncompressed 108.5 MB dataset file (`data/raw/wild_sboms/sboms-02-filenames.csv`). 

GitHub strictly rejects commits containing any object exceeding **100.00 MB** (`GH001: Large files detected`).

## Instructions for Collaborators & Existing Clones

Because commit hashes prior to commit `bf68ac7` were rewritten:
- **Existing Local Clones:** Must synchronize their tracking branch by fetching and resetting:
  ```bash
  git fetch origin
  git reset --hard origin/main
  ```
- **New Clones:** Are completely unaffected (`git clone https://github.com/itssaideep/AutoSupplyGuard.git`).

## Preservation of Dataset Integrity

No data was lost:
1. The full file list remains permanently available in the repository in its compressed form: `data/raw/wild_sboms/sboms-02-filenames.csv.zstd` (26.8 MB).
2. The complete metadata for all 78,612 Wild SBOMs is preserved in `data/raw/wild_sboms/sboms-01.csv` (11.8 MB).
3. The automated dataset fetcher (`python -m scripts.fetch_data --verify-only`) verifies all file checksums against `data/manifests/dataset_manifest.json`.
4. Pre-commit hooks (`check-added-large-files --maxkb=51200`) and CI checks now prevent any file larger than 50 MB from ever being committed.
