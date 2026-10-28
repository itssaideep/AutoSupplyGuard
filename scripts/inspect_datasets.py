import os
import json
import pandas as pd
import openpyxl

def audit_wild_sboms():
    print("=== AUDIT: Wild SBOMs (Zenodo 17397281) ===")
    meta_path = "data/raw/wild_sboms/sboms-01.csv"
    fn_path = "data/raw/wild_sboms/sboms-02-filenames.csv"
    
    if os.path.exists(meta_path):
        df_meta = pd.read_csv(meta_path)
        print(f"Total SBOM records: {len(df_meta):,}")
        print("Columns:", df_meta.columns.tolist())
        print("Standard distribution:\n", df_meta['standard'].value_counts(dropna=False).to_dict())
        print("Format distribution:\n", df_meta['format'].value_counts(dropna=False).to_dict())
        print("Version distribution:\n", df_meta['version'].value_counts(dropna=False).head(10).to_dict())
        print("Score summary (NTIA-based quality):\n", df_meta['score'].describe().to_dict())
    
    if os.path.exists(fn_path):
        df_fn = pd.read_csv(fn_path)
        print(f"\nTotal filename records: {len(df_fn):,}, Unique sha1s: {df_fn['sha1'].nunique():,}")
        print("Top 10 filenames:\n", df_fn['filename'].value_counts().head(10).to_dict())

def audit_curated_sboms():
    print("\n=== AUDIT: Curated SBOMs Benchmark (Zenodo 14808410 / arXiv:2504.06880) ===")
    extracted_dir = "data/raw/curated_sboms/extracted"
    if os.path.exists(extracted_dir):
        projects = [d for d in os.listdir(extracted_dir) if os.path.isdir(os.path.join(extracted_dir, d))]
        print(f"Total curated projects: {len(projects)}")
        total_packages = 0
        total_relationships = 0
        formats = {}
        for p in projects:
            spdx_path = os.path.join(extracted_dir, p, "sbom.spdx.json")
            if os.path.exists(spdx_path):
                with open(spdx_path, 'r', encoding='utf-8') as f:
                    doc = json.load(f)
                    ver = doc.get('spdxVersion', 'Unknown')
                    formats[ver] = formats.get(ver, 0) + 1
                    total_packages += len(doc.get('packages', []))
                    total_relationships += len(doc.get('relationships', []))
        print("SPDX Versions:", formats)
        print(f"Total packages across curated benchmark: {total_packages:,}")
        print(f"Total relationships across curated benchmark: {total_relationships:,}")

def audit_automotive_vulnerabilities():
    print("\n=== AUDIT: Connected Vehicles Vulnerabilities (Basu et al. / SriAbir) ===")
    excel_path = "data/raw/automotive_vulnerabilities/CV_Vulnerability_22-24/GitHubAutomotiveVulnerabilities_2022_2024.xlsx"
    if os.path.exists(excel_path):
        xl = pd.ExcelFile(excel_path)
        print("Sheets found:", xl.sheet_names)
        total_rows = 0
        all_cves = set()
        for sheet in xl.sheet_names:
            df = xl.parse(sheet)
            total_rows += len(df)
            cve_col = None
            for col in df.columns:
                if 'vul' in str(col).lower() or 'cve' in str(col).lower():
                    cve_col = col
                    break
            if cve_col:
                cves = df[cve_col].dropna().astype(str).str.strip().tolist()
                valid_cves = [c for c in cves if 'CVE-' in c]
                all_cves.update(valid_cves)
                print(f"Sheet '{sheet}': {len(df)} rows, {len(valid_cves)} CVEs (col='{cve_col}')")
            else:
                # check first row / values
                first_col = df.columns[0]
                if 'CVE-' in str(first_col):
                    valid_cves = [str(first_col)] + [str(x).strip() for x in df[first_col].dropna() if 'CVE-' in str(x)]
                    all_cves.update(valid_cves)
                    print(f"Sheet '{sheet}': {len(df)} rows, {len(valid_cves)} CVEs (headerless)")
                else:
                    print(f"Sheet '{sheet}': {len(df)} rows, no CVE col recognized")
        print(f"Total rows across all sheets: {total_rows}")
        print(f"Total unique CVE identifiers identified: {len(all_cves)}")

if __name__ == '__main__':
    audit_wild_sboms()
    audit_curated_sboms()
    audit_automotive_vulnerabilities()
