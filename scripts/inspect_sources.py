import urllib.request
import json
import sys

def inspect_zenodo(record_id):
    url = f"https://zenodo.org/api/records/{record_id}"
    print(f"=== Inspecting Zenodo Record {record_id} ===")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'AutoSupplyGuard/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            meta = data.get('metadata', {})
            print("Title:", meta.get('title'))
            print("DOI:", data.get('doi'))
            print("License:", meta.get('license', {}).get('id'))
            print("Publication Date:", meta.get('publication_date'))
            print("Description length:", len(meta.get('description', '')))
            files = data.get('files', [])
            print(f"Total files: {len(files)}")
            for f in files[:20]:
                key = f.get('key')
                size = f.get('size', 0)
                mb = size / (1024 * 1024)
                print(f" - {key}: {size} bytes ({mb:.2f} MB)")
            return data
    except Exception as e:
        print(f"Error fetching {record_id}: {e}")
        return None

if __name__ == '__main__':
    # Wild SBOMs
    inspect_zenodo('17397281')
    print("\n" + "="*50 + "\n")
    # Curated SBOM benchmark
    inspect_zenodo('14808410')
