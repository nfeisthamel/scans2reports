import pickle
import os
import sys
from types import ModuleType
from openpyxl import Workbook

# --- Dummy classes ---
class ScanFile(dict):
    def __init__(self, data):
        dict.__init__(self)
        self['requirements'] = []
        for key in data:
            self[key] = data[key] if key in data else ''

    def add_requirement(self, req):
        self['requirements'].append(req)

class ScanRequirement(dict):
    def __init__(self, data):
        dict.__init__(self)
        for key in data:
            self[key] = data[key]

    def get(self, key, default=None):
        return super().get(key, default)

# --- Simulate module paths used by pickle ---
sys.modules["scan_file"] = ModuleType("scan_file")
sys.modules["scan_file"].ScanFile = ScanFile
sys.modules["scan_requirement"] = ModuleType("scan_requirement")
sys.modules["scan_requirement"].ScanRequirement = ScanRequirement

# --- Replace pathlib.*Path with this ---
class FakePath(str):
    def __new__(cls, *args, **kwargs):
        return str.__new__(cls, os.path.join(*args))

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "pathlib" and name in ("WindowsPath", "PosixPath"):
            return FakePath
        return super().find_class(module, name)

def load_scan_results(path):
    with open(path, "rb") as f:
        return SafeUnpickler(f).load()

def flatten_results(scan_results):
    flat_rows = []
    for entry in scan_results:
        base = {k: entry.get(k, '') for k in entry if k != 'requirements'}

        for req in entry.get('requirements', []):
            row = base.copy()
            row.update(req)
            flat_rows.append(row)
    return flat_rows

def export_to_excel(rows, output_path):
    if not rows:
        print("[!] No data to write.")
        return

    wb = Workbook()
    ws = wb.active
    ws.title = "Scan Results"

    # Extract all headers
    headers = sorted({key for row in rows for key in row})
    ws.append(headers)

    for row in rows:
        ws.append([row.get(h, '') for h in headers])

    wb.save(output_path)
    print(f"[+] Exported {len(rows)} rows to: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python export_scan_results_to_excel.py scan_results.pkl")
        sys.exit(1)

    pkl_path = sys.argv[1]
    if not os.path.isfile(pkl_path):
        print(f"[!] File not found: {pkl_path}")
        sys.exit(1)

    try:
        results = load_scan_results(pkl_path)
        flat_data = flatten_results(results)
        output_excel = os.path.splitext(pkl_path)[0] + "_export.xlsx"
        export_to_excel(flat_data, output_excel)
    except Exception as e:
        print(f"[!] Error: {e}")
