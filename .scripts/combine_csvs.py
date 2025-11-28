#!/usr/bin/env python3
"""
combine_csvs.py

Combine two CSV files (benign.csv and malware.csv) into a single CSV
and randomly shuffle the rows. Defaults to files in `archive/`.

Usage:
    python .\\script\\combine_csvs.py
    python .\\script\\combine_csvs.py --benign archive/benign.csv --malware archive/malware.csv --out archive/combined_random.csv

"""
import csv
import random
import argparse
from pathlib import Path


def load_rows(path):
    rows = []
    header = None
    with path.open(newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if i == 0:
                header = row
                continue
            rows.append(row)
    return header, rows


def write_rows(path, header, rows):
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if header:
            writer.writerow(header)
        for r in rows:
            writer.writerow(r)


def main():
    parser = argparse.ArgumentParser(description='Combine and shuffle two CSV files')
    parser.add_argument('--benign', default='archive/benign.csv', help='Path to benign CSV')
    parser.add_argument('--malware', default='archive/malware.csv', help='Path to malware CSV')
    parser.add_argument('--out', default='archive/combined_random.csv', help='Output combined CSV path')
    parser.add_argument('--seed', type=int, default=None, help='Optional random seed for reproducibility')
    args = parser.parse_args()

    benign_path = Path(args.benign)
    malware_path = Path(args.malware)
    out_path = Path(args.out)

    if args.seed is not None:
        random.seed(args.seed)

    if not benign_path.exists():
        print(f"Benign file not found: {benign_path}")
        return
    if not malware_path.exists():
        print(f"Malware file not found: {malware_path}")
        return

    # Load both files
    h1, rows1 = load_rows(benign_path)
    h2, rows2 = load_rows(malware_path)

    # Prefer header from first file; if it is empty, try second
    header = h1 if h1 else h2

    combined = rows1 + rows2
    random.shuffle(combined)

    # Ensure output directory exists
    out_path.parent.mkdir(parents=True, exist_ok=True)

    write_rows(out_path, header, combined)

    print(f"Wrote {len(combined)} rows to {out_path} (header columns: {len(header) if header else 0})")

if __name__ == '__main__':
    main()
