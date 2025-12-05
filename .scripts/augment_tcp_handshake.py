#!/usr/bin/env python3
"""
augment_tcp_handshake.py

Generates archive/tcp_sequences_by_filename.jsonl by augmenting existing datasets
with synthetic TCP handshake sequences keyed by filename. This enables PDA validation
mapped to DFA-flagged filenames.

Inputs (searched under ./archive):
- Malicious_file_trick_detection.jsonl (expects entries with {filename, is_malicious} or similar)
- combined_random.csv (tries to infer columns; if none usable, skips rows)
- malware.csv (tries to infer columns)

Output:
- archive/tcp_sequences_by_filename.jsonl where each line is:
  {"trace_id": <filename>, "sequence": [...], "valid": <bool>, "description": <str>, "category": <str>}

Rules:
- For entries labeled malicious: generate invalid sequences (e.g., SYN only, wrong order, RST)
- For entries labeled benign: generate valid 3-way handshake sequences (optionally with DATA)

Note: This script is conservative: if it cannot find a filename per row, it skips the row.
"""
import json
import csv
import os
import random
from typing import Dict, List, Tuple

ARCHIVE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'archive')
OUT_PATH = os.path.join(ARCHIVE_DIR, 'unified_dataset.jsonl')

random.seed(311)

VALID_SEQS = [
    ["SYN", "SYN-ACK", "ACK"],
    ["SYN", "SYN-ACK", "ACK", "DATA", "ACK"],
    ["SYN", "SYN-ACK", "ACK", "FIN", "ACK"],
]
INVALID_SEQS = [
    ["SYN"],
    ["SYN", "SYN-ACK"],
    ["ACK"],
    ["SYN", "ACK"],
    ["RST"],
    ["ACK", "SYN", "SYN-ACK"],
]


def choose_sequence(is_malicious: bool) -> Tuple[List[str], bool, str, str]:
    if is_malicious:
        seq = random.choice(INVALID_SEQS)
        return seq, False, "Synthetic invalid handshake for malicious filename", "Derived Malicious"
    else:
        seq = random.choice(VALID_SEQS)
        return seq, True, "Synthetic valid handshake for benign filename", "Derived Benign"


def read_jsonl_filenames(path: str) -> List[Tuple[str, bool]]:
    out = []
    if not os.path.exists(path):
        return out
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            # Try common keys
            filename = obj.get('filename') or obj.get('name') or obj.get('file')
            if not filename:
                continue
            # Label inference
            is_mal = obj.get('is_malicious')
            if is_mal is None:
                cat = (obj.get('category') or '').lower()
                # Heuristic: category containing 'malicious' or technique known keywords
                is_mal = 'malicious' in cat or bool(obj.get('technique'))
            out.append((filename, bool(is_mal)))
    return out


def read_csv_filenames(path: str, default_malicious: bool = False) -> List[Tuple[str, bool]]:
    out = []
    if not os.path.exists(path):
        return out
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        # Detect candidate filename column
        fname_col = None
        for c in reader.fieldnames or []:
            lc = c.lower()
            if lc in ('filename', 'file', 'name', 'path'):
                fname_col = c
                break
        type_col = None
        for c in reader.fieldnames or []:
            if c.lower() == 'type':
                type_col = c
                break
        for row in reader:
            fn = None
            if fname_col:
                fn = row.get(fname_col)
            # if unavailable, try to synthesize a filename from hash columns (best-effort)
            if not fn:
                for key in ('sha256', 'md5', 'hash'):
                    if row.get(key):
                        fn = f"{row[key]}.bin"
                        break
            if not fn:
                continue
            # Determine label
            is_mal = default_malicious
            if type_col:
                # combined_random.csv convention: type=1 benign, type=0 malicious
                try:
                    tval = int(row.get(type_col, ''))
                    is_mal = (tval == 0)
                except Exception:
                    pass
            out.append((fn, is_mal))
    return out


def main():
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    jsonl_path = os.path.join(ARCHIVE_DIR, 'Malicious_file_trick_detection.jsonl')
    comb_path = os.path.join(ARCHIVE_DIR, 'combined_random.csv')
    malw_path = os.path.join(ARCHIVE_DIR, 'malware.csv')

    pairs: List[Tuple[str, bool]] = []
    pairs.extend(read_jsonl_filenames(jsonl_path))
    pairs.extend(read_csv_filenames(comb_path, default_malicious=False))
    pairs.extend(read_csv_filenames(malw_path, default_malicious=True))

    # Deduplicate preserving first occurrence
    seen = set()
    dedup: List[Tuple[str, bool]] = []
    for fn, mal in pairs:
        if fn in seen:
            continue
        seen.add(fn)
        dedup.append((fn, mal))

    count = 0
    with open(OUT_PATH, 'w', encoding='utf-8') as out:
        for filename, is_mal in dedup:
            seq, valid, desc, cat = choose_sequence(is_mal)
            rec = {
                # DFA fields
                "filename": filename,
                "is_malicious": bool(is_mal),
                # PDA fields (trace_id mirrors filename)
                "trace_id": filename,
                "sequence": seq,
                "valid": valid,
                "description": desc,
                "category": cat,
            }
            out.write(json.dumps(rec) + "\n")
            count += 1

    print(f"Wrote {count} unified records to {OUT_PATH}")


if __name__ == '__main__':
    main()
