Starting simulator...
╔══════════════════════════════════════════════════════════════╗
║      CS311 CHOMSKY HIERARCHY SECURITY SIMULATOR             ║
║      Filename Detection (DFA) & TCP Validation (PDA)         ║
╚══════════════════════════════════════════════════════════════╝
╔═══════════════════════════════════╗
MODULE 1 — Filename Detection (DFA)
╚═══════════════════════════════════╝
Chomsky Type-3: Regular Language
Uses Deterministic Finite Automaton (DFA)
• Memory: finite-state
• Function: pattern matching
1. Dataset Loading
[INFO] Reading unified dataset: archive/unified_dataset.jsonl
[INFO] Loading filename dataset: archive/unified_dataset.jsonl
✓[SUCCESS] Loaded 12199 filename entries
[INFO] Loading filename dataset: archive/unified_dataset.jsonl
✓[SUCCESS] Loaded 12199 filename entries
  Top extensions:
    .bin: 11924
    .exe: 98
    .scr: 15
    .bat: 12
    .vbs: 8
    .lnk: 6
    .{hidden}: 5
    .enc: 5
    .dll: 4
    .b64: 4
✓ SUCCESS — Single-source unified dataset loaded
✓ SUCCESS — Total filenames staged: 12199
2. Regex Pattern Definition
[INFO] Defining regex patterns...
[SAMPLE FILENAME RESULTS (RANDOMIZED)]
[File_001]  "5a4f8c9e940827b99d53b9d106c044426d3a27de78baf8dabf88fb675283e410.bin" → BENIGN
[File_002]  "2efa547e5039f0edbbc7e4350160c01d6cf5fcb226ce2aa49b718f92d2a90531.bin" → BENIGN
[File_003]  "878eb5423f9178630120b092231645a5f3086fc67611f3d461424a4898ce5d8a.bin" → BENIGN
[File_004]  "ce33bb3d6fcc837c4666755a522cbcd938e8681635b769e49a99912617588e2f.bin" → BENIGN
[File_005]  "2c37d78609450c02d998c9e27ad6bc594ae4bf5ae9f789011f6557aa0c50d05e.bin" → BENIGN
[CONFUSION MATRIX DEFINITIONS]
  TP (True Positive):  Malicious file correctly detected as malicious
  FP (False Positive): Benign file incorrectly detected as malicious
  TN (True Negative):  Benign file correctly detected as benign
  FN (False Negative): Malicious file incorrectly detected as benign
[DETECTION METRICS]
  ✓ True Positives (TP):   200
  ✗ False Positives (FP):  0
  ✓ True Negatives (TN):   1971
  ✗ False Negatives (FN):  10028
  Precision:               100%
  Recall:                  1.95542%
  F1 Score:                3.83583%
  Detection Rate:          17.7965%
[TOKENIZATION]
  Mode: per-character DFA
  Alphabet (Σ): {  , !, ", #, $, %, &, ', (, ), *, +, ,, -, ., /, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, :, ;, <, =, >, ?, @, A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z, [, \, ], ^, _, `, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, {, |, }, ~ }
[STATE REDUCTION]
  Original DFA states:    107
  After Minimization:     54 (-49.5327% vs original)
[RESOURCE METRICS]
  Estimated DFA memory:   81 KB (83376 bytes)
[PERFORMANCE]
  Patterns:               1
  Files tested:           12199
  Total execution time:   119 ms (wall-clock)
  Average per file:       0.0097549 ms
  Note: Times measured using std::chrono::high_resolution_clock
[PATTERN → DFA MAPPING]
  Pattern '(exe|scr|bat|vbs|update|password|stealer|setup|patch)' (combined_patterns) → DFA 0
[PER-PATTERN METRICS]
╔═══════════════════════════════════╗
MODULE 2 — TCP Protocol Validation (PDA)
╚═══════════════════════════════════╝
Chomsky Type-2: Context-Free Language
Uses Pushdown Automaton (PDA)
• Memory: stack
• Function: sequence validation
1. Loading TCP Trace Dataset
[INFO] Reading: archive/unified_dataset.jsonl
[INFO] Loading TCP trace dataset: archive/unified_dataset.jsonl
✓[SUCCESS] Loaded 12199 TCP traces
  Valid sequences: 1971
  Invalid sequences: 10228
✓ SUCCESS — Loaded 200 traces
Valid:   0
Invalid: 200
2. CFG for TCP 3-Way Handshake
[INFO] Defining Context-Free Grammar for TCP Handshake...
╔════════════════════════════════════════════════════════╗
║  CONTEXT-FREE GRAMMAR (Type-2 Chomsky Hierarchy)       ║
╚════════════════════════════════════════════════════════╝
Production Rules:
  S  → SYN A                (Start with SYN)
  A  → SYN-ACK B            (Must respond with SYN-ACK)
  B  → ACK C                (Complete handshake with ACK)
  C  → DATA C | FIN | ε     (Data transfer or finish)
Terminals: { SYN, SYN-ACK, ACK, DATA, FIN, RST }
Non-terminals: { S, A, B, C }
Start symbol: S
[CFG — Canonical Form]
V = { S, A, B, C }
Σ = { SYN, SYN-ACK, ACK, DATA, FIN, RST }
S = S
P = {
  S → SYN A,
  A → SYN-ACK B,
  B → ACK C,
  C → DATA C | FIN | ε
}
3. PDA Structure
[INFO] Building PDA from CFG...
[PDA STRUCTURE]
  States: 5
    q0: Initial state
    q1: SYN received (expects SYN-ACK)
    q2: SYN-ACK received (expects ACK)
    q3: Handshake complete (ACCEPTING)
    qE: Error state (REJECTING)
[STACK OPERATIONS]
  PUSH SYN:      On receiving SYN in q0
  PUSH SYN-ACK:  On receiving SYN-ACK in q1
  POP ALL:       On receiving ACK in q2 (pops both SYN-ACK and SYN)
  Stack empty:   Required for acceptance (state-based + empty stack)
[NOTE] Both SYN and SYN-ACK are pushed to visualize stack depth
  for pedagogical purposes. In production, only SYN might be pushed,
  with transitions checking SYN-ACK before popping on ACK.
✓[SUCCESS] PDA constructed from CFG
[OK] Wrote PDA construction log: output/pda_construction.txt
4. PDA Validation — Sample Randomized Results
[INFO] Validating 200 TCP traces with PDA...
✓[SUCCESS] Validation complete
  Accuracy: 100%
5. Stack Trace Examples
╔════════════════════════════════════════════════════════╗
║  STACK TRACE VISUALIZATION                             ║
╚════════════════════════════════════════════════════════╝
Input sequence: [SYN, SYN-ACK, ACK]
Step-by-step execution:
  Initial: State=q0, Stack=[BOTTOM]
  Step 1: Input='SYN'
         Stack depth: 1
  Step 2: Input='SYN-ACK'
         Stack depth: 2
  Step 3: Input='ACK'
         Stack depth: 0
  Stack depth: 0
  Result: ✓ VALID
╔════════════════════════════════════════════════════════╗
║  STACK TRACE VISUALIZATION                             ║
╚════════════════════════════════════════════════════════╝
Input sequence: [SYN, ACK]
Step-by-step execution:
  Initial: State=q0, Stack=[BOTTOM]
  Step 1: Input='SYN'
         Stack depth: 1
  Step 2: Input='ACK'
         Operation: [PRECONDITION MISSING] SYN before SYN-ACK
         Stack depth: 1 [ERROR]
  Stack depth: 1
  Result: ✗ INVALID
6. PDA Summary
╔═══════════════════════════════════════════════════════════╗
║          PDA MODULE - VALIDATION RESULTS                  ║
╚═══════════════════════════════════════════════════════════╝
[SAMPLE TCP TRACE RESULTS (RANDOMIZED)]
[Trace_001] script.js.exe: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_002] encoded.exe.b64: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_003] file.txt....[U+202F]....exe: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_004] installer.msi.exe: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_005] config.xml.ws: INVALID (Synthetic invalid handshake for malicious filename)
[VALIDATION METRICS]
  ✓ Valid accepted:       0 / 0
  ✓ Invalid rejected:     200 / 200
  ✗ False positives:      0
  ✗ False negatives:      0
  Validation accuracy:    100%
[STACK METRICS]
  Average stack depth:    0.6
  Maximum stack depth:    2
[CONFUSION MATRIX DEFINITIONS]
  TP (True Positive):  Valid trace correctly accepted
  FP (False Positive): Invalid trace incorrectly accepted
  TN (True Negative):  Invalid trace correctly rejected
  FN (False Negative): Valid trace incorrectly rejected
[CONFUSION MATRIX]
  ✓ True Positives (TP):   0
  ✗ False Positives (FP):  0
  ✓ True Negatives (TN):   200
  ✗ False Negatives (FN):  0
  Precision:               0%
  Recall:                  0%
  F1 Score:                0%
[PERFORMANCE]
  Total traces:           200
  Total execution time:   0.578 ms (wall-clock)
  Average per trace:      0.00289 ms
  Note: Times measured using std::chrono::high_resolution_clock
[OK] Wrote minimized DFA DOT: output/dfa_min_0.dot (pattern: combined_patterns)
[OK] Wrote PDA DOT: output/pda.dot
[OK] Wrote combined DOT: output/graph_from_run.dot
[OK] Wrote output/dfa_min_0.json
[OK] Wrote output/pda.json
[OK] Wrote output/automata.json
+-----------------------------------+
| CHOMSKY HIERARCHY DEMONSTRATION |
+-----------------------------------+
┌─────────────────────┬──────────────────┬──────────────────┐
│ Aspect              │ DFA (Regular)    │ PDA (Context-Free)│
├─────────────────────┼──────────────────┼──────────────────┤
│ Chomsky Type        │ Type 3           │ Type 2           │
│ Memory              │ Finite-state     │ Stack (unbounded)│
│ Can match patterns  │ ✓ Yes            │ ✓ Yes            │
│ Can count/pair      │ ✗ No             │ ✓ Yes            │
│ Grammar             │ Regular (a→αB)   │ CFG (A→α)        │
│ Example task        │ *.exe detection  │ SYN-ACK pairing  │
│ Complexity          │ O(n)             │ O(n)             │
└─────────────────────┴──────────────────┴──────────────────┘
HAHAHHA
All automata saved to /output/.