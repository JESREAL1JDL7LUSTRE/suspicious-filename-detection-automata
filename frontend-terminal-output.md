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
[INFO] Reading tricks dataset: archive/Malicious_file_trick_detection.jsonl
[INFO] Loading filename dataset: archive/Malicious_file_trick_detection.jsonl
✓[SUCCESS] Loaded 341 filename entries
[INFO] Loading filename dataset: archive/Malicious_file_trick_detection.jsonl
✓[SUCCESS] Loaded 341 filename entries
  Top extensions:
    .exe: 123
    .scr: 22
    .bat: 20
    .{hidden}: 11
    .vbs: 8
    .lnk: 6
    .𝙴𝚇𝙴: 5
    .pif: 5
    .enc: 5
    .js: 4
✓ SUCCESS — Trick dataset loaded
✓ SUCCESS — Total filenames staged: 341
2. Regex Pattern Definition
[INFO] Defining regex patterns...
[SAMPLE FILENAME RESULTS (RANDOMIZED)]
[File_001]  "file.txt.lnk" → MALICIOUS (matched: double_extension)
[File_002]  "video.avi:trojan" → BENIGN
[File_003]  "image.png:stego.exe" → MALICIOUS (matched: executable)
[File_004]  "archive.zip:encrypted" → BENIGN
[File_005]  "setup.exe:payload" → MALICIOUS (matched: executable)
[CONFUSION MATRIX DEFINITIONS]
  TP (True Positive):  Malicious file correctly detected as malicious
  FP (False Positive): Benign file incorrectly detected as malicious
  TN (True Negative):  Benign file correctly detected as benign
  FN (False Negative): Malicious file incorrectly detected as benign
[DETECTION METRICS]
  ✓ True Positives (TP):   304
  ✗ False Positives (FP):  0
  ✓ True Negatives (TN):   0
  ✗ False Negatives (FN):  37
  Precision:               100%
  Recall:                  89.1496%
  F1 Score:                94.2636%
  Detection Rate:          89.1496%
[TOKENIZATION]
  Mode: per-character DFA
  Alphabet (Σ): {  , !, ", #, $, %, &, ', (, ), *, +, ,, -, ., /, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, :, ;, <, =, >, ?, @, A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z, [, \, ], ^, _, `, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, {, |, }, ~ }
[STATE REDUCTION]
  Original DFA states:    95
  After Minimization:     52 (-45.2632% vs original)
[RESOURCE METRICS]
  Estimated DFA memory:   78 KB (80288 bytes)
[PERFORMANCE]
  Patterns:               9
  Files tested:           341
  Total execution time:   3 ms (wall-clock)
  Average per file:       0.00879765 ms
  Note: Times measured using std::chrono::high_resolution_clock
[PATTERN → DFA MAPPING]
  Pattern 'exe' (executable) → DFA 0
  Pattern 'scr' (screensaver) → DFA 1
  Pattern 'bat' (batch_file) → DFA 2
  Pattern 'vbs' (vbscript) → DFA 3
  Pattern 'update' (mimic_legitimate) → DFA 4
  Pattern 'password' (deceptive_password) → DFA 5
  Pattern 'stealer' (deceptive_stealer) → DFA 6
  Pattern 'setup' (deceptive_setup) → DFA 7
  Pattern 'patch' (deceptive_patch) → DFA 8
[PER-PATTERN METRICS]
  executable: TP=157, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
  screensaver: TP=28, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
  batch_file: TP=18, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
  vbscript: TP=8, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
  mimic_legitimate: TP=5, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
  deceptive_setup: TP=3, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
╔═══════════════════════════════════╗
MODULE 2 — TCP Protocol Validation (PDA)
╚═══════════════════════════════════╝
Chomsky Type-2: Context-Free Language
Uses Pushdown Automaton (PDA)
• Memory: stack
• Function: sequence validation
1. Loading TCP Trace Dataset
[INFO] Reading: archive/tcp_tricks.jsonl
[INFO] Loading TCP trace dataset: archive/tcp_tricks.jsonl
✓[SUCCESS] Loaded 338 TCP traces
  Valid sequences: 0
  Invalid sequences: 338
✓ SUCCESS — Loaded 265 traces
Valid:   0
Invalid: 265
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
[INFO] Validating 265 TCP traces with PDA...
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
[Trace_001] image.jpg.com: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_002] file.pdf.....exe: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_003] file.txt[U+2063].exe: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_004] payload.qr.enc: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_005] music.wav.bat: INVALID (Synthetic invalid handshake for malicious filename)
[VALIDATION METRICS]
  ✓ Valid accepted:       0 / 0
  ✓ Invalid rejected:     265 / 265
  ✗ False positives:      0
  ✗ False negatives:      0
  Validation accuracy:    100%
[STACK METRICS]
  Average stack depth:    0.633962
  Maximum stack depth:    2
[CONFUSION MATRIX DEFINITIONS]
  TP (True Positive):  Valid trace correctly accepted
  FP (False Positive): Invalid trace incorrectly accepted
  TN (True Negative):  Invalid trace correctly rejected
  FN (False Negative): Valid trace incorrectly rejected
[CONFUSION MATRIX]
  ✓ True Positives (TP):   0
  ✗ False Positives (FP):  0
  ✓ True Negatives (TN):   265
  ✗ False Negatives (FN):  0
  Precision:               0%
  Recall:                  0%
  F1 Score:                0%
[PERFORMANCE]
  Total traces:           265
  Total execution time:   0.514 ms (wall-clock)
  Average per trace:      0.00193962 ms
  Note: Times measured using std::chrono::high_resolution_clock
╔═══════════════════════════════════════════════════════════╗
║        RE-RUN — CSV (combined_random + malware)           ║
╚═══════════════════════════════════════════════════════════╝
[INFO] Integrating combined CSV: archive/combined_random.csv
✓[SUCCESS] Added 11923 entries from combined_random.csv
[INFO] Integrating malware CSV: archive/malware.csv
✓[SUCCESS] Added 10841 entries from malware.csv
[INFO] Post-ingest label summary
  Label balance (majority share): 91.3416%
[INFO] Classifying CSV dataset with existing DFA...
  [INFO] DFA flagged 20793 CSV entries as suspicious
╔═══════════════════════════════════════════════════════════╗
║          DFA MODULE - DETECTION RESULTS                   ║
╚═══════════════════════════════════════════════════════════╝
[SAMPLE FILENAME RESULTS (RANDOMIZED)]
[File_001]  "8214d930ada54705.txt" → BENIGN
[File_002]  "ae804dbaf96a1204.exe" → MALICIOUS (matched: executable)
[File_003]  "27b589107d77d353.exe" → MALICIOUS (matched: executable)
[File_004]  "a2c48edf42506d7f.exe" → MALICIOUS (matched: executable)
[File_005]  "ec4f449e19e854e4.exe" → MALICIOUS (matched: executable)
[CONFUSION MATRIX DEFINITIONS]
  TP (True Positive):  Malicious file correctly detected as malicious
  FP (False Positive): Benign file incorrectly detected as malicious
  TN (True Negative):  Benign file correctly detected as benign
  FN (False Negative): Malicious file incorrectly detected as benign
[DETECTION METRICS]
  ✓ True Positives (TP):   20793
  ✗ False Positives (FP):  0
  ✓ True Negatives (TN):   1971
  ✗ False Negatives (FN):  0
  Precision:               100%
  Recall:                  100%
  F1 Score:                100%
  Detection Rate:          100%
[TOKENIZATION]
  Mode: per-character DFA
  Alphabet (Σ): {  , !, ", #, $, %, &, ', (, ), *, +, ,, -, ., /, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, :, ;, <, =, >, ?, @, A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z, [, \, ], ^, _, `, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, {, |, }, ~ }
[STATE REDUCTION]
  Original DFA states:    0
  After Minimization:     0 (-0% vs original)
[RESOURCE METRICS]
  Estimated DFA memory:   78 KB (80288 bytes)
[PERFORMANCE]
  Patterns:               0
  Files tested:           22764
  Total execution time:   142 ms (wall-clock)
  Average per file:       0.00623792 ms
  Note: Times measured using std::chrono::high_resolution_clock
[PATTERN → DFA MAPPING]
  Pattern 'exe' (executable) → DFA 0
  Pattern 'scr' (screensaver) → DFA 1
  Pattern 'bat' (batch_file) → DFA 2
  Pattern 'vbs' (vbscript) → DFA 3
  Pattern 'update' (mimic_legitimate) → DFA 4
  Pattern 'password' (deceptive_password) → DFA 5
  Pattern 'stealer' (deceptive_stealer) → DFA 6
  Pattern 'setup' (deceptive_setup) → DFA 7
  Pattern 'patch' (deceptive_patch) → DFA 8
[PER-PATTERN METRICS]
  executable: TP=157, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
  screensaver: TP=28, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
  batch_file: TP=18, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
  vbscript: TP=8, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
  mimic_legitimate: TP=5, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
  deceptive_setup: TP=3, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%
[INFO] Loading CSV TCP traces: archive/combined_with_tcp.csv
[INFO] Loading TCP trace dataset (CSV): archive/combined_with_tcp.csv
✓[SUCCESS] Loaded 13794 TCP traces (CSV)
  Valid sequences: 1971
  Invalid sequences: 11823
✓ SUCCESS — Loaded 11823 traces
Valid:   0
Invalid: 11823
[INFO] Validating 11823 TCP traces with PDA...
✓[SUCCESS] Validation complete
  Accuracy: 100%
[OK] Wrote minimized DFA DOT: output/dfa_min_0.dot (pattern: executable)
[OK] Wrote minimized DFA DOT: output/dfa_min_1.dot (pattern: screensaver)
[OK] Wrote minimized DFA DOT: output/dfa_min_2.dot (pattern: batch_file)
[OK] Wrote minimized DFA DOT: output/dfa_min_3.dot (pattern: vbscript)
[OK] Wrote minimized DFA DOT: output/dfa_min_4.dot (pattern: mimic_legitimate)
[OK] Wrote minimized DFA DOT: output/dfa_min_5.dot (pattern: deceptive_password)
[OK] Wrote minimized DFA DOT: output/dfa_min_6.dot (pattern: deceptive_stealer)
[OK] Wrote minimized DFA DOT: output/dfa_min_7.dot (pattern: deceptive_setup)
[OK] Wrote minimized DFA DOT: output/dfa_min_8.dot (pattern: deceptive_patch)
[OK] Wrote PDA DOT: output/pda.dot
[OK] Wrote combined DOT: output/graph_from_run.dot
[OK] Wrote output/dfa_min_0.json
[OK] Wrote output/dfa_min_1.json
[OK] Wrote output/dfa_min_2.json
[OK] Wrote output/dfa_min_3.json
[OK] Wrote output/dfa_min_4.json
[OK] Wrote output/dfa_min_5.json
[OK] Wrote output/dfa_min_6.json
[OK] Wrote output/dfa_min_7.json
[OK] Wrote output/dfa_min_8.json
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