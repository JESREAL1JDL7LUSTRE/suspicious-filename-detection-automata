PS D:\SCHOOL\Automata\suspicious-filename-detection-automata> .\simulator.exe
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
[SUCCESS] Loaded 341 filename entries
  Malicious: 341, Benign: 0
  Unique extensions: 109
[INFO] Loading filename dataset: archive/Malicious_file_trick_detection.jsonl
[SUCCESS] Loaded 341 filename entries
  Malicious: 341, Benign: 0
  Unique extensions: 109
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

[TOKENIZATION DISCIPLINE]
  Method: Per-character tokenization
  Alphabet: Printable ASCII (32-126)
  Processing: Sequential character-by-character DFA transitions
  Pattern 1: executable ('exe')
  Pattern 2: screensaver ('scr')
  Pattern 3: batch_file ('bat')
  Pattern 4: vbscript ('vbs')
  Pattern 5: mimic_legitimate ('update')
  Pattern 6: deceptive_password ('password')
  Pattern 7: deceptive_stealer ('stealer')
  Pattern 8: deceptive_setup ('setup')
  Pattern 9: deceptive_patch ('patch')
[SUCCESS] Defined 9 patterns

3. Regex → NFA (Thompson’s Construction)
[INFO] Converting regex to NFAs (Thompson's Construction)...
  Built NFA for 'exe' - 5 states (time: 36 μs)
  Built NFA for 'scr' - 5 states (time: 27 μs)
  Built NFA for 'bat' - 5 states (time: 18 μs)
  Built NFA for 'vbs' - 5 states (time: 20 μs)
  Built NFA for 'update' - 8 states (time: 40 μs)
  Built NFA for 'password' - 10 states (time: 28 μs)
  Built NFA for 'stealer' - 9 states (time: 35 μs)
  Built NFA for 'setup' - 7 states (time: 27 μs)
  Built NFA for 'patch' - 7 states (time: 52 μs)
[SUCCESS] Built 9 NFAs
  Total NFA states: 61
  Total time: 6108 μs
  Complexity: O(|regex|) per pattern (Thompson's Construction)

✓ SUCCESS — Total NFA states: 61

4. NFA → DFA (Subset Construction)
[INFO] Converting NFAs to DFAs (Subset Construction)...
  Converted NFA 1 -> DFA with 7 states (time: 1267 μs)
  Converted NFA 2 -> DFA with 7 states (time: 1193 μs)
  Converted NFA 3 -> DFA with 7 states (time: 1698 μs)
  Converted NFA 4 -> DFA with 7 states (time: 1526 μs)
  Converted NFA 5 -> DFA with 13 states (time: 2199 μs)
  Converted NFA 6 -> DFA with 17 states (time: 3554 μs)
  Converted NFA 7 -> DFA with 15 states (time: 3280 μs)
  Converted NFA 8 -> DFA with 11 states (time: 2664 μs)
  Converted NFA 9 -> DFA with 11 states (time: 2841 μs)
[SUCCESS] Built 9 DFAs
  Total states before minimization: 95
  Total time: 28986 μs
  Complexity: O(2^n) worst-case, where n = NFA states
  Empirical: 61 NFA states → 95 DFA states

✓ SUCCESS — Total DFA states: 95

5. DFA Minimization (Hopcroft)
[INFO] Minimizing DFAs (Hopcroft's Algorithm)...
  DFA 1: refinement steps = 2, final equivalence classes = 4
  DFA 2: refinement steps = 2, final equivalence classes = 4
  DFA 3: refinement steps = 2, final equivalence classes = 4
  DFA 4: refinement steps = 2, final equivalence classes = 4
  DFA 5: refinement steps = 5, final equivalence classes = 7
  DFA 6: refinement steps = 7, final equivalence classes = 9
  DFA 7: refinement steps = 6, final equivalence classes = 8
  DFA 8: refinement steps = 4, final equivalence classes = 6
  DFA 9: refinement steps = 4, final equivalence classes = 6
[SUCCESS] Minimized DFAs (Hopcroft)
  States after minimization: 52
  Reduction: 45.2632%
  Total time: 41886 μs
  Complexity: O(k n log n) where k = |alphabet|, n = |DFA states|
  Empirical: 95 states → 52 states

[OK] Wrote Regular Grammar: output/grammar_0.txt
[OK] Wrote Regular Grammar: output/grammar_1.txt
[OK] Wrote Regular Grammar: output/grammar_2.txt
[OK] Wrote Regular Grammar: output/grammar_3.txt
[OK] Wrote Regular Grammar: output/grammar_4.txt
[OK] Wrote Regular Grammar: output/grammar_5.txt
[OK] Wrote Regular Grammar: output/grammar_6.txt
[OK] Wrote Regular Grammar: output/grammar_7.txt
[OK] Wrote Regular Grammar: output/grammar_8.txt
[OK] Wrote Regular Grammar: output/grammar_0.txt
[OK] Wrote Regular Grammar: output/grammar_1.txt
[OK] Wrote Regular Grammar: output/grammar_2.txt
[OK] Wrote Regular Grammar: output/grammar_3.txt
[OK] Wrote Regular Grammar: output/grammar_4.txt
[OK] Wrote Regular Grammar: output/grammar_5.txt
[OK] Wrote Regular Grammar: output/grammar_6.txt
[OK] Wrote Regular Grammar: output/grammar_7.txt
[OK] Wrote Regular Grammar: output/grammar_8.txt
6. Sample Filename Detection (Randomized)
[INFO] Testing 341 filenames using DFAs...
[SUCCESS] Testing complete
  True Positives: 304
  Detection accuracy: 89.1496%

[Sample True Positives]:
  report.pdf.exe (matched: executable)
  invoice.doc.scr (matched: screensaver)
  budget.xlsx.vbs (matched: vbscript)
  resume.pdf.bat (matched: batch_file)
  contract.doc.pif (matched: double_extension)

[Sample False Negatives]:
  system.dll
  win32.sys
  payload.bin
  archive.zip:encrypted
  video.mp4:payload

6b. DFA Classification → Collect suspicious filenames
  [INFO] DFA flagged 304 entries as suspicious
7. DFA Summary
True Positives:   304
False Negatives:   37
Accuracy:      89.1496%

Execution Time:
  Total:        1 ms
  Per file:     0.00293255 ms


╔═══════════════════════════════════════════════════════════╗
║          DFA MODULE - DETECTION RESULTS                   ║
╚═══════════════════════════════════════════════════════════╝

[SAMPLE FILENAME RESULTS (RANDOMIZED)]
[File_001]  "script.js.enc" → MALICIOUS (matched: screensaver)
[File_002]  "file.pdf:ml.exe" → MALICIOUS (matched: executable)
[File_003]  "readme.txt:evil" → BENIGN
[File_004]  "script.sh.exe" → MALICIOUS (matched: executable)
[File_005]  "photo.png:exploit" → BENIGN

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
  Total execution time:   1 ms (wall-clock)
  Average per file:       0.00293255 ms
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
[SUCCESS] Loaded 338 TCP traces
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

[SUCCESS] PDA constructed from CFG

[OK] Wrote PDA construction log: output/pda_construction.txt
4. PDA Validation — Sample Randomized Results
[INFO] Validating 265 TCP traces with PDA...
[SUCCESS] Validation complete
  Accuracy: 100%

5. Stack Trace Examples

╔════════════════════════════════════════════════════════╗
║  STACK TRACE VISUALIZATION                             ║
╚════════════════════════════════════════════════════════╝

Input sequence: [SYN, SYN-ACK, ACK]

Step-by-step execution:
  Initial: State=q0, Stack=[BOTTOM]
  Step 1: Input='SYN'
         State: q0 → q1
         Operation: PUSH(SYN) → q1
         Stack depth: 1
  Step 2: Input='SYN-ACK'
         State: q1 → q2
         Operation: PUSH(SYN-ACK) → q2
         Stack depth: 2
  Step 3: Input='ACK'
         State: q2 → q3
         Operation: POP(SYN-ACK), POP(SYN) → q3
         Stack depth: 0

  Final state: q3
  Stack depth: 0
  Result: ✓ VALID


╔════════════════════════════════════════════════════════╗
║  STACK TRACE VISUALIZATION                             ║
╚════════════════════════════════════════════════════════╝

Input sequence: [SYN, ACK]

Step-by-step execution:
  Initial: State=q0, Stack=[BOTTOM]
  Step 1: Input='SYN'
         State: q0 → q1
         Operation: PUSH(SYN) → q1
         Stack depth: 1
  Step 2: Input='ACK'
         State: q1 → q4
         Operation: [PRECONDITION MISSING] SYN before SYN-ACK
         Stack depth: 1 [ERROR]

  Final state: q4
  Stack depth: 1
  Result: ✗ INVALID

6. PDA Summary

╔═══════════════════════════════════════════════════════════╗
║          PDA MODULE - VALIDATION RESULTS                  ║
╚═══════════════════════════════════════════════════════════╝

[SAMPLE TCP TRACE RESULTS (RANDOMIZED)]
[Trace_001] document.docx.{hidden}: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_002] install.msi.scr: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_003] setup.msi.exe: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_004] invoice.pdf.exe: INVALID (Synthetic invalid handshake for malicious filename)
[Trace_005] file.exe:stego.dll: INVALID (Synthetic invalid handshake for malicious filename)

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
  Total execution time:   1.643 ms (wall-clock)
  Average per trace:      0.0062 ms
  Note: Times measured using std::chrono::high_resolution_clock



╔═══════════════════════════════════════════════════════════╗
║        RE-RUN — CSV (combined_random + malware)           ║
╚═══════════════════════════════════════════════════════════╝
[INFO] Integrating combined CSV: archive/combined_random.csv
[SUCCESS] Added 11923 entries from combined_random.csv
[INFO] Integrating malware CSV: archive/malware.csv
[SUCCESS] Added 10841 entries from malware.csv
[INFO] Post-ingest label summary
  Malicious: 20793, Benign: 1971
  Label balance (majority share): 91.3416%

[INFO] Classifying CSV dataset with existing DFA...
  [INFO] DFA flagged 20793 CSV entries as suspicious

╔═══════════════════════════════════════════════════════════╗
║          DFA MODULE - DETECTION RESULTS                   ║
╚═══════════════════════════════════════════════════════════╝

[SAMPLE FILENAME RESULTS (RANDOMIZED)]
[File_001]  "e42c9b044f2c6cda.exe" → MALICIOUS (matched: executable)
[File_002]  "8bd49ff13b39e9b8.txt" → BENIGN
[File_003]  "e9dcdd05f3bee021.txt" → BENIGN
[File_004]  "aeaaf67e38fb1d44.txt" → BENIGN
[File_005]  "0c4db97ea4705e3b.exe" → MALICIOUS (matched: executable)

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
  Total execution time:   165 ms (wall-clock)
  Average per file:       0.00724829 ms
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
[SUCCESS] Loaded 13794 TCP traces (CSV)
  Valid sequences: 1971
  Invalid sequences: 11823
✓ SUCCESS — Loaded 11823 traces
Valid:   0
Invalid: 11823
[INFO] Validating 11823 TCP traces with PDA...
[SUCCESS] Validation complete
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
PS D:\SCHOOL\Automata\suspicious-filename-detection-automata> 