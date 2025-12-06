PS D:\SCHOOL\Automata\suspicious-filename-detection-automata> make
g++ -std=c++17 -Wall -Wextra -O2 -I./src -I./src/dfa -I./src/pda -I./src/regexparser -I./src/jsonparser -c src/main.cpp -o obj/main.o
g++ obj/main.o obj/regexparser/RegexParser.o obj/pda/PDAModule.o obj/dfa/DFAModule.o obj/jsonparser/JSONParser.o obj/AutomataJSON.o -o simulator
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
[INFO] Reading tricks dataset: archive/tcp_tricks.jsonl
[INFO] Loading TCP trace dataset: archive/tcp_tricks.jsonl
[SUCCESS] Loaded 338 TCP traces
  Valid sequences: 0
  Invalid sequences: 338
[INFO] Loading filename dataset from TCP JSONL: archive/tcp_tricks.jsonl
[SUCCESS] Loaded 338 filename entries (from traces)
  Malicious: 338, Benign: 0
✓ SUCCESS — Trick dataset loaded
  Filenames staged (tricks): 338
[INFO] Reading CSV traces dataset: archive/combined_with_tcp.csv
[INFO] Loading TCP trace dataset (CSV): archive/combined_with_tcp.csv
[SUCCESS] Loaded 13794 TCP traces (CSV)
  Valid sequences: 1971
  Invalid sequences: 11823
[INFO] Loading filename dataset from CSV traces: archive/combined_with_tcp.csv
[SUCCESS] Loaded 13794 filename entries (from CSV)
  Malicious: 11823, Benign: 1971
✓ SUCCESS — CSV dataset loaded
  Filenames staged (tricks + CSV): 13794

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
  Built NFA for 'exe' - 5 states (time: 98 μs)
  Built NFA for 'scr' - 5 states (time: 30 μs)
  Built NFA for 'bat' - 5 states (time: 27 μs)
  Built NFA for 'vbs' - 5 states (time: 31 μs)
  Built NFA for 'update' - 8 states (time: 30 μs)
  Built NFA for 'password' - 10 states (time: 31 μs)
  Built NFA for 'stealer' - 9 states (time: 33 μs)
  Built NFA for 'setup' - 7 states (time: 31 μs)
  Built NFA for 'patch' - 7 states (time: 29 μs)
[SUCCESS] Built 9 NFAs
  Total NFA states: 61
  Total time: 5186 μs
  Complexity: O(|regex|) per pattern (Thompson's Construction)

✓ SUCCESS — Total NFA states: 61

4. NFA → DFA (Subset Construction)
[INFO] Converting NFAs to DFAs (Subset Construction)...
  Converted NFA 1 -> DFA with 7 states (time: 3665 μs)
  Converted NFA 2 -> DFA with 7 states (time: 2416 μs)
  Converted NFA 3 -> DFA with 7 states (time: 2517 μs)
  Converted NFA 4 -> DFA with 7 states (time: 1819 μs)
  Converted NFA 5 -> DFA with 13 states (time: 4262 μs)
  Converted NFA 6 -> DFA with 17 states (time: 4958 μs)
  Converted NFA 7 -> DFA with 15 states (time: 5763 μs)
  Converted NFA 8 -> DFA with 11 states (time: 3637 μs)
  Converted NFA 9 -> DFA with 11 states (time: 3039 μs)
[SUCCESS] Built 9 DFAs
  Total states before minimization: 95
  Total time: 42554 μs
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
  Total time: 56373 μs
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
[INFO] Defining content regex patterns...
[SUCCESS] Defined 5 content patterns
[INFO] Converting content regex to NFAs...
  Built NFA for content '(powershell\.exe\s+-nop|powershell\s+-exec\s+bypass|powershell)' - 65 states
  Built NFA for content '(invoke-expression|iex\s*\(|invoke-webrequest|downloadstring)' - 63 states
  Built NFA for content '(cmd(\.exe)?\s+/c|cmd)' - 24 states
  Built NFA for content 'TVqQAAMAAAAEAAAA' - 18 states
  Built NFA for content '(autoopen\(|document_open\(|workbook_open\()' - 46 states
[SUCCESS] Built 5 content NFAs
[INFO] Converting content NFAs to DFAs...
  Converted content NFA 1 -> DFA with 127 states
  Converted content NFA 2 -> DFA with 123 states
  Converted content NFA 3 -> DFA with 45 states
  Converted content NFA 4 -> DFA with 33 states
  Converted content NFA 5 -> DFA with 89 states
[SUCCESS] Built 5 content DFAs
[INFO] Minimizing content DFAs (Hopcroft)...
  Content DFA 1: refinement steps = 62, final equivalence classes = 64
  Content DFA 2: refinement steps = 60, final equivalence classes = 62
  Content DFA 3: refinement steps = 21, final equivalence classes = 23
  Content DFA 4: refinement steps = 15, final equivalence classes = 17
  Content DFA 5: refinement steps = 43, final equivalence classes = 45
[SUCCESS] Minimized content DFAs
[OK] Wrote Content Regular Grammar: output/grammar_content_0.txt
[OK] Wrote Content Regular Grammar: output/grammar_content_1.txt
[OK] Wrote Content Regular Grammar: output/grammar_content_2.txt
[OK] Wrote Content Regular Grammar: output/grammar_content_3.txt
[OK] Wrote Content Regular Grammar: output/grammar_content_4.txt

╔═══════════════════════════════════╗
MODULE 2 — Content Scan (DFA)
╚═══════════════════════════════════╝
Chomsky Type-3: Regular Language

Uses Deterministic Finite Automaton (DFA)
• Memory: finite-state
• Function: content inspection


╔═══════════════════════════════════════════════════════════╗
║            CONTENT SCAN: DFA MODULE (TYPE-3)              ║
╚═══════════════════════════════════════════════════════════╝

[CONTENT PATTERNS]
  Pattern 1: powershell_family ('(powershell\.exe\s+-nop|powershell\s+-exec\s+bypass|powershell)')
  Pattern 2: invoke_family ('(invoke-expression|iex\s*\(|invoke-webrequest|downloadstring)')
  Pattern 3: cmd_family ('(cmd(\.exe)?\s+/c|cmd)')
  Pattern 4: mz_base64 ('TVqQAAMAAAAEAAAA')
  Pattern 5: macro_autoexec ('(autoopen\(|document_open\(|workbook_open\()')

[CONTENT DFA SUMMARY]
  DFAs built:            5
  DFAs after minimization:5
[INFO] Loading TCP trace dataset: archive/tcp_tricks.jsonl
[SUCCESS] Loaded 338 TCP traces
  Valid sequences: 0
  Invalid sequences: 338

[SAMPLE CONTENT RESULTS (RANDOMIZED)]
[Content_001] trace_id='file.doc:malware.js' → BENIGN
[Content_002] trace_id='image.tiff.bat' → BENIGN
[Content_003] trace_id='system.dev/zero.exe' → BENIGN
[Content_004] trace_id='script.js:exploit' → BENIGN
[Content_005] trace_id='file.txt:evil.exe' → BENIGN
6. Sample Filename Detection (Randomized)
[INFO] Testing 13794 filenames using DFAs...
[SUCCESS] Testing complete
  True Positives: 11823
  Detection accuracy: 85.7112%

[Sample True Positives]:
  9a97affaa82f9837.exe (matched: executable)
  b82bc8644fde8f7f.exe (matched: executable)
  102929c0125c9c32.exe (matched: executable)
  9f06c7aef79d219f.exe (matched: executable)
  33396f653a2a1461.exe (matched: executable)

6b. DFA Classification → Collect suspicious filenames (all staged)
  [INFO] DFA flagged 11823 entries as suspicious
7. DFA Summary
True Positives:   11823
False Negatives:   0
Accuracy:      100%

Execution Time:
  Total:        25 ms
  Per file:     0.00181238 ms


╔═══════════════════════════════════════════════════════════╗
║          DFA MODULE - DETECTION RESULTS                   ║
╚═══════════════════════════════════════════════════════════╝

[SAMPLE FILENAME RESULTS (RANDOMIZED)]
[File_001]  "ec79c085e39bc000.exe" → MALICIOUS (matched: executable) [pattern 1]
[File_002]  "b14ceabdd75ebdbf.exe" → MALICIOUS (matched: executable) [pattern 1]
[File_003]  "1edb5c54fee229f7.exe" → MALICIOUS (matched: executable) [pattern 1]
[File_004]  "b7427190145e74fb.txt" → BENIGN
[File_005]  "7afae88c30981308.txt" → BENIGN

[CONFUSION MATRIX DEFINITIONS]
  TP (True Positive):  Malicious file correctly detected as malicious
  FP (False Positive): Benign file incorrectly detected as malicious
  TN (True Negative):  Benign file correctly detected as benign
  FN (False Negative): Malicious file incorrectly detected as benign

[DETECTION METRICS]
  ✓ True Positives (TP):   11823
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
  Original DFA states:    95
  After Minimization:     52 (-45.2632% vs original)

[RESOURCE METRICS]
  Estimated DFA memory:   78 KB (80288 bytes)

[PERFORMANCE]
  Patterns:               9
  Files tested:           13794
  Total execution time:   25 ms (wall-clock)
  Average per file:       0.00181238 ms
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
  executable: TP=11823, FP=0, FN=0, TN=0, precision=100%, recall=100%, F1=100%


╔═══════════════════════════════════╗
MODULE 3 — TCP Protocol Validation (PDA)
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
[INFO] Loading TCP trace dataset: archive/tcp_tricks.jsonl
[SUCCESS] Loaded 338 TCP traces
  Valid sequences: 0
  Invalid sequences: 338
[PIPELINE] DFA filename suspicious: 11823, Content-malicious (within suspicious): 0
[INFO] No traces meet gating (filename suspicious AND content malicious). Skipping PDA.
[OK] Wrote minimized DFA DOT: output/dfa_min_0.dot (pattern: executable)
[OK] Wrote minimized DFA DOT: output/dfa_min_1.dot (pattern: screensaver)
[OK] Wrote minimized DFA DOT: output/dfa_min_2.dot (pattern: batch_file)
[OK] Wrote minimized DFA DOT: output/dfa_min_3.dot (pattern: vbscript)
[OK] Wrote minimized DFA DOT: output/dfa_min_4.dot (pattern: mimic_legitimate)
[OK] Wrote minimized DFA DOT: output/dfa_min_5.dot (pattern: deceptive_password)
[OK] Wrote minimized DFA DOT: output/dfa_min_6.dot (pattern: deceptive_stealer)
[OK] Wrote minimized DFA DOT: output/dfa_min_7.dot (pattern: deceptive_setup)
[OK] Wrote minimized DFA DOT: output/dfa_min_8.dot (pattern: deceptive_patch)
[OK] Wrote content DFA DOT: output/dfa_content_min_0.dot
[OK] Wrote content DFA DOT: output/dfa_content_min_1.dot
[OK] Wrote content DFA DOT: output/dfa_content_min_2.dot
[OK] Wrote content DFA DOT: output/dfa_content_min_3.dot
[OK] Wrote content DFA DOT: output/dfa_content_min_4.dot
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
[OK] Wrote output/dfa_content_min_0.json
[OK] Wrote output/dfa_content_min_1.json
[OK] Wrote output/dfa_content_min_2.json
[OK] Wrote output/dfa_content_min_3.json
[OK] Wrote output/dfa_content_min_4.json
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