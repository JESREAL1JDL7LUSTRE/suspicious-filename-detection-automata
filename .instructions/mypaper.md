PROCESS OF THE SYSTEM

1. Dataset Input: Suspicious and Benign Filenames
The system begins by accepting a dataset containing different types of filenames:
Benign (harmless) filenames
Suspicious or potentially malicious filenames
Filename samples containing double extensions, hidden extensions, or deceptive keywords
Each filename in the dataset serves as input for the first part of the system: pattern detection using regular languages.


Filenames (DFA → Regular Language Detection)
Filenames are checked individually because:
A DFA processes one string at a time
Each filename is its own input
Each filename must return Malicious or Not
DFA cannot check “groups” of filenames at once
DFA resets for every filename
Therefore:
Filename detection must always be individual.
One filename = one DFA pass = one result


2. Regular Language Definition using Regular Expressions
To detect malicious filenames, the system creates a set of regular expressions (regex rules) that describe harmful patterns such as:
Dangerous extensions (e.g., .exe, .bat, .vbs)
Double extensions (e.g., file.txt.exe)
Deceptive keywords (e.g., password_stealer.exe)
Fake installers (e.g., setup, update, patch)
These regular expressions form the basis of the regular languages used in pattern detection.

3. Conversion of Regex to Regular Grammars and DFA
Each regular expression is transformed into:
A regular grammar (Type-3 grammar) that follows Chomsky hierarchy rules.
A Deterministic Finite Automaton (DFA) that recognizes filenames matching that pattern.
The DFA is generated through formal steps:
Regex → NFA (Thompson construction)
NFA → DFA (subset construction)
DFA → minimized DFA
This DFA becomes a pattern detector that checks each filename in the dataset.

4. DFA-Based Suspicious Filename Detection
The minimized DFA scans each filename:
If the filename matches any malicious pattern → Flagged as Suspicious
If no pattern matches → Labeled as Benign
The DFA is fast and efficient, making it suitable for large filename datasets.

5. Context-Free Grammar for Protocol Validation
The second part of the system handles TCP 3-way handshake validation.

A Context-Free Grammar (CFG) is defined to describe the valid sequence:
S → SYN SYNACK ACK

This grammar represents a Type-2 language, which requires stack-based memory to validate the correct order.

6. PDA Design Using CFG
From the CFG, the system constructs a Pushdown Automaton (PDA).

The PDA uses its stack to store handshake state:
On receiving a SYN, the PDA pushes a marker onto the stack.
On SYN-ACK, it verifies that SYN exists in stack order.
On ACK, it pops the stored marker.
If the stack is empty at the end of the sequence:
The handshake is valid
If the order is wrong or incomplete:
The handshake is invalid

7. Integrated System Operation
Once both components are ready, the system processes inputs in the following way:
A. For Filenames
Input filename from dataset
Send to DFA
DFA checks pattern
Outputs: Malicious / Benign
B. For Network Packet Traces
Input packet sequence
Send to PDA
PDA validates handshake
Outputs: Valid / Invalid handshake

8. Final Output 
The system produces two parallel results:
1. Filename Detection Result
Each filename → Malicious or Clean
Based on DFA pattern matching
2. Protocol Validation Result
Each handshake → Valid or Invalid
Based on PDA stack behavior

DIAGRAM
Dataset (Suspicious Filenames)
            ↓
Regular Expressions (malicious patterns)
            ↓
Convert to Regular Grammar → Build DFA
            ↓
DFA scans filenames → Malicious / Benign

Network Packet Stream
            ↓
Context-Free Grammar of Handshake
            ↓
Build PDA with Stack
            ↓
PDA validates handshake → Valid / Invalid



