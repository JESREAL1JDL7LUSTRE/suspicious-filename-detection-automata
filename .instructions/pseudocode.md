# CS311 Security Simulator - Complete Pseudocode
## Suspicious Filename Detection & TCP Protocol Validation

---

## 📋 TABLE OF CONTENTS

1. [Main Program Flow](#main-program-flow)
2. [Data Structures](#data-structures)
3. [JSON Parser Module](#json-parser-module)
4. [Regex Parser Module (Thompson's Construction)](#regex-parser-module)
5. [NFA to DFA Converter (Subset Construction)](#nfa-to-dfa-converter)
6. [DFA Minimizer (Hopcroft's Algorithm)](#dfa-minimizer)
7. [IGA Module (Improved Grouping Algorithm)](#iga-module)
8. [DFA Module (Filename Detection)](#dfa-module)
9. [PDA Module (TCP Validation)](#pda-module)

---

## 🎯 MAIN PROGRAM FLOW

```pseudocode
ALGORITHM Main_Simulator

INPUT: 
    - filename_dataset_path: "archive/Malicious_file_trick_detection.jsonl"
    - tcp_dataset_path: "archive/tcp_handshake_traces_expanded.jsonl"

OUTPUT:
    - Console output with results
    - Performance metrics
    - Chomsky Hierarchy demonstration

BEGIN
    PRINT "CS311 Chomsky Hierarchy Security Simulator"
    PRINT "=========================================="
    
    // ========== MODULE 1: DFA (Regular Languages) ==========
    PRINT "MODULE 1: Filename Pattern Detection (DFA)"
    
    CREATE dfa_module
    
    TRY
        // Step 1: Load Dataset
        dfa_module.load_dataset(filename_dataset_path)
        // Loads 341 malicious filename entries
        
        // Step 2: Define Regex Patterns
        dfa_module.define_patterns()
        // Creates 5-10 regex patterns for different techniques
        
        // Step 3: Build NFAs
        dfa_module.build_nfas()
        // Convert each regex to NFA using Thompson's Construction
        
        // Step 4: Convert to DFAs
        dfa_module.convert_to_dfas()
        // Use Subset Construction for each NFA
        
        // Step 5: Minimize DFAs
        dfa_module.minimize_dfas()
        // Apply Hopcroft's Algorithm
        
        // Step 6: Apply IGA
        dfa_module.apply_iga()
        // Group similar DFAs, reduce states by ~27%
        
        // Step 7: Test All Filenames
        dfa_module.test_patterns()
        // Match 341 filenames against grouped DFAs
        
        // Step 8: Generate Report
        dfa_module.generate_report()
        // Print metrics and results
        
    CATCH exception
        PRINT "ERROR in DFA Module:", exception.message
    END TRY
    
    // ========== MODULE 2: PDA (Context-Free Languages) ==========
    PRINT "MODULE 2: TCP Protocol Validation (PDA)"
    
    CREATE pda_module
    
    TRY
        // Step 1: Load Dataset
        pda_module.load_dataset(tcp_dataset_path)
        // Loads 75 TCP handshake traces
        
        // Step 2: Build PDA
        pda_module.build_pda()
        // Design PDA with stack for TCP validation
        
        // Step 3: Validate All Traces
        pda_module.test_all_traces()
        // Process each trace through PDA
        
        // Step 4: Show Sample Operations
        sample_traces = [
            ["SYN", "SYN-ACK", "ACK"],
            ["SYN", "ACK"],
            ["ACK", "SYN", "SYN-ACK"]
        ]
        
        FOR EACH trace IN sample_traces DO
            pda_module.show_stack_operations(trace)
        END FOR
        
        // Step 5: Generate Report
        pda_module.generate_report()
        // Print validation results and metrics
        
    CATCH exception
        PRINT "ERROR in PDA Module:", exception.message
    END TRY
    
    // ========== COMPARATIVE ANALYSIS ==========
    PRINT "CHOMSKY HIERARCHY DEMONSTRATION"
    PRINT "=========================================="
    
    PRINT "DFA (Regular Language - Type 3):"
    PRINT "  - No memory (stateless)"
    PRINT "  - Can match patterns: *.exe, *.pdf.exe"
    PRINT "  - Cannot validate nested/paired structures"
    PRINT "  - Example: Filename pattern matching"
    
    PRINT "PDA (Context-Free Language - Type 2):"
    PRINT "  - Has stack memory"
    PRINT "  - Can match patterns AND validate pairs"
    PRINT "  - Can count and match nested structures"
    PRINT "  - Example: TCP SYN-ACK pairing"
    
    PRINT "Key Insight:"
    PRINT "  DFA cannot validate TCP handshakes because it"
    PRINT "  requires matching SYN with SYN-ACK (pairing)."
    PRINT "  PDA uses stack to track which packets have been"
    PRINT "  seen and ensures proper pairing."
    
    PRINT "Execution complete!"
    
END ALGORITHM
```

---

## 📊 DATA STRUCTURES

```pseudocode
// ==================== AUTOMATA STRUCTURES ====================

STRUCTURE State
    FIELDS:
        id: INTEGER                    // Unique state identifier
        is_accepting: BOOLEAN          // True if accepting/final state
        label: STRING                  // Optional label (e.g., "q0", "q_start")
    END FIELDS
END STRUCTURE

STRUCTURE Transition
    FIELDS:
        from_state: INTEGER            // Source state ID
        to_state: INTEGER              // Destination state ID
        symbol: CHARACTER              // Input symbol
        is_epsilon: BOOLEAN            // True for ε-transitions (NFA only)
    END FIELDS
END STRUCTURE

STRUCTURE NFA
    FIELDS:
        states: LIST<State>            // All states in NFA
        transitions: LIST<Transition>  // All transitions
        start_state: INTEGER           // Starting state ID
        accepting_states: SET<INTEGER> // Set of accepting state IDs
        alphabet: SET<CHARACTER>       // Input alphabet (excluding ε)
    END FIELDS
    
    METHODS:
        add_state(state: State)
        add_transition(from, to, symbol, is_epsilon)
        get_state_count() -> INTEGER
    END METHODS
END STRUCTURE

STRUCTURE DFA
    FIELDS:
        states: LIST<State>
        transition_table: MAP<(INTEGER, CHARACTER), INTEGER>
            // Maps (state, symbol) -> next_state
        start_state: INTEGER
        accepting_states: SET<INTEGER>
        alphabet: SET<CHARACTER>
    END FIELDS
    
    METHODS:
        add_state(state: State)
        add_transition(from, symbol, to)
        get_next_state(current, symbol) -> INTEGER
        get_state_count() -> INTEGER
        accepts(input: STRING) -> BOOLEAN
    END METHODS
END STRUCTURE

STRUCTURE PDA
    FIELDS:
        states: LIST<State>
        pda_stack: STACK<STRING>       // Stack for memory
        current_state: INTEGER
        start_state: INTEGER
        accepting_states: SET<INTEGER>
    END FIELDS
    
    METHODS:
        reset()                        // Reset to initial state
        push(symbol: STRING)           // Push to stack
        pop() -> STRING                // Pop from stack
        peek() -> STRING               // Look at top of stack
        is_accepting() -> BOOLEAN      // Check if in accepting state
        get_stack_depth() -> INTEGER
    END METHODS
END STRUCTURE

// ==================== DATASET STRUCTURES ====================

STRUCTURE FilenameEntry
    FIELDS:
        filename: STRING               // e.g., "report.pdf.exe"
        technique: STRING              // e.g., "Double extension"
        category: STRING               // e.g., "Social Engineering"
        detected_by: STRING            // e.g., "AV heuristic"
        is_malicious: BOOLEAN          // True for malicious files
    END FIELDS
END STRUCTURE

STRUCTURE TCPTrace
    FIELDS:
        trace_id: STRING               // e.g., "T001"
        sequence: LIST<STRING>         // e.g., ["SYN", "SYN-ACK", "ACK"]
        valid: BOOLEAN                 // True if valid handshake
        description: STRING            // e.g., "Valid 3-way handshake"
        category: STRING               // e.g., "Normal"
    END FIELDS
END STRUCTURE

// ==================== METRICS STRUCTURES ====================

STRUCTURE DFAMetrics
    FIELDS:
        total_patterns: INTEGER
        total_nfa_states: INTEGER
        total_dfa_states_before_min: INTEGER
        total_dfa_states_after_min: INTEGER
        total_dfa_states_after_iga: INTEGER
        state_reduction_min_percent: REAL
        state_reduction_iga_percent: REAL
        
        filenames_tested: INTEGER
        true_positives: INTEGER
        false_positives: INTEGER
        false_negatives: INTEGER
        detection_accuracy: REAL
        
        avg_matching_time_ms: REAL
        total_execution_time_ms: REAL
    END FIELDS
END STRUCTURE

STRUCTURE PDAMetrics
    FIELDS:
        total_traces: INTEGER
        valid_traces: INTEGER
        invalid_traces: INTEGER
        correctly_accepted: INTEGER
        correctly_rejected: INTEGER
        false_positives: INTEGER
        false_negatives: INTEGER
        validation_accuracy: REAL
        
        avg_stack_depth: REAL
        max_stack_depth: INTEGER
        avg_validation_time_ms: REAL
    END FIELDS
END STRUCTURE
```

---

## 📄 JSON PARSER MODULE

```pseudocode
// ==================== JSON PARSER ====================

ALGORITHM Load_Filename_Dataset
INPUT: filepath: STRING (path to JSONL file)
OUTPUT: LIST<FilenameEntry>

BEGIN
    dataset = EMPTY LIST
    
    OPEN file at filepath
    IF file cannot be opened THEN
        PRINT "ERROR: Cannot open", filepath
        RETURN empty list
    END IF
    
    line_number = 0
    
    WHILE NOT end_of_file DO
        line = READ next line from file
        line_number = line_number + 1
        
        IF line is empty THEN
            CONTINUE
        END IF
        
        TRY
            // Parse JSON line
            json_object = PARSE_JSON(line)
            
            // Extract fields
            entry = NEW FilenameEntry
            entry.filename = json_object["filename"]
            entry.technique = json_object["technique"] OR "Unknown"
            entry.category = json_object["category"] OR "Unknown"
            entry.detected_by = json_object["detected_by"] OR "Unknown"
            entry.is_malicious = TRUE  // All in dataset are malicious
            
            ADD entry to dataset
            
        CATCH parse_error
            PRINT "WARNING: JSON parse error at line", line_number
        END TRY
    END WHILE
    
    CLOSE file
    
    PRINT "SUCCESS: Loaded", LENGTH(dataset), "entries"
    RETURN dataset
    
END ALGORITHM


ALGORITHM Load_TCP_Dataset
INPUT: filepath: STRING
OUTPUT: LIST<TCPTrace>

BEGIN
    dataset = EMPTY LIST
    
    OPEN file at filepath
    IF file cannot be opened THEN
        PRINT "ERROR: Cannot open", filepath
        RETURN empty list
    END IF
    
    line_number = 0
    
    WHILE NOT end_of_file DO
        line = READ next line from file
        line_number = line_number + 1
        
        IF line is empty THEN
            CONTINUE
        END IF
        
        TRY
            json_object = PARSE_JSON(line)
            
            trace = NEW TCPTrace
            trace.trace_id = json_object["trace_id"]
            
            // Parse sequence array
            trace.sequence = EMPTY LIST
            FOR EACH packet IN json_object["sequence"] DO
                ADD packet to trace.sequence
            END FOR
            
            trace.valid = json_object["valid"]
            trace.description = json_object["description"] OR ""
            trace.category = json_object["category"] OR "Unknown"
            
            ADD trace to dataset
            
        CATCH parse_error
            PRINT "WARNING: Parse error at line", line_number
        END TRY
    END WHILE
    
    CLOSE file
    
    // Count valid/invalid
    valid_count = 0
    FOR EACH trace IN dataset DO
        IF trace.valid THEN
            valid_count = valid_count + 1
        END IF
    END FOR
    
    PRINT "SUCCESS: Loaded", LENGTH(dataset), "traces"
    PRINT "  Valid:", valid_count
    PRINT "  Invalid:", LENGTH(dataset) - valid_count
    
    RETURN dataset
    
END ALGORITHM
```

---

## 🔄 REGEX PARSER MODULE

### Thompson's Construction (Regex → NFA)

```pseudocode
// ==================== THOMPSON'S CONSTRUCTION ====================

ALGORITHM Regex_To_NFA
INPUT: regex: STRING (regular expression)
OUTPUT: NFA

BEGIN
    IF regex is empty THEN
        // Create NFA that accepts empty string
        nfa = NEW NFA
        start_state = CREATE_STATE(accepting=TRUE)
        nfa.add_state(start_state)
        nfa.start_state = start_state.id
        nfa.accepting_states.add(start_state.id)
        RETURN nfa
    END IF
    
    // Step 1: Add explicit concatenation operators
    processed_regex = Add_Concat_Operator(regex)
    
    // Step 2: Convert to postfix notation (Shunting Yard)
    postfix = Infix_To_Postfix(processed_regex)
    
    // Step 3: Build NFA from postfix expression
    nfa = Build_NFA_From_Postfix(postfix)
    
    RETURN nfa
    
END ALGORITHM


ALGORITHM Add_Concat_Operator
INPUT: regex: STRING
OUTPUT: STRING (regex with explicit '.' for concatenation)

BEGIN
    result = ""
    
    FOR i = 0 TO LENGTH(regex) - 1 DO
        current = regex[i]
        result = result + current
        
        IF i + 1 < LENGTH(regex) THEN
            next = regex[i + 1]
            
            // Need concatenation between:
            // - char and char: "ab" -> "a.b"
            // - char and '(': "a(" -> "a.("
            // - ')' and char: ")a" -> ").a"
            // - ')' and '(': ")(" -> ").("
            // - '*' and char: "*a" -> "*.a"
            
            need_concat = FALSE
            
            IF (is_alphanumeric(current) OR current = ')' OR current = '*') AND
               (is_alphanumeric(next) OR next = '(') THEN
                need_concat = TRUE
            END IF
            
            IF need_concat AND next ≠ '|' AND next ≠ '*' AND next ≠ '+' THEN
                result = result + '.'  // Add concatenation operator
            END IF
        END IF
    END FOR
    
    RETURN result
    
END ALGORITHM


ALGORITHM Infix_To_Postfix
INPUT: regex: STRING (with explicit concatenation)
OUTPUT: STRING (postfix expression)

BEGIN
    postfix = ""
    operator_stack = EMPTY STACK
    
    FOR EACH character c IN regex DO
        IF is_alphanumeric(c) THEN
            // Operand - add directly to output
            postfix = postfix + c
            
        ELSE IF c = '(' THEN
            PUSH c onto operator_stack
            
        ELSE IF c = ')' THEN
            // Pop until matching '('
            WHILE operator_stack is not empty AND TOP(operator_stack) ≠ '(' DO
                postfix = postfix + POP(operator_stack)
            END WHILE
            POP(operator_stack)  // Remove '('
            
        ELSE IF c is operator ('*', '+', '?', '|', '.') THEN
            // Pop operators with higher or equal precedence
            WHILE operator_stack is not empty AND 
                  TOP(operator_stack) ≠ '(' AND
                  precedence(TOP(operator_stack)) >= precedence(c) DO
                postfix = postfix + POP(operator_stack)
            END WHILE
            PUSH c onto operator_stack
        END IF
    END FOR
    
    // Pop remaining operators
    WHILE operator_stack is not empty DO
        postfix = postfix + POP(operator_stack)
    END WHILE
    
    RETURN postfix
    
END ALGORITHM


FUNCTION Get_Precedence
INPUT: operator: CHARACTER
OUTPUT: INTEGER (precedence value)

BEGIN
    IF operator = '*' OR operator = '+' OR operator = '?' THEN
        RETURN 3
    ELSE IF operator = '.' THEN
        RETURN 2
    ELSE IF operator = '|' THEN
        RETURN 1
    ELSE
        RETURN 0
    END IF
END FUNCTION


ALGORITHM Build_NFA_From_Postfix
INPUT: postfix: STRING
OUTPUT: NFA

BEGIN
    nfa_stack = EMPTY STACK
    state_counter = 0  // Global counter for unique state IDs
    
    FOR EACH character c IN postfix DO
        IF is_alphanumeric(c) THEN
            // Create single-character NFA
            nfa = Create_Char_NFA(c, state_counter)
            PUSH nfa onto nfa_stack
            
        ELSE IF c = '.' THEN
            // Concatenation
            IF SIZE(nfa_stack) < 2 THEN
                ERROR "Not enough operands for concatenation"
            END IF
            
            nfa2 = POP(nfa_stack)
            nfa1 = POP(nfa_stack)
            result = Concatenate_NFA(nfa1, nfa2)
            PUSH result onto nfa_stack
            
        ELSE IF c = '|' THEN
            // Alternation
            IF SIZE(nfa_stack) < 2 THEN
                ERROR "Not enough operands for alternation"
            END IF
            
            nfa2 = POP(nfa_stack)
            nfa1 = POP(nfa_stack)
            result = Alternate_NFA(nfa1, nfa2, state_counter)
            PUSH result onto nfa_stack
            
        ELSE IF c = '*' THEN
            // Kleene star
            IF nfa_stack is empty THEN
                ERROR "No operand for Kleene star"
            END IF
            
            nfa = POP(nfa_stack)
            result = Kleene_Star_NFA(nfa, state_counter)
            PUSH result onto nfa_stack
        END IF
    END FOR
    
    IF SIZE(nfa_stack) ≠ 1 THEN
        ERROR "Invalid regex: malformed expression"
    END IF
    
    RETURN POP(nfa_stack)
    
END ALGORITHM


// ==================== NFA CONSTRUCTION HELPERS ====================

ALGORITHM Create_Char_NFA
INPUT: 
    c: CHARACTER (input symbol)
    state_counter: INTEGER (reference, incremented)
OUTPUT: NFA

BEGIN
    nfa = NEW NFA
    
    // Create two states: start and accept
    start = CREATE_STATE(id=state_counter++, accepting=FALSE)
    accept = CREATE_STATE(id=state_counter++, accepting=TRUE)
    
    nfa.add_state(start)
    nfa.add_state(accept)
    
    nfa.start_state = start.id
    nfa.accepting_states.add(accept.id)
    
    // Add transition: start --c--> accept
    nfa.add_transition(start.id, accept.id, c, is_epsilon=FALSE)
    
    RETURN nfa
    
END ALGORITHM


ALGORITHM Concatenate_NFA
INPUT: nfa1, nfa2: NFA
OUTPUT: NFA (nfa1 followed by nfa2)

BEGIN
    result = COPY of nfa1
    
    // Add all states from nfa2
    FOR EACH state IN nfa2.states DO
        result.add_state(state)
    END FOR
    
    // Connect nfa1 accepting states to nfa2 start with ε-transition
    FOR EACH accept_state IN nfa1.accepting_states DO
        result.add_transition(accept_state, nfa2.start_state, 'ε', is_epsilon=TRUE)
    END FOR
    
    // Add all transitions from nfa2
    FOR EACH transition IN nfa2.transitions DO
        result.transitions.add(transition)
    END FOR
    
    // Result accepts only at nfa2's accepting states
    result.accepting_states = nfa2.accepting_states
    
    RETURN result
    
END ALGORITHM


ALGORITHM Alternate_NFA
INPUT: 
    nfa1, nfa2: NFA
    state_counter: INTEGER (reference)
OUTPUT: NFA (nfa1 | nfa2)

BEGIN
    result = NEW NFA
    
    // Create new start and accept states
    new_start = CREATE_STATE(id=state_counter++, accepting=FALSE)
    new_accept = CREATE_STATE(id=state_counter++, accepting=TRUE)
    
    result.add_state(new_start)
    result.add_state(new_accept)
    
    // Add all states from both NFAs
    FOR EACH state IN nfa1.states DO
        result.add_state(state)
    END FOR
    FOR EACH state IN nfa2.states DO
        result.add_state(state)
    END FOR
    
    // ε-transitions from new start to both NFA starts
    result.add_transition(new_start.id, nfa1.start_state, 'ε', TRUE)
    result.add_transition(new_start.id, nfa2.start_state, 'ε', TRUE)
    
    // Add all transitions from both NFAs
    FOR EACH transition IN nfa1.transitions DO
        result.transitions.add(transition)
    END FOR
    FOR EACH transition IN nfa2.transitions DO
        result.transitions.add(transition)
    END FOR
    
    // ε-transitions from both NFA accepting states to new accept
    FOR EACH accept IN nfa1.accepting_states DO
        result.add_transition(accept, new_accept.id, 'ε', TRUE)
    END FOR
    FOR EACH accept IN nfa2.accepting_states DO
        result.add_transition(accept, new_accept.id, 'ε', TRUE)
    END FOR
    
    result.start_state = new_start.id
    result.accepting_states.add(new_accept.id)
    
    RETURN result
    
END ALGORITHM


ALGORITHM Kleene_Star_NFA
INPUT: 
    nfa: NFA
    state_counter: INTEGER (reference)
OUTPUT: NFA (nfa*)

BEGIN
    result = NEW NFA
    
    // Create new start and accept states
    new_start = CREATE_STATE(id=state_counter++, accepting=FALSE)
    new_accept = CREATE_STATE(id=state_counter++, accepting=TRUE)
    
    result.add_state(new_start)
    result.add_state(new_accept)
    
    // Add all states from original NFA
    FOR EACH state IN nfa.states DO
        result.add_state(state)
    END FOR
    
    // ε-transitions from new start to:
    // 1. Original NFA start (for one or more repetitions)
    // 2. New accept (for zero repetitions)
    result.add_transition(new_start.id, nfa.start_state, 'ε', TRUE)
    result.add_transition(new_start.id, new_accept.id, 'ε', TRUE)
    
    // Add all transitions from original NFA
    FOR EACH transition IN nfa.transitions DO
        result.transitions.add(transition)
    END FOR
    
    // ε-transitions from NFA accepting states to:
    // 1. NFA start (for repetition)
    // 2. New accept (to finish)
    FOR EACH accept IN nfa.accepting_states DO
        result.add_transition(accept, nfa.start_state, 'ε', TRUE)
        result.add_transition(accept, new_accept.id, 'ε', TRUE)
    END FOR
    
    result.start_state = new_start.id
    result.accepting_states.add(new_accept.id)
    
    RETURN result
    
END ALGORITHM
```

---

## 🔄 NFA TO DFA CONVERTER

### Subset Construction Algorithm

```pseudocode
// ==================== SUBSET CONSTRUCTION ====================

ALGORITHM NFA_To_DFA
INPUT: nfa: NFA
OUTPUT: DFA

BEGIN
    dfa = NEW DFA
    state_counter = 0
    
    // Map: Set of NFA states -> DFA state ID
    state_map = EMPTY MAP
    
    // Worklist: DFA states to process
    worklist = EMPTY QUEUE
    
    // Step 1: Compute ε-closure of NFA start state
    start_closure = Epsilon_Closure(nfa, {nfa.start_state})
    
    // Step 2: Create DFA start state
    dfa_start_id = state_counter++
    state_map[start_closure] = dfa_start_id
    
    // Check if start state is accepting
    is_accepting = FALSE
    FOR EACH nfa_state IN start_closure DO
        IF nfa_state IN nfa.accepting_states THEN
            is_accepting = TRUE
            BREAK
        END IF
    END FOR
    
    dfa_start = CREATE_STATE(dfa_start_id, is_accepting)
    dfa.add_state(dfa_start)
    dfa.start_state = dfa_start_id
    IF is_accepting THEN
        dfa.accepting_states.add(dfa_start_id)
    END IF
    
    // Add to worklist
    ENQUEUE start_closure to worklist
    
    // Step 3: Process all unmarked states
    WHILE worklist is not empty DO
        current_nfa_states = DEQUEUE from worklist
        current_dfa_id = state_map[current_nfa_states]
        
        // For each symbol in alphabet
        FOR EACH symbol IN nfa.alphabet DO
            // Compute states reachable on symbol
            next_nfa_states = Move(nfa, current_nfa_states, symbol)
            
            // Compute ε-closure of those states
            next_closure = Epsilon_Closure(nfa, next_nfa_states)
            
            IF next_closure is empty THEN
                CONTINUE  // No transition on this symbol
            END IF
            
            // Check if this DFA state already exists
            IF next_closure NOT IN state_map THEN
                // Create new DFA state
                new_dfa_id = state_counter++
                state_map[next_closure] = new_dfa_id
                
                // Check if accepting
                is_accepting = FALSE
                FOR EACH nfa_state IN next_closure DO
                    IF nfa_state IN nfa.accepting_states THEN
                        is_accepting = TRUE
                        BREAK
                    END IF
                END FOR
                
                new_state = CREATE_STATE(new_dfa_id, is_accepting)
                dfa.add_state(new_state)
                IF is_accepting THEN
                    dfa.accepting_states.add(new_dfa_id)
                END IF
                
                // Add to worklist
                ENQUEUE next_closure to worklist
            END IF
            
            // Add transition in DFA
            next_dfa_id = state_map[next_closure]
            dfa.add_transition(current_dfa_id, symbol, next_dfa_id)
        END FOR
    END WHILE
    
    RETURN dfa
    
END ALGORITHM


ALGORITHM Epsilon_Closure
INPUT: 
    nfa: NFA
    states: SET<INTEGER> (set of NFA state IDs)
OUTPUT: SET<INTEGER> (ε-closure of states)

BEGIN
    closure = COPY of states
    stack = NEW STACK
    
    // Push all states onto stack
    FOR EACH state IN states DO
        PUSH state onto stack
    END FOR
    
    // DFS/BFS through ε-transitions
    WHILE stack is not empty DO
        current = POP from stack
        
        // Find all ε-transitions from current
        FOR EACH transition IN nfa.transitions DO
            IF transition.from_state = current AND transition.is_epsilon THEN
                IF transition.to_state NOT IN closure THEN
                    closure.add(transition.to_state)
                    PUSH transition.to_state onto stack
                END IF
            END IF
        END FOR
    END WHILE
    
    RETURN closure
    
END ALGORITHM


ALGORITHM Move
INPUT:
    nfa: NFA
    states: SET<INTEGER> (set of NFA state IDs)
    symbol: CHARACTER
OUTPUT: SET<INTEGER> (states reachable on symbol)

BEGIN
    result = EMPTY SET
    
    FOR EACH state IN states DO
        FOR EACH transition IN nfa.transitions DO
            IF transition.from_state = state AND
               transition.symbol = symbol AND
               NOT transition.is_epsilon THEN
                result.add(transition.to_state)
            END IF
        END FOR
    END FOR
    
    RETURN result
    
END ALGORITHM
```

---

## 🔄 DFA MINIMIZER

### Hopcroft's Algorithm

```pseudocode
// ==================== HOPCROFT'S ALGORITHM ====================

ALGORITHM Minimize_DFA
INPUT: dfa: DFA
OUTPUT: DFA (minimized)

BEGIN
    // Step 1: Initial partition
    // Separate accepting and non-accepting states
    accepting = dfa.accepting_states
    non_accepting = EMPTY SET
    
    FOR EACH state IN dfa.states DO
        IF state.id NOT IN accepting THEN
            non_accepting.add(state.id)
        END IF
    END FOR
    
    partitions = [non_accepting, accepting]
    
    // Step 2: Refine partitions until no more splits
    changed = TRUE
    
    WHILE changed DO
        changed = FALSE
        new_partitions = EMPTY LIST
        
        FOR EACH partition P IN partitions DO
            // Try to split partition P
            splits = Split_Partition(dfa, P, partitions)
            
            IF LENGTH(splits) > 1 THEN
                // Partition was split
                changed = TRUE
                FOR EACH split IN splits DO
                    new_partitions.add(split)
                END FOR
            ELSE
                // Partition stays the same
                new_partitions.add(P)
            END IF
        END FOR
        
        partitions = new_partitions
    END WHILE
    
    // Step 3: Build minimized DFA from partitions
    minimized = Build_DFA_From_Partitions(dfa, partitions)
    
    RETURN minimized
    
END ALGORITHM


ALGORITHM Split_Partition
INPUT:
    dfa: DFA
    partition: SET<INTEGER> (states to potentially split)
    all_partitions: LIST<SET<INTEGER>>
OUTPUT: LIST<SET<INTEGER>> (split partitions)

BEGIN
    // Group states by their transition behavior
    groups = EMPTY MAP  // Map: transition_signature -> states
    
    FOR EACH state IN partition DO
        signature = EMPTY LIST
        
        // For each symbol, find which partition the state goes to
        FOR EACH symbol IN dfa.alphabet DO
            next_state = dfa.get_next_state(state, symbol)
            
            // Find which partition next_state belongs to
            partition_index = -1
            FOR i = 0 TO LENGTH(all_partitions) - 1 DO
                IF next_state IN all_partitions[i] THEN
                    partition_index = i
                    BREAK
                END IF
            END FOR
            
            signature.add(partition_index)
        END FOR
        
        // Group states with same signature
        IF signature NOT IN groups THEN
            groups[signature] = EMPTY SET
        END IF
        groups[signature].add(state)
    END FOR
    
    // Return all groups as separate partitions
    result = EMPTY LIST
    FOR EACH group IN groups.values DO
        result.add(group)
    END FOR
    
    RETURN result
    
END ALGORITHM


ALGORITHM Build_DFA_From_Partitions
INPUT:
    original_dfa: DFA
    partitions: LIST<SET<INTEGER>>
OUTPUT: DFA (minimized)

BEGIN
    minimized = NEW DFA
    state_counter = 0
    
    // Map: partition index -> new DFA state ID
    partition_to_state = EMPTY MAP
    
    // Create new states (one per partition)
    FOR i = 0 TO LENGTH(partitions) - 1 DO
        partition = partitions[i]
        
        // Check if partition contains accepting state
        is_accepting = FALSE
        FOR EACH state_id IN partition DO
            IF state_id IN original_dfa.accepting_states THEN
                is_accepting = TRUE
                BREAK
            END IF
        END FOR
        
        new_state = CREATE_STATE(state_counter, is_accepting)
        minimized.add_state(new_state)
        partition_to_state[i] = state_counter
        
        IF is_accepting THEN
            minimized.accepting_states.add(state_counter)
        END IF
        
        state_counter = state_counter + 1
    END FOR
    
    // Set start state (partition containing original start)
    FOR i = 0 TO LENGTH(partitions) - 1 DO
        IF original_dfa.start_state IN partitions[i] THEN
            minimized.start_state = partition_to_state[i]
            BREAK
        END IF
    END FOR
    
    // Create transitions
    FOR i = 0 TO LENGTH(partitions) - 1 DO
        partition = partitions[i]
        representative = ANY state from partition  // Pick any state as representative
        
        FOR EACH symbol IN original_dfa.alphabet DO
            next_state = original_dfa.get_next_state(representative, symbol)
            
            IF next_state ≠ -1 THEN
                // Find partition containing next_state
                FOR j = 0 TO LENGTH(partitions) - 1 DO
                    IF next_state IN partitions[j] THEN
                        from_id = partition_to_state[i]
                        to_id = partition_to_state[j]
                        minimized.add_transition(from_id, symbol, to_id)
                        BREAK
                    END IF
                END FOR
            END IF
        END FOR
    END FOR
    
    RETURN minimized
    
END ALGORITHM
```

---

## 🔄 IGA MODULE

### Improved Grouping Algorithm

```pseudocode
// ==================== IMPROVED GROUPING ALGORITHM (IGA) ====================

ALGORITHM Apply_IGA
INPUT: dfas: LIST<DFA> (list of minimized DFAs)
OUTPUT: LIST<DFA> (grouped DFAs with reduced states)

BEGIN
    // Step 1: Initialize - each DFA in its own group
    groups = EMPTY LIST
    FOR EACH dfa IN dfas DO
        group = [dfa]
        groups.add(group)
    END FOR
    
    // Step 2: Compute pairwise expansion coefficients
    ec_matrix = Compute_EC_Matrix(groups)
    
    // Step 3: Iteratively merge groups with lowest EC
    WHILE TRUE DO
        // Find pair with lowest expansion coefficient
        min_ec = INFINITY
        best_i = -1
        best_j = -1
        
        FOR i = 0 TO LENGTH(groups) - 1 DO
            FOR j = i + 1 TO LENGTH(groups) - 1 DO
                IF ec_matrix[i][j] < min_ec THEN
                    min_ec = ec_matrix[i][j]
                    best_i = i
                    best_j = j
                END IF
            END FOR
        END FOR
        
        // Threshold check (Wang 2016: EC < 0.5 is good for merging)
        IF min_ec > 0.5 THEN
            BREAK  // Stop merging
        END IF
        
        // Merge groups i and j
        merged_group = groups[best_i] + groups[best_j]
        
        // Remove old groups and add merged group
        REMOVE groups[best_j] from groups  // Remove j first (higher index)
        REMOVE groups[best_i] from groups
        groups.add(merged_group)
        
        // Recompute EC matrix
        ec_matrix = Compute_EC_Matrix(groups)
    END WHILE
    
    // Step 4: Build final grouped DFAs
    result = EMPTY LIST
    FOR EACH group IN groups DO
        merged_dfa = Merge_DFAs(group)
        result.add(merged_dfa)
    END FOR
    
    RETURN result
    
END ALGORITHM


ALGORITHM Compute_EC_Matrix
INPUT: groups: LIST<LIST<DFA>> (groups of DFAs)
OUTPUT: MATRIX<REAL> (expansion coefficient matrix)

BEGIN
    n = LENGTH(groups)
    ec_matrix = n × n matrix initialized with 0
    
    FOR i = 0 TO n - 1 DO
        FOR j = i + 1 TO n - 1 DO
            ec = Calculate_Expansion_Coefficient(groups[i], groups[j])
            ec_matrix[i][j] = ec
            ec_matrix[j][i] = ec
        END FOR
    END FOR
    
    RETURN ec_matrix
    
END ALGORITHM


ALGORITHM Calculate_Expansion_Coefficient
INPUT: 
    group_a: LIST<DFA>
    group_b: LIST<DFA>
OUTPUT: REAL (expansion coefficient)

BEGIN
    // Count states in each group
    states_a = 0
    FOR EACH dfa IN group_a DO
        states_a = states_a + dfa.get_state_count()
    END FOR
    
    states_b = 0
    FOR EACH dfa IN group_b DO
        states_b = states_b + dfa.get_state_count()
    END FOR
    
    // Merge groups temporarily and count states
    merged_group = group_a + group_b
    merged_dfa = Merge_DFAs(merged_group)
    states_merged = merged_dfa.get_state_count()
    
    // Calculate expansion coefficient
    // EC = (states_merged - states_a - states_b) / (states_a + states_b)
    
    IF states_a + states_b = 0 THEN
        RETURN 0
    END IF
    
    ec = (states_merged - states_a - states_b) / (states_a + states_b)
    
    RETURN ec
    
END ALGORITHM


ALGORITHM Merge_DFAs
INPUT: dfas: LIST<DFA> (DFAs to merge)
OUTPUT: DFA (merged DFA)

BEGIN
    IF LENGTH(dfas) = 0 THEN
        RETURN empty DFA
    END IF
    
    IF LENGTH(dfas) = 1 THEN
        RETURN dfas[0]
    END IF
    
    // Use product construction to merge multiple DFAs
    // Each state in merged DFA represents a tuple of states from individual DFAs
    
    merged = NEW DFA
    state_counter = 0
    
    // Map: tuple of DFA states -> merged DFA state
    state_map = EMPTY MAP
    worklist = EMPTY QUEUE
    
    // Create start state (tuple of all start states)
    start_tuple = EMPTY LIST
    FOR EACH dfa IN dfas DO
        start_tuple.add(dfa.start_state)
    END FOR
    
    merged_start_id = state_counter++
    state_map[start_tuple] = merged_start_id
    
    // Check if accepting (any DFA in accepting state)
    is_accepting = FALSE
    FOR i = 0 TO LENGTH(dfas) - 1 DO
        IF start_tuple[i] IN dfas[i].accepting_states THEN
            is_accepting = TRUE
            BREAK
        END IF
    END FOR
    
    merged.add_state(CREATE_STATE(merged_start_id, is_accepting))
    merged.start_state = merged_start_id
    IF is_accepting THEN
        merged.accepting_states.add(merged_start_id)
    END IF
    
    ENQUEUE start_tuple to worklist
    
    // Build alphabet (union of all DFA alphabets)
    alphabet = EMPTY SET
    FOR EACH dfa IN dfas DO
        FOR EACH symbol IN dfa.alphabet DO
            alphabet.add(symbol)
        END FOR
    END FOR
    merged.alphabet = alphabet
    
    // Process all state tuples
    WHILE worklist is not empty DO
        current_tuple = DEQUEUE from worklist
        current_id = state_map[current_tuple]
        
        FOR EACH symbol IN alphabet DO
            next_tuple = EMPTY LIST
            valid = TRUE
            
            // Compute next state for each DFA
            FOR i = 0 TO LENGTH(dfas) - 1 DO
                next = dfas[i].get_next_state(current_tuple[i], symbol)
                IF next = -1 THEN
                    valid = FALSE
                    BREAK
                END IF
                next_tuple.add(next)
            END FOR
            
            IF NOT valid THEN
                CONTINUE  // Skip this symbol
            END IF
            
            // Create new state if needed
            IF next_tuple NOT IN state_map THEN
                new_id = state_counter++
                state_map[next_tuple] = new_id
                
                // Check if accepting
                is_accepting = FALSE
                FOR i = 0 TO LENGTH(dfas) - 1 DO
                    IF next_tuple[i] IN dfas[i].accepting_states THEN
                        is_accepting = TRUE
                        BREAK
                    END IF
                END FOR
                
                merged.add_state(CREATE_STATE(new_id, is_accepting))
                IF is_accepting THEN
                    merged.accepting_states.add(new_id)
                END IF
                
                ENQUEUE next_tuple to worklist
            END IF
            
            next_id = state_map[next_tuple]
            merged.add_transition(current_id, symbol, next_id)
        END FOR
    END WHILE
    
    RETURN merged
    
END ALGORITHM
```

---

## 📁 DFA MODULE

### Filename Pattern Detection

```pseudocode
// ==================== DFA MODULE ====================

ALGORITHM DFA_Module_Workflow

BEGIN
    module = NEW DFA_Module
    
    // Step 1: Load Dataset
    module.dataset = Load_Filename_Dataset("archive/Malicious_file_trick_detection.jsonl")
    module.metrics.filenames_tested = LENGTH(module.dataset)
    
    // Step 2: Define Patterns
    module.Define_Patterns()
    
    // Step 3: Build NFAs
    module.Build_NFAs()
    
    // Step 4: Convert to DFAs
    module.Convert_To_DFAs()
    
    // Step 5: Minimize DFAs
    module.Minimize_DFAs()
    
    // Step 6: Apply IGA
    module.Apply_IGA()
    
    // Step 7: Test Patterns
    module.Test_Patterns()
    
    // Step 8: Generate Report
    module.Generate_Report()
    
END ALGORITHM


ALGORITHM Define_Patterns

BEGIN
    PRINT "Defining regex patterns..."
    
    // Pattern 1: Double extension
    ADD ".*\\.(pdf|doc|docx|txt|xlsx)\\.(exe|scr|bat|com|vbs)" to patterns
    ADD "double_extension" to pattern_names
    
    // Pattern 2: Unicode Right-to-Left Override
    ADD ".*[\\u202E\\u202D].*\\.(exe|scr|bat)" to patterns
    ADD "unicode_rtlo" to pattern_names
    
    // Pattern 3: Whitespace padding
    ADD ".*\\s{2,}\\.(exe|scr|bat|com)" to patterns
    ADD "whitespace_padding" to pattern_names
    
    // Pattern 4: Mimic legitimate files
    ADD ".*(update|patch|installer|setup|system)\\.(iso|img|msi|dll)" to patterns
    ADD "mimic_legitimate" to pattern_names
    
    // Pattern 5: Unicode homoglyph
    ADD ".*[\\uFF21-\\uFF5A]+$" to patterns
    ADD "unicode_homoglyph" to pattern_names
    
    metrics.total_patterns = LENGTH(patterns)
    
    PRINT "Defined", metrics.total_patterns, "patterns"
    
END ALGORITHM


ALGORITHM Build_NFAs

BEGIN
    PRINT "Converting regex to NFAs..."
    
    FOR EACH pattern IN patterns DO
        TRY
            nfa = Regex_To_NFA(pattern)
            ADD nfa to nfas
            metrics.total_nfa_states += nfa.get_state_count()
        CATCH exception
            PRINT "ERROR: Failed to build NFA for", pattern
        END TRY
    END FOR
    
    PRINT "Built", LENGTH(nfas), "NFAs"
    PRINT "Total NFA states:", metrics.total_nfa_states
    
END ALGORITHM


ALGORITHM Convert_To_DFAs

BEGIN
    PRINT "Converting NFAs to DFAs (Subset Construction)..."
    
    start_time = GET_CURRENT_TIME()
    
    FOR EACH nfa IN nfas DO
        dfa = NFA_To_DFA(nfa)
        ADD dfa to dfas
        metrics.total_dfa_states_before_min += dfa.get_state_count()
    END FOR
    
    end_time = GET_CURRENT_TIME()
    conversion_time = end_time - start_time
    
    PRINT "Built", LENGTH(dfas), "DFAs"
    PRINT "Total states:", metrics.total_dfa_states_before_min
    PRINT "Conversion time:", conversion_time, "ms"
    
END ALGORITHM


ALGORITHM Minimize_DFAs

BEGIN
    PRINT "Minimizing DFAs (Hopcroft's Algorithm)..."
    
    start_time = GET_CURRENT_TIME()
    
    FOR EACH dfa IN dfas DO
        minimized = Minimize_DFA(dfa)
        ADD minimized to minimized_dfas
        metrics.total_dfa_states_after_min += minimized.get_state_count()
    END FOR
    
    end_time = GET_CURRENT_TIME()
    minimization_time = end_time - start_time
    
    // Calculate reduction percentage
    states_reduced = metrics.total_dfa_states_before_min - metrics.total_dfa_states_after_min
    metrics.state_reduction_min_percent = (states_reduced / metrics.total_dfa_states_before_min) * 100.0
    
    PRINT "Minimized", LENGTH(minimized_dfas), "DFAs"
    PRINT "States after minimization:", metrics.total_dfa_states_after_min
    PRINT "Reduction:", states_reduced, "(", metrics.state_reduction_min_percent, "%)"
    PRINT "Minimization time:", minimization_time, "ms"
    
END ALGORITHM


ALGORITHM Apply_IGA

BEGIN
    PRINT "Applying IGA (Improved Grouping Algorithm)..."
    
    start_time = GET_CURRENT_TIME()
    
    grouped_dfas = Apply_IGA(minimized_dfas)
    
    // Count total states after grouping
    metrics.total_dfa_states_after_iga = 0
    FOR EACH dfa IN grouped_dfas DO
        metrics.total_dfa_states_after_iga += dfa.get_state_count()
    END FOR
    
    end_time = GET_CURRENT_TIME()
    iga_time = end_time - start_time
    
    // Calculate IGA reduction
    iga_reduction = metrics.total_dfa_states_after_min - metrics.total_dfa_states_after_iga
    metrics.state_reduction_iga_percent = (iga_reduction / metrics.total_dfa_states_after_min) * 100.0
    
    // Calculate total reduction
    total_reduction = metrics.total_dfa_states_before_min - metrics.total_dfa_states_after_iga
    metrics.total_reduction_percent = (total_reduction / metrics.total_dfa_states_before_min) * 100.0
    
    PRINT "IGA complete"
    PRINT "Groups created:", LENGTH(grouped_dfas)
    PRINT "States after IGA:", metrics.total_dfa_states_after_iga
    PRINT "IGA reduction:", iga_reduction, "(", metrics.state_reduction_iga_percent, "%)"
    PRINT "Total reduction:", total_reduction, "(", metrics.total_reduction_percent, "%)"
    PRINT "IGA time:", iga_time, "ms"
    
END ALGORITHM


ALGORITHM Test_Patterns

BEGIN
    PRINT "Testing", LENGTH(dataset), "filenames..."
    
    start_time = GET_CURRENT_TIME()
    
    FOR EACH entry IN dataset DO
        matched_pattern = ""
        detected = Test_Filename(entry.filename, matched_pattern)
        
        // Update metrics
        IF detected AND entry.is_malicious THEN
            metrics.true_positives += 1
        ELSE IF detected AND NOT entry.is_malicious THEN
            metrics.false_positives += 1
        ELSE IF NOT detected AND entry.is_malicious THEN
            metrics.false_negatives += 1
        END IF
    END FOR
    
    end_time = GET_CURRENT_TIME()
    metrics.total_execution_time_ms = end_time - start_time
    metrics.avg_matching_time_ms = metrics.total_execution_time_ms / LENGTH(dataset)
    
    // Calculate accuracy
    metrics.detection_accuracy = (metrics.true_positives / LENGTH(dataset)) * 100.0
    
    PRINT "Testing complete"
    PRINT "Detection accuracy:", metrics.detection_accuracy, "%"
    
END ALGORITHM


ALGORITHM Test_Filename
INPUT: 
    filename: STRING
    matched_pattern: STRING (output parameter)
OUTPUT: BOOLEAN (true if detected as malicious)

BEGIN
    // Test filename against all grouped DFAs
    FOR i = 0 TO LENGTH(grouped_dfas) - 1 DO
        IF grouped_dfas[i].accepts(filename) THEN
            matched_pattern = pattern_names[i]
            RETURN TRUE
        END IF
    END FOR
    
    RETURN FALSE
    
END ALGORITHM


ALGORITHM Generate_Report

BEGIN
    PRINT ""
    PRINT "[RESULTS] DFA Detection Summary:"
    PRINT "  ✓ True Positives: ", metrics.true_positives
    PRINT "  ✗ False Positives:", metrics.false_positives
    PRINT "  ✗ False Negatives:", metrics.false_negatives
    PRINT "  Detection Rate:", metrics.detection_accuracy, "%"
    
    PRINT ""
    PRINT "[PERFORMANCE] DFA Metrics:"
    PRINT "  Total patterns:", metrics.total_patterns
    PRINT "  NFA states:", metrics.total_nfa_states
    PRINT "  DFA states (before min):", metrics.total_dfa_states_before_min
    PRINT "  DFA states (after min):", metrics.total_dfa_states_after_min
    PRINT "  DFA states (after IGA):", metrics.total_dfa_states_after_iga
    PRINT "  Minimization reduction:", metrics.state_reduction_min_percent, "%"
    PRINT "  IGA reduction:", metrics.state_reduction_iga_percent, "%"
    PRINT "  Total reduction:", metrics.total_reduction_percent, "%"
    PRINT "  Execution time:", metrics.total_execution_time_ms, "ms"
    PRINT "  Avg per file:", metrics.avg_matching_time_ms, "ms"
    
END ALGORITHM
```

---

## 🔄 PDA MODULE

### TCP Protocol Validation

```pseudocode
// ==================== PDA MODULE ====================

ALGORITHM PDA_Module_Workflow

BEGIN
    module = NEW PDA_Module
    
    // Step 1: Load Dataset
    module.dataset = Load_TCP_Dataset("archive/tcp_handshake_traces_expanded.jsonl")
    module.metrics.total_traces = LENGTH(module.dataset)
    
    // Count valid/invalid
    FOR EACH trace IN module.dataset DO
        IF trace.valid THEN
            module.metrics.valid_traces += 1
        ELSE
            module.metrics.invalid_traces += 1
        END IF
    END FOR
    
    // Step 2: Build PDA
    module.Build_PDA()
    
    // Step 3: Test All Traces
    module.Test_All_Traces()
    
    // Step 4: Show Sample Operations
    sample_traces = [
        ["SYN", "SYN-ACK", "ACK"],
        ["SYN", "ACK"],
        ["ACK", "SYN", "SYN-ACK"],
        ["SYN", "SYN-ACK"],
        ["SYN", "SYN", "ACK"]
    ]
    
    PRINT "[SAMPLE STACK OPERATIONS]"
    FOR EACH trace IN sample_traces DO
        module.Show_Stack_Operations(trace)
    END FOR
    
    // Step 5: Generate Report
    module.Generate_Report()
    
END ALGORITHM


ALGORITHM Build_PDA

BEGIN
    PRINT "Building PDA for TCP 3-way handshake..."
    
    // Define PDA states
    Q_START = 0
    Q_SYN_RECEIVED = 1
    Q_SYNACK_RECEIVED = 2
    Q_ACCEPT = 3
    Q_ERROR = -1
    
    // Initialize PDA
    pda = NEW PDA
    
    pda.states.add(CREATE_STATE(Q_START, FALSE, "q_start"))
    pda.states.add(CREATE_STATE(Q_SYN_RECEIVED, FALSE, "q_syn_recv"))
    pda.states.add(CREATE_STATE(Q_SYNACK_RECEIVED, FALSE, "q_synack_recv"))
    pda.states.add(CREATE_STATE(Q_ACCEPT, TRUE, "q_accept"))
    
    pda.start_state = Q_START
    pda.accepting_states.add(Q_ACCEPT)
    pda.current_state = Q_START
    
    // Initialize stack with bottom marker
    pda.pda_stack.push("BOTTOM")
    
    PRINT "PDA constructed"
    PRINT "  States: {q_start, q_syn_recv, q_synack_recv, q_accept, q_error}"
    PRINT "  Stack alphabet: {SYN, SYN-ACK, BOTTOM}"
    PRINT "  Transitions:"
    PRINT "    q_start + SYN → q_syn_recv [PUSH SYN]"
    PRINT "    q_syn_recv + SYN-ACK → q_synack_recv [PUSH SYN-ACK]"
    PRINT "    q_synack_recv + ACK → q_accept [POP ALL]"
    PRINT "    q_accept + DATA/FIN → q_accept [NO CHANGE]"
    PRINT "    ANY + RST → q_error"
    
END ALGORITHM


ALGORITHM Validate_Sequence
INPUT: sequence: LIST<STRING> (TCP packets)
OUTPUT: BOOLEAN (true if valid handshake)

BEGIN
    pda.reset()  // Reset to initial state
    
    FOR EACH packet IN sequence DO
        operations = EMPTY LIST
        success = Process_Packet(packet, operations)
        
        IF NOT success THEN
            RETURN FALSE
        END IF
    END FOR
    
    // Check if in accepting state and stack is empty (only BOTTOM)
    RETURN pda.is_accepting()
    
END ALGORITHM


ALGORITHM Process_Packet
INPUT: 
    packet: STRING
    operations: LIST<STRING> (output - stack operations performed)
OUTPUT: BOOLEAN (true if packet processed successfully)

BEGIN
    stack_top = pda.peek()
    current = pda.current_state
    
    // Define state constants
    Q_START = 0
    Q_SYN_RECEIVED = 1
    Q_SYNACK_RECEIVED = 2
    Q_ACCEPT = 3
    Q_ERROR = -1
    
    // Transition rules
    IF current = Q_START AND packet = "SYN" THEN
        pda.push("SYN")
        pda.current_state = Q_SYN_RECEIVED
        operations.add("PUSH SYN")
        RETURN TRUE
        
    ELSE IF current = Q_SYN_RECEIVED AND packet = "SYN-ACK" AND stack_top = "SYN" THEN
        pda.push("SYN-ACK")
        pda.current_state = Q_SYNACK_RECEIVED
        operations.add("PUSH SYN-ACK")
        RETURN TRUE
        
    ELSE IF current = Q_SYNACK_RECEIVED AND packet = "ACK" AND stack_top = "SYN-ACK" THEN
        pda.pop()  // Remove SYN-ACK
        pda.pop()  // Remove SYN
        pda.current_state = Q_ACCEPT
        operations.add("POP ALL")
        RETURN TRUE
        
    ELSE IF current = Q_ACCEPT AND (packet = "DATA" OR packet = "FIN" OR packet = "ACK") THEN
        // Allow data transfer / connection close after handshake
        operations.add("ALLOW " + packet)
        RETURN TRUE
        
    ELSE IF packet = "RST" THEN
        // Reset always causes error
        pda.current_state = Q_ERROR
        operations.add("ERROR: RST received")
        RETURN FALSE
        
    ELSE
        // Invalid transition
        pda.current_state = Q_ERROR
        operations.add("ERROR: Invalid transition")
        RETURN FALSE
    END IF
    
END ALGORITHM


ALGORITHM Test_All_Traces

BEGIN
    PRINT "Validating", LENGTH(dataset), "TCP traces..."
    
    start_time = GET_CURRENT_TIME()
    total_stack_depth = 0
    
    FOR EACH trace IN dataset DO
        result = Validate_Sequence(trace.sequence)
        
        // Track stack depth
        depth = pda.get_stack_depth()
        IF depth > metrics.max_stack_depth THEN
            metrics.max_stack_depth = depth
        END IF
        total_stack_depth += depth
        
        // Update metrics based on result
        IF result AND trace.valid THEN
            metrics.correctly_accepted += 1
        ELSE IF NOT result AND NOT trace.valid THEN
            metrics.correctly_rejected += 1
        ELSE IF result AND NOT trace.valid THEN
            metrics.false_positives += 1
        ELSE IF NOT result AND trace.valid THEN
            metrics.false_negatives += 1
        END IF
    END FOR
    
    end_time = GET_CURRENT_TIME()
    metrics.total_execution_time_ms = end_time - start_time
    metrics.avg_validation_time_ms = metrics.total_execution_time_ms / LENGTH(dataset)
    
    // Calculate average stack depth
    metrics.avg_stack_depth = total_stack_depth / LENGTH(dataset)
    
    // Calculate accuracy
    correct = metrics.correctly_accepted + metrics.correctly_rejected
    metrics.validation_accuracy = (correct / LENGTH(dataset)) * 100.0
    
    PRINT "Validation complete"
    PRINT "  Accuracy:", metrics.validation_accuracy, "%"
    
END ALGORITHM


ALGORITHM Show_Stack_Operations
INPUT: sequence: LIST<STRING>

BEGIN
    pda.reset()
    
    PRINT ""
    PRINT "Sequence: [", JOIN(sequence, ", "), "]"
    
    step_number = 1
    
    FOR EACH packet IN sequence DO
        state_before = pda.current_state
        stack_before = pda.peek()
        depth_before = pda.get_stack_depth()
        
        operations = EMPTY LIST
        success = Process_Packet(packet, operations)
        
        state_after = pda.current_state
        depth_after = pda.get_stack_depth()
        
        // Print step
        PRINT "  Step", step_number, ":", packet,
              "| State:", Get_State_Name(state_before), "→", Get_State_Name(state_after),
              "| Stack depth:", depth_before, "→", depth_after
        
        IF NOT success THEN
            PRINT "    [ERROR:", operations[0], "]"
        ELSE
            PRINT "    [", operations[0], "]"
        END IF
        
        step_number += 1
    END FOR
    
    // Print result
    IF pda.is_accepting() THEN
        PRINT "  Result: ✓ VALID (handshake complete, stack cleared)"
    ELSE
        PRINT "  Result: ✗ INVALID (", Get_Error_Reason(), ")"
    END IF
    
END ALGORITHM


FUNCTION Get_State_Name
INPUT: state_id: INTEGER
OUTPUT: STRING

BEGIN
    IF state_id = 0 THEN RETURN "q_start"
    ELSE IF state_id = 1 THEN RETURN "q_syn_recv"
    ELSE IF state_id = 2 THEN RETURN "q_synack_recv"
    ELSE IF state_id = 3 THEN RETURN "q_accept"
    ELSE RETURN "q_error"
END FUNCTION


FUNCTION Get_Error_Reason
OUTPUT: STRING

BEGIN
    IF pda.current_state = -1 THEN
        RETURN "Invalid state transition"
    ELSE IF pda.get_stack_depth() > 0 THEN
        RETURN "Incomplete handshake"
    ELSE
        RETURN "Unknown error"
    END IF
END FUNCTION


ALGORITHM Generate_Report

BEGIN
    PRINT ""
    PRINT "[RESULTS] PDA Validation Summary:"
    PRINT "  Total traces:", metrics.total_traces
    PRINT "  Valid sequences:", metrics.valid_traces
    PRINT "  Invalid sequences:", metrics.invalid_traces
    PRINT "  ✓ Valid accepted:", metrics.correctly_accepted, "/", metrics.valid_traces
    PRINT "  ✓ Invalid rejected:", metrics.correctly_rejected, "/", metrics.invalid_traces
    PRINT "  ✗ False positives:", metrics.false_positives
    PRINT "  ✗ False negatives:", metrics.false_negatives
    PRINT "  Validation accuracy:", metrics.validation_accuracy, "%"
    
    PRINT ""
    PRINT "[PERFORMANCE] PDA Metrics:"
    PRINT "  Average stack depth:", metrics.avg_stack_depth
    PRINT "  Maximum stack depth:", metrics.max_stack_depth
    PRINT "  Average time per trace:", metrics.avg_validation_time_ms, "ms"
    PRINT "  Total execution time:", metrics.total_execution_time_ms, "ms"
    
    PRINT ""
    PRINT "[KEY INSIGHT]"
    PRINT "  The PDA successfully validates TCP handshakes by using"
    PRINT "  the stack to match SYN with SYN-ACK, then verify ACK."
    PRINT "  A DFA cannot do this because it has no memory to track"
    PRINT "  which packets have been seen (no stack/counter)."
    
END ALGORITHM
```

---

## 🎯 COMPLETE WORKFLOW PSEUDOCODE

```pseudocode
// ==================== INTEGRATED SYSTEM ====================

ALGORITHM Complete_Security_Simulator

INPUT:
    filename_dataset: "archive/Malicious_file_trick_detection.jsonl"
    tcp_dataset: "archive/tcp_handshake_traces_expanded.jsonl"

OUTPUT:
    Console output with complete analysis
    Performance comparison
    Chomsky Hierarchy demonstration

BEGIN
    // ==================== INITIALIZATION ====================
    
    PRINT "======================================================="
    PRINT "   CS311 Chomsky Hierarchy Security Simulator"
    PRINT "   Filename Detection & TCP Protocol Validation"
    PRINT "======================================================="
    PRINT ""
    
    total_start_time = GET_CURRENT_TIME()
    
    // ==================== MODULE 1: DFA ====================
    
    PRINT "╔═══════════════════════════════════════════════════╗"
    PRINT "║  MODULE 1: Filename Pattern Detection (DFA)      ║"
    PRINT "║  Regular Languages - Level 3 Chomsky Hierarchy   ║"
    PRINT "╚═══════════════════════════════════════════════════╝"
    PRINT ""
    
    dfa_start_time = GET_CURRENT_TIME()
    
    TRY
        // 1. Load filename dataset
        filenames = Load_Filename_Dataset(filename_dataset)
        PRINT "[SUCCESS] Loaded", LENGTH(filenames), "entries"
        PRINT ""
        
        // 2. Define regex patterns
        patterns = [
            ".*\\.(pdf|doc|txt)\\.(exe|scr|bat)",
            ".*[\\u202E\\u202D].*\\.(exe|bat)",
            ".*\\s{2,}\\.(exe|scr)",
            ".*(update|setup)\\.(iso|msi)",
            ".*[\\uFF21-\\uFF5A]+$"
        ]
        pattern_names = [
            "double_extension",
            "unicode_rtlo",
            "whitespace_padding",
            "mimic_legitimate",
            "unicode_homoglyph"
        ]
        
        PRINT "[INFO] Defined", LENGTH(patterns), "detection patterns"
        FOR i = 1 TO LENGTH(patterns) DO
            PRINT "  Pattern", i, ":", pattern_names[i-1]
        END FOR
        PRINT ""
        
        // 3. Build NFAs (Thompson's Construction)
        PRINT "[INFO] Building NFAs (Thompson's Construction)..."
        nfas = EMPTY LIST
        total_nfa_states = 0
        
        FOR EACH pattern IN patterns DO
            nfa = Regex_To_NFA(pattern)
            nfas.add(nfa)
            total_nfa_states += nfa.get_state_count()
        END FOR
        
        PRINT "[SUCCESS] Built", LENGTH(nfas), "NFAs"
        PRINT "  Total NFA states:", total_nfa_states
        PRINT ""
        
        // 4. Convert to DFAs (Subset Construction)
        PRINT "[INFO] Converting to DFAs (Subset Construction)..."
        dfas = EMPTY LIST
        total_dfa_states_original = 0
        
        FOR EACH nfa IN nfas DO
            dfa = NFA_To_DFA(nfa)
            dfas.add(dfa)
            total_dfa_states_original += dfa.get_state_count()
        END FOR
        
        PRINT "[SUCCESS] Built", LENGTH(dfas), "DFAs"
        PRINT "  Total DFA states:", total_dfa_states_original
        PRINT ""
        
        // 5. Minimize DFAs (Hopcroft's Algorithm)
        PRINT "[INFO] Minimizing DFAs (Hopcroft's Algorithm)..."
        minimized_dfas = EMPTY LIST
        total_dfa_states_minimized = 0
        
        FOR EACH dfa IN dfas DO
            minimized = Minimize_DFA(dfa)
            minimized_dfas.add(minimized)
            total_dfa_states_minimized += minimized.get_state_count()
        END FOR
        
        reduction_min = total_dfa_states_original - total_dfa_states_minimized
        reduction_min_pct = (reduction_min / total_dfa_states_original) * 100.0
        
        PRINT "[SUCCESS] Minimized", LENGTH(minimized_dfas), "DFAs"
        PRINT "  States after minimization:", total_dfa_states_minimized
        PRINT "  Reduction:", reduction_min, "(", reduction_min_pct, "%)"
        PRINT ""
        
        // 6. Apply IGA (Improved Grouping Algorithm)
        PRINT "[INFO] Applying IGA (Improved Grouping Algorithm)..."
        PRINT "  Computing expansion coefficients..."
        grouped_dfas = Apply_IGA(minimized_dfas)
        
        total_dfa_states_iga = 0
        FOR EACH dfa IN grouped_dfas DO
            total_dfa_states_iga += dfa.get_state_count()
        END FOR
        
        reduction_iga = total_dfa_states_minimized - total_dfa_states_iga
        reduction_iga_pct = (reduction_iga / total_dfa_states_minimized) * 100.0
        total_reduction = total_dfa_states_original - total_dfa_states_iga
        total_reduction_pct = (total_reduction / total_dfa_states_original) * 100.0
        
        PRINT "[SUCCESS] IGA complete"
        PRINT "  Groups created:", LENGTH(grouped_dfas)
        PRINT "  States after IGA:", total_dfa_states_iga
        PRINT "  IGA reduction:", reduction_iga, "(", reduction_iga_pct, "%)"
        PRINT "  Total reduction:", total_reduction, "(", total_reduction_pct, "%)"
        PRINT ""
        
        // 7. Test all filenames
        PRINT "[INFO] Testing", LENGTH(filenames), "filenames..."
        true_positives = 0
        false_positives = 0
        false_negatives = 0
        
        test_start = GET_CURRENT_TIME()
        
        FOR EACH entry IN filenames DO
            detected = FALSE
            matched_pattern = ""
            
            FOR i = 0 TO LENGTH(grouped_dfas) - 1 DO
                IF grouped_dfas[i].accepts(entry.filename) THEN
                    detected = TRUE
                    matched_pattern = pattern_names[i]
                    BREAK
                END IF
            END FOR
            
            IF detected AND entry.is_malicious THEN
                true_positives += 1
            ELSE IF detected AND NOT entry.is_malicious THEN
                false_positives += 1
            ELSE IF NOT detected AND entry.is_malicious THEN
                false_negatives += 1
            END IF
        END FOR
        
        test_end = GET_CURRENT_TIME()
        test_time = test_end - test_start
        avg_test_time = test_time / LENGTH(filenames)
        
        detection_accuracy = (true_positives / LENGTH(filenames)) * 100.0
        
        PRINT "[SUCCESS] Testing complete"
        PRINT ""
        
        // 8. Display DFA results
        PRINT "[RESULTS] DFA Detection Summary:"
        PRINT "  ✓ True Positives: ", true_positives
        PRINT "  ✗ False Positives:", false_positives
        PRINT "  ✗ False Negatives:", false_negatives
        PRINT "  Detection Rate:", detection_accuracy, "%"
        PRINT ""
        
        PRINT "[PERFORMANCE] DFA Module Metrics:"
        PRINT "  Patterns:", LENGTH(patterns)
        PRINT "  Files tested:", LENGTH(filenames)
        PRINT "  DFA states (original):", total_dfa_states_original
        PRINT "  DFA states (minimized):", total_dfa_states_minimized
        PRINT "  DFA states (after IGA):", total_dfa_states_iga
        PRINT "  State reduction:", total_reduction_pct, "%"
        PRINT "  Avg matching time:", avg_test_time, "ms/file"
        PRINT "  Total test time:", test_time, "ms"
        
    CATCH error
        PRINT "[ERROR] DFA Module failed:", error.message
    END TRY
    
    dfa_end_time = GET_CURRENT_TIME()
    dfa_total_time = dfa_end_time - dfa_start_time
    
    PRINT ""
    
    // ==================== MODULE 2: PDA ====================
    
    PRINT "╔═══════════════════════════════════════════════════╗"
    PRINT "║  MODULE 2: TCP Protocol Validation (PDA)         ║"
    PRINT "║  Context-Free Languages - Level 2 Chomsky        ║"
    PRINT "╚═══════════════════════════════════════════════════╝"
    PRINT ""
    
    pda_start_time = GET_CURRENT_TIME()
    
    TRY
        // 1. Load TCP trace dataset
        traces = Load_TCP_Dataset(tcp_dataset)
        
        valid_count = 0
        invalid_count = 0
        FOR EACH trace IN traces DO
            IF trace.valid THEN
                valid_count += 1
            ELSE
                invalid_count += 1
            END IF
        END FOR
        
        PRINT "[SUCCESS] Loaded", LENGTH(traces), "TCP traces"
        PRINT "  Valid sequences:", valid_count
        PRINT "  Invalid sequences:", invalid_count
        PRINT ""
        
        // 2. Build PDA
        PRINT "[INFO] Building PDA for TCP 3-way handshake..."
        
        pda = NEW PDA
        
        // Define states
        Q_START = 0
        Q_SYN_RECV = 1
        Q_SYNACK_RECV = 2
        Q_ACCEPT = 3
        Q_ERROR = -1
        
        pda.states = [
            CREATE_STATE(Q_START, FALSE, "q_start"),
            CREATE_STATE(Q_SYN_RECV, FALSE, "q_syn_recv"),
            CREATE_STATE(Q_SYNACK_RECV, FALSE, "q_synack_recv"),
            CREATE_STATE(Q_ACCEPT, TRUE, "q_accept")
        ]
        
        pda.start_state = Q_START
        pda.accepting_states = {Q_ACCEPT}
        pda.current_state = Q_START
        pda.pda_stack.push("BOTTOM")
        
        PRINT "[SUCCESS] PDA constructed"
        PRINT "  States: {q_start, q_syn_recv, q_synack_recv, q_accept}"
        PRINT "  Stack alphabet: {SYN, SYN-ACK, BOTTOM}"
        PRINT "  Transition rules:"
        PRINT "    δ(q_start, SYN, BOTTOM) → (q_syn_recv, BOTTOM·SYN)"
        PRINT "    δ(q_syn_recv, SYN-ACK, SYN) → (q_synack_recv, SYN·SYN-ACK)"
        PRINT "    δ(q_synack_recv, ACK, SYN-ACK) → (q_accept, BOTTOM)"
        PRINT ""
        
        // 3. Validate all traces
        PRINT "[INFO] Validating", LENGTH(traces), "TCP traces..."
        
        correctly_accepted = 0
        correctly_rejected = 0
        false_positives_pda = 0
        false_negatives_pda = 0
        
        total_stack_depth = 0
        max_stack_depth = 0
        
        validation_start = GET_CURRENT_TIME()
        
        FOR EACH trace IN traces DO
            pda.reset()
            valid_handshake = TRUE
            
            FOR EACH packet IN trace.sequence DO
                success = Process_Packet(pda, packet)
                IF NOT success THEN
                    valid_handshake = FALSE
                    BREAK
                END IF
            END FOR
            
            // Check final state
            IF valid_handshake THEN
                valid_handshake = pda.is_accepting()
            END IF
            
            // Track stack depth
            depth = pda.get_stack_depth()
            total_stack_depth += depth
            IF depth > max_stack_depth THEN
                max_stack_depth = depth
            END IF
            
            // Update metrics
            IF valid_handshake AND trace.valid THEN
                correctly_accepted += 1
            ELSE IF NOT valid_handshake AND NOT trace.valid THEN
                correctly_rejected += 1
            ELSE IF valid_handshake AND NOT trace.valid THEN
                false_positives_pda += 1
            ELSE IF NOT valid_handshake AND trace.valid THEN
                false_negatives_pda += 1
            END IF
        END FOR
        
        validation_end = GET_CURRENT_TIME()
        validation_time = validation_end - validation_start
        avg_validation_time = validation_time / LENGTH(traces)
        
        avg_stack_depth = total_stack_depth / LENGTH(traces)
        validation_accuracy = ((correctly_accepted + correctly_rejected) / LENGTH(traces)) * 100.0
        
        PRINT "[SUCCESS] Validation complete"
        PRINT ""
        
        // 4. Show sample stack operations
        PRINT "[SAMPLE STACK OPERATIONS]"
        PRINT ""
        
        sample_traces = [
            {
                "id": "Valid",
                "sequence": ["SYN", "SYN-ACK", "ACK"]
            },
            {
                "id": "Missing SYN-ACK",
                "sequence": ["SYN", "ACK"]
            },
            {
                "id": "Wrong Order",
                "sequence": ["ACK", "SYN", "SYN-ACK"]
            }
        ]
        
        FOR EACH sample IN sample_traces DO
            PRINT "Trace:", sample.id
            PRINT "Sequence: [", JOIN(sample.sequence, ", "), "]"
            
            pda.reset()
            step = 1
            
            FOR EACH packet IN sample.sequence DO
                state_before = pda.current_state
                depth_before = pda.get_stack_depth()
                
                success = Process_Packet(pda, packet)
                
                state_after = pda.current_state
                depth_after = pda.get_stack_depth()
                
                PRINT "  Step", step, ":", packet,
                      "| State:", Get_State_Name(state_before), "→", Get_State_Name(state_after),
                      "| Depth:", depth_before, "→", depth_after
                
                IF NOT success THEN
                    PRINT "    [ERROR]"
                END IF
                
                step += 1
            END FOR
            
            IF pda.is_accepting() THEN
                PRINT "  Result: ✓ VALID"
            ELSE
                PRINT "  Result: ✗ INVALID"
            END IF
            
            PRINT ""
        END FOR
        
        // 5. Display PDA results
        PRINT "[RESULTS] PDA Validation Summary:"
        PRINT "  Total traces:", LENGTH(traces)
        PRINT "  ✓ Valid accepted:", correctly_accepted, "/", valid_count
        PRINT "  ✓ Invalid rejected:", correctly_rejected, "/", invalid_count
        PRINT "  ✗ False positives:", false_positives_pda
        PRINT "  ✗ False negatives:", false_negatives_pda
        PRINT "  Validation accuracy:", validation_accuracy, "%"
        PRINT ""
        
        PRINT "[PERFORMANCE] PDA Module Metrics:"
        PRINT "  Traces validated:", LENGTH(traces)
        PRINT "  Average stack depth:", avg_stack_depth
        PRINT "  Maximum stack depth:", max_stack_depth
        PRINT "  Avg validation time:", avg_validation_time, "ms/trace"
        PRINT "  Total validation time:", validation_time, "ms"
        
    CATCH error
        PRINT "[ERROR] PDA Module failed:", error.message
    END TRY
    
    pda_end_time = GET_CURRENT_TIME()
    pda_total_time = pda_end_time - pda_start_time
    
    PRINT ""
    
    // ==================== COMPARATIVE ANALYSIS ====================
    
    PRINT "╔═══════════════════════════════════════════════════╗"
    PRINT "║  CHOMSKY HIERARCHY DEMONSTRATION                  ║"
    PRINT "╚═══════════════════════════════════════════════════╝"
    PRINT ""
    
    PRINT "[THEORETICAL COMPARISON]"
    PRINT ""
    PRINT "┌─────────────────────┬──────────────────┬──────────────────┐"
    PRINT "│ Aspect              │ DFA (Regular)    │ PDA (Context-Free)│"
    PRINT "├─────────────────────┼──────────────────┼──────────────────┤"
    PRINT "│ Chomsky Level       │ Type 3           │ Type 2           │"
    PRINT "│ Memory              │ None (stateless) │ Stack            │"
    PRINT "│ Can match patterns  │ ✓ Yes            │ ✓ Yes            │"
    PRINT "│ Can count/pair      │ ✗ No             │ ✓ Yes            │"
    PRINT "│ Nested structures   │ ✗ No             │ ✓ Yes            │"
    PRINT "│ Example task        │ *.exe detection  │ SYN-ACK pairing  │"
    PRINT "│ Our application     │ Filename detect  │ TCP validation   │"
    PRINT "└─────────────────────┴──────────────────┴──────────────────┘"
    PRINT ""
    
    PRINT "[KEY INSIGHTS]"
    PRINT ""
    PRINT "1. DFA Limitation:"
    PRINT "   - Cannot validate TCP handshakes because it requires"
    PRINT "     matching SYN with SYN-ACK (pairing/counting)"
    PRINT "   - No memory to track which packets have been seen"
    PRINT "   - Example: Cannot recognize language {a^n b^n | n ≥ 0}"
    PRINT ""
    PRINT "2. PDA Advantage:"
    PRINT "   - Stack provides memory to match pairs"
    PRINT "   - Can push SYN, verify SYN-ACK matches, then pop on ACK"
    PRINT "   - Essential for protocol validation with nesting"
    PRINT ""
    PRINT "3. Practical Application:"
    PRINT "   - Simple pattern matching → Use DFA (more efficient)"
    PRINT "   - Protocol validation → Use PDA (necessary)"
    PRINT "   - Complex nested protocols → May need Turing Machine"
    PRINT ""
    PRINT "4. Performance Comparison:"
    PRINT "   - DFA: Faster per-item (", avg_test_time, "ms/file)"
    PRINT "   - PDA: Slightly slower (", avg_validation_time, "ms/trace)"
    PRINT "   - Trade-off: Speed vs. Expressiveness"
    PRINT ""
    
    // ==================== EXECUTION SUMMARY ====================
    
    total_end_time = GET_CURRENT_TIME()
    total_execution_time = total_end_time - total_start_time
    
    PRINT "╔═══════════════════════════════════════════════════╗"
    PRINT "║  EXECUTION SUMMARY                                ║"
    PRINT "╚═══════════════════════════════════════════════════╝"
    PRINT ""
    
    PRINT "[OVERALL STATISTICS]"
    PRINT ""
    PRINT "DFA Module:"
    PRINT "  - Patterns defined:", LENGTH(patterns)
    PRINT "  - Filenames tested:", LENGTH(filenames)
    PRINT "  - Detection accuracy:", detection_accuracy, "%"
    PRINT "  - State reduction (IGA):", total_reduction_pct, "%"
    PRINT "  - Execution time:", dfa_total_time, "ms"
    PRINT ""
    PRINT "PDA Module:"
    PRINT "  - Traces validated:", LENGTH(traces)
    PRINT "  - Validation accuracy:", validation_accuracy, "%"
    PRINT "  - Max stack depth:", max_stack_depth
    PRINT "  - Execution time:", pda_total_time, "ms"
    PRINT ""
    PRINT "Total execution time:", total_execution_time, "ms"
    PRINT ""
    PRINT "[EXECUTION COMPLETE]"
    PRINT "Results would be saved to: output/results.txt"
    PRINT "Metrics would be saved to: output/performance_metrics.txt"
    PRINT ""
    PRINT "======================================================="
    
END ALGORITHM


// ==================== HELPER FUNCTION ====================

FUNCTION Process_Packet
INPUT: 
    pda: PDA
    packet: STRING
OUTPUT: BOOLEAN

BEGIN
    stack_top = pda.peek()
    current = pda.current_state
    
    IF current = 0 AND packet = "SYN" THEN
        pda.push("SYN")
        pda.current_state = 1
        RETURN TRUE
        
    ELSE IF current = 1 AND packet = "SYN-ACK" AND stack_top = "SYN" THEN
        pda.push("SYN-ACK")
        pda.current_state = 2
        RETURN TRUE
        
    ELSE IF current = 2 AND packet = "ACK" AND stack_top = "SYN-ACK" THEN
        pda.pop()
        pda.pop()
        pda.current_state = 3
        RETURN TRUE
        
    ELSE IF current = 3 AND (packet = "DATA" OR packet = "FIN" OR packet = "ACK") THEN
        RETURN TRUE
        
    ELSE
        pda.current_state = -1
        RETURN FALSE
    END IF
END FUNCTION


FUNCTION Get_State_Name
INPUT: state_id: INTEGER
OUTPUT: STRING

BEGIN
    CASE state_id OF
        0: RETURN "q_start"
        1: RETURN "q_syn_recv"
        2: RETURN "q_synack_recv"
        3: RETURN "q_accept"
        -1: RETURN "q_error"
        DEFAULT: RETURN "unknown"
    END CASE
END FUNCTION
```

---

## 📊 COMPLEXITY ANALYSIS

```pseudocode
// ==================== TIME & SPACE COMPLEXITY ====================

ALGORITHM COMPLEXITIES

Thompson's Construction (Regex → NFA):
    Time: O(m) where m = length of regex
    Space: O(m) for NFA states
    Reason: Creates constant states per operator

Subset Construction (NFA → DFA):
    Time: O(2^n × |Σ|) where n = NFA states, |Σ| = alphabet size
    Space: O(2^n) for DFA states (worst case)
    Reason: DFA states are subsets of NFA states (powerset)

Hopcroft's DFA Minimization:
    Time: O(n log n) where n = DFA states
    Space: O(n)
    Reason: Partition refinement with efficient data structures

IGA (Improved Grouping Algorithm):
    Time: O(k^2 × s) where k = # DFAs, s = avg states per DFA
    Space: O(k × s)
    Reason: Pairwise EC computation and iterative merging

DFA Pattern Matching:
    Time: O(|w|) where |w| = input string length
    Space: O(1)
    Reason: Follow transitions character by character

PDA TCP Validation:
    Time: O(|w| × d) where |w| = sequence length, d = max stack depth
    Space: O(d)
    Reason: Process each packet, stack operations

Complete Simulator:
    Time: O(2^n) dominated by subset construction (worst case)
    Space: O(2^n) for DFA storage (worst case)
    
    Practical Performance:
    - DFA module: ~10-50ms for 341 files
    - PDA module: ~1-5ms for 75 traces
    - Total: < 100ms on modern hardware

END COMPLEXITIES
```

---

## 🎓 THEORETICAL FOUNDATIONS

```pseudocode
// ==================== CHOMSKY HIERARCHY PROOF ====================

THEOREM: TCP Handshake Language is Not Regular

PROOF BY PUMPING LEMMA:

Let L = {valid TCP handshake sequences}
    = {SYN SYN-ACK ACK} and variants

Assume L is regular. Then by Pumping Lemma:
    ∃ pumping length p such that
    ∀ string w ∈ L where |w| ≥ p
    ∃ decomposition w = xyz where:
        1. |xy| ≤ p
        2. |y| > 0  
        3. ∀ i ≥ 0: xy^i z ∈ L

Consider w = SYN^p SYN-ACK^p ACK^p (balanced)

By Pumping Lemma, w = xyz where y consists only of SYN
(since |xy| ≤ p)

But then xy^2z = SYN^(p+|y|) SYN-ACK^p ACK^p
This is NOT a valid handshake (unbalanced)

CONTRADICTION!

Therefore, TCP handshake language is NOT regular.
It requires Context-Free grammar with stack (PDA).

QED.


COROLLARY: DFA Cannot Validate TCP Handshakes

Since TCP handshake language is not regular,
and DFA recognizes exactly regular languages,
no DFA can validate TCP handshakes.

PDA with stack is necessary.

END PROOF
```

---

## 📝 SUMMARY

This complete pseudocode provides:

✅ **All major algorithms**:
- Thompson's Construction
- Subset Construction  
- Hopcroft's Minimization
- IGA (Improved Grouping Algorithm)
- DFA Pattern Matching
- PDA TCP Validation

✅ **Complete workflows**:
- Main program flow
- DFA Module (341 filenames)
- PDA Module (75 TCP traces)
- Comparative analysis

✅ **Data structures**:
- NFA, DFA, PDA definitions
- Dataset entry structures
- Performance metrics

✅ **Helper algorithms**:
- JSON parsing
- State management
- Stack operations
- Error handling

✅ **Complexity analysis**
✅ **Theoretical proofs**

**This pseudocode can be directly translated to C++ implementation!**


    PRINT "