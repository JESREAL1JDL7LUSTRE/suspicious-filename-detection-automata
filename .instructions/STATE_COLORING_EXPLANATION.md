# Detailed Explanation: Progressive State Coloring System

## Overview

The **Progressive State Coloring** system provides real-time visual feedback by dynamically changing the color of graph nodes (states) as files are scanned through the DFA. The color reflects the **risk level** of the file that visited that state, creating an intuitive visual representation of the scanning process.

---

## Complete Flow: From File Upload to Colored Graph

### Step 1: File Upload & Scan Initiation

```
User uploads: "malware.exe"
↓
Frontend calls: scanFiles([File("malware.exe")])
↓
POST /api/scan with file paths
↓
Node.js server spawns: simulator.exe malware.exe
```

### Step 2: C++ Backend Processing (Verbose Mode)

The C++ backend processes the filename character-by-character and outputs state transitions:

```cpp
// In DFA::accepts(input, verbose=true)
Input: "malware.exe"
Processing character 'm':
  std::cout << "  State: q0 → q0 (symbol: 'm')" << std::endl;
  
Processing character 'e':
  std::cout << "  State: q0 → q1 (symbol: 'e')" << std::endl;
  
Processing character 'x':
  std::cout << "  State: q1 → q2 (symbol: 'x')" << std::endl;
  
Processing character 'e':
  std::cout << "  State: q2 → q3 (symbol: 'e')" << std::endl;
  std::cout << "  Final state: q3" << std::endl;
  
Result:
  std::cout << "  ✓ Result: SUSPICIOUS (executable)" << std::endl;
```

**Output Stream**:
```
[1/1] Analyzing: malware.exe
  State: q0 → q0 (symbol: 'm')
  State: q0 → q0 (symbol: 'a')
  State: q0 → q0 (symbol: 'l')
  State: q0 → q0 (symbol: 'w')
  State: q0 → q0 (symbol: 'a')
  State: q0 → q0 (symbol: 'r')
  State: q0 → q1 (symbol: 'e')
  State: q1 → q0 (symbol: '.')
  State: q0 → q1 (symbol: 'e')
  State: q1 → q2 (symbol: 'x')
  State: q2 → q3 (symbol: 'e')
  Final state: q3
  ✓ Result: SUSPICIOUS (executable)
```

### Step 3: Server-Sent Events (SSE) Streaming

The Node.js server captures C++ stdout and streams it to the frontend:

```javascript
// display/server.js
simulator.stdout.on('data', (data) => {
  const output = data.toString('utf8')
  res.write(`data: ${JSON.stringify({ type: 'stdout', message: output })}\n\n`)
})
```

**SSE Format**:
```
data: {"type":"stdout","message":"  State: q0 → q1 (symbol: 'e')\n"}\n\n
data: {"type":"stdout","message":"  Final state: q3\n"}\n\n
data: {"type":"stdout","message":"  ✓ Result: SUSPICIOUS (executable)\n"}\n\n
```

### Step 4: Frontend Parsing (useFileScan Hook)

The `useFileScan` hook receives SSE messages and parses them:

```typescript
// display/src/hooks/useFileScan.ts

// 1. Receive SSE message
if (data.type === 'stdout') {
  const message = data.message || ''
  const lines = message.split(/\r?\n/)
  
  // 2. Parse each line
  for (const line of lines) {
    // A. Parse file analysis start
    const analyzingMatch = line.match(/\[(\d+)\/(\d+)\]\s*Analyzing:\s*([^\n\r]+)/i)
    if (analyzingMatch) {
      const fileIndex = parseInt(analyzingMatch[1]) - 1
      currentFileIndexRef.current = fileIndex
      // Create placeholder ScanResult
      const newResult: ScanResult = {
        file: "malware.exe",
        status: 'safe',      // Placeholder (will be updated)
        severity: 'safe',    // Placeholder
        pattern: null,       // Placeholder
        color: 'blue'        // Placeholder
      }
      results.push(newResult)
      setScanResults([...results])
    }
    
    // B. Parse state transitions
    const stateTransitionMatch = line.match(/State:\s*q(\d+)\s*→\s*q(\d+)/i)
    if (stateTransitionMatch) {
      const stateTo = `q${stateTransitionMatch[2]}`  // e.g., "q1"
      const fileIndex = currentFileIndexRef.current
      const currentFileResult = results[fileIndex] || results[results.length - 1]
      
      // Create VisitedState
      const visitedState: VisitedState = {
        stateId: stateTo,                    // "q1"
        fileIndex: fileIndex,                 // 0
        status: currentFileResult?.status || 'safe',    // 'safe' (placeholder)
        severity: currentFileResult?.severity || 'safe', // 'safe' (placeholder)
        timestamp: Date.now()                // 1234567890
      }
      
      // Add to visitedStates array
      setVisitedStates((prev) => {
        const existingIndex = prev.findIndex(
          v => v.stateId === stateTo && v.fileIndex === fileIndex
        )
        if (existingIndex >= 0) {
          // Update existing visit
          const updated = [...prev]
          updated[existingIndex] = visitedState
          return updated
        } else {
          // Add new visit
          return [...prev, visitedState]
        }
      })
    }
    
    // C. Parse result line
    const resultMatch = line.match(/✓\s*Result:\s*(SUSPICIOUS|SAFE)(?:\s*\(([^)]+)\))?/i)
    if (resultMatch) {
      const status = resultMatch[1].toLowerCase() === 'suspicious' ? 'suspicious' : 'safe'
      const pattern = resultMatch[2] || null  // "executable"
      
      // Determine severity based on pattern
      const severity = status === 'suspicious' 
        ? (pattern === 'executable' || pattern === 'screensaver' ? 'high' : 
           pattern === 'batch_file' || pattern === 'vbscript' ? 'medium' : 'low')
        : 'safe'
      
      // Update ScanResult
      const updatedResult: ScanResult = {
        ...results[fileIndex],
        status: 'suspicious',
        severity: 'high',
        pattern: 'executable',
        color: 'red'
      }
      results[fileIndex] = updatedResult
      setScanResults([...results])
      
      // CRITICAL: Update ALL visited states for this file with the correct status
      setVisitedStates((prev) => {
        return prev.map(vs => {
          if (vs.fileIndex === fileIndex) {
            return {
              ...vs,
              status: 'suspicious',    // Update from 'safe' to 'suspicious'
              severity: 'high',        // Update from 'safe' to 'high'
              timestamp: Date.now()    // Update timestamp
            }
          }
          return vs
        })
      })
    }
  }
}
```

**State After Parsing**:
```typescript
visitedStates = [
  { stateId: "q0", fileIndex: 0, status: "suspicious", severity: "high", timestamp: 1234567890 },
  { stateId: "q1", fileIndex: 0, status: "suspicious", severity: "high", timestamp: 1234567891 },
  { stateId: "q2", fileIndex: 0, status: "suspicious", severity: "high", timestamp: 1234567892 },
  { stateId: "q3", fileIndex: 0, status: "suspicious", severity: "high", timestamp: 1234567893 }
]
```

### Step 5: Graph Visualization (GraphVisualization Component)

The `GraphVisualization` component receives `visitedStates` and applies colors:

```typescript
// display/src/components/GraphVisualization.tsx

const coloredNodes = useMemo(() => {
  // 1. Create state visit map (most recent visit wins)
  const stateVisitMap = new Map<string, { status, severity, timestamp }>()
  
  for (const visitedState of visitedStates) {
    const existing = stateVisitMap.get(visitedState.stateId)
    // Keep most recent visit (higher timestamp = later)
    if (!existing || visitedState.timestamp > existing.timestamp) {
      stateVisitMap.set(visitedState.stateId, {
        status: visitedState.status,
        severity: visitedState.severity || 'safe',
        timestamp: visitedState.timestamp
      })
    }
  }
  
  // 2. Map graph nodes to visited states
  return graph.nodes.map((node: Node) => {
    const nodeId = node.id || ''  // e.g., "q0", "d0_s0", etc.
    let visitedStateInfo = null
    
    // Try exact match
    if (stateVisitMap.has(nodeId)) {
      visitedStateInfo = stateVisitMap.get(nodeId)!
    } else {
      // Try pattern match: extract "q0" from "d0_s0"
      const stateMatch = nodeId.match(/q?(\d+)/i)
      if (stateMatch) {
        const stateId = `q${stateMatch[1]}`  // "q0"
        if (stateVisitMap.has(stateId)) {
          visitedStateInfo = stateVisitMap.get(stateId)!
        }
      }
    }
    
    // 3. Apply color based on status and severity
    if (visitedStateInfo) {
      if (visitedStateInfo.status === 'suspicious') {
        // Determine color based on severity
        const color = visitedStateInfo.severity === 'high' ? '#ef4444' :    // Red
                     visitedStateInfo.severity === 'medium' ? '#eab308' :   // Yellow
                     '#f97316'  // Orange
        
        return {
          ...node,
          style: {
            ...node.style,
            backgroundColor: color,
            borderColor: color,
            borderWidth: 3,
            borderRadius: '50%',
            width: 80,
            height: 80,
            color: '#ffffff',
            transition: 'background-color 0.3s ease, border-color 0.3s ease',
            boxShadow: `0 0 8px rgba(${color}, 0.5)`  // Glow effect
          }
        }
      } else {
        // Safe files: Blue
        return {
          ...node,
          style: {
            ...node.style,
            backgroundColor: '#3b82f6',  // Blue
            borderColor: '#2563eb',
            borderWidth: 3,
            borderRadius: '50%',
            width: 80,
            height: 80,
            color: '#ffffff',
            transition: 'background-color 0.3s ease, border-color 0.3s ease',
            boxShadow: '0 0 8px rgba(59, 130, 246, 0.5)'  // Blue glow
          }
        }
      }
    }
    
    // 4. Default: Unvisited states (Gray)
    return {
      ...node,
      style: {
        ...node.style,
        backgroundColor: '#94a3b8',  // Gray
        borderColor: '#64748b',
        borderWidth: 2,
        borderRadius: '50%',
        width: 80,
        height: 80,
        color: '#ffffff',
        transition: 'background-color 0.3s ease, border-color 0.3s ease'
        // No glow effect for unvisited states
      }
    }
  })
}, [graph.nodes, visitedStates, isScanMode])
```

---

## Color Determination Logic

### Severity Mapping

The severity is determined by the **pattern** that matched:

```typescript
// Pattern → Severity Mapping
if (pattern === 'executable' || pattern === 'screensaver') {
  severity = 'high'      // → Red (#ef4444)
} else if (pattern === 'batch_file' || pattern === 'vbscript') {
  severity = 'medium'    // → Yellow (#eab308)
} else {
  severity = 'low'       // → Orange (#f97316)
}
```

**Pattern Examples**:
- `"executable"` (matches "exe") → **High** → **Red**
- `"screensaver"` (matches "scr") → **High** → **Red**
- `"batch_file"` (matches "bat") → **Medium** → **Yellow**
- `"vbscript"` (matches "vbs") → **Medium** → **Yellow**
- `"mimic_legitimate"` (matches "update") → **Low** → **Orange**

### Status → Color Mapping

```typescript
if (status === 'suspicious') {
  if (severity === 'high') {
    color = '#ef4444'    // Red
  } else if (severity === 'medium') {
    color = '#eab308'    // Yellow
  } else {
    color = '#f97316'    // Orange
  }
} else {
  color = '#3b82f6'      // Blue (safe)
}
```

---

## Visual Effects

### Visited States (Suspicious or Safe)

- **Background Color**: Matches status/severity (red, yellow, orange, or blue)
- **Border Color**: Same as background (3px width)
- **Text Color**: White (`#ffffff`)
- **Glow Effect**: `boxShadow: '0 0 8px rgba(color, 0.5)'` - Creates a subtle glow around the node
- **Transition**: Smooth 0.3s ease animation when color changes

### Unvisited States

- **Background Color**: Gray (`#94a3b8`)
- **Border Color**: Darker gray (`#64748b`, 2px width)
- **Text Color**: White (`#ffffff`)
- **No Glow**: No box-shadow effect
- **Transition**: Smooth 0.3s ease animation

---

## Progressive Coloring Timeline Example

### Scenario: Scanning "malware.exe"

**Time T+0ms** - Initial State:
```
Graph: All nodes are GRAY (unvisited)
┌─────┐    ┌─────┐    ┌─────┐    ┌─────┐
│ q0  │───▶│ q1  │───▶│ q2  │───▶│ q3  │
│ GRAY│    │ GRAY│    │ GRAY│    │ GRAY│
└─────┘    └─────┘    └─────┘    └─────┘
```

**Time T+50ms** - Processing 'e' (q0 → q1):
```
C++ Output: "State: q0 → q1 (symbol: 'e')"
Frontend: Creates VisitedState { stateId: "q1", status: "safe", severity: "safe" }
Graph: q1 turns BLUE (placeholder, result not known yet)
┌─────┐    ┌─────┐    ┌─────┐    ┌─────┐
│ q0  │───▶│ q1  │───▶│ q2  │───▶│ q3  │
│ GRAY│    │ BLUE│    │ GRAY│    │ GRAY│
└─────┘    └─────┘    └─────┘    └─────┘
```

**Time T+200ms** - Processing 'x' (q1 → q2):
```
C++ Output: "State: q1 → q2 (symbol: 'x')"
Frontend: Creates VisitedState { stateId: "q2", status: "safe", severity: "safe" }
Graph: q2 turns BLUE (placeholder)
┌─────┐    ┌─────┐    ┌─────┐    ┌─────┐
│ q0  │───▶│ q1  │───▶│ q2  │───▶│ q3  │
│ GRAY│    │ BLUE│    │ BLUE│    │ GRAY│
└─────┘    └─────┘    └─────┘    └─────┘
```

**Time T+250ms** - Processing 'e' (q2 → q3):
```
C++ Output: 
  "State: q2 → q3 (symbol: 'e')"
  "Final state: q3"
Frontend: Creates VisitedState { stateId: "q3", status: "safe", severity: "safe" }
Graph: q3 turns BLUE (placeholder)
┌─────┐    ┌─────┐    ┌─────┐    ┌─────┐
│ q0  │───▶│ q1  │───▶│ q2  │───▶│ q3  │
│ GRAY│    │ BLUE│    │ BLUE│    │ BLUE│
└─────┘    └─────┘    └─────┘    └─────┘
```

**Time T+300ms** - Result Received:
```
C++ Output: "✓ Result: SUSPICIOUS (executable)"
Frontend: 
  - Updates ScanResult: { status: "suspicious", severity: "high", pattern: "executable" }
  - Updates ALL visited states for this file:
    * q1: { status: "suspicious", severity: "high" }
    * q2: { status: "suspicious", severity: "high" }
    * q3: { status: "suspicious", severity: "high" }

Graph: ALL visited states turn RED (high severity)
┌─────┐    ┌─────┐    ┌─────┐    ┌─────┐
│ q0  │───▶│ q1  │───▶│ q2  │───▶│ q3  │
│ GRAY│    │ RED │    │ RED │    │ RED │
│ ⚪  │    │ 🔴  │    │ 🔴  │    │ 🔴  │
└─────┘    └─────┘    └─────┘    └─────┘
```

**Visual Changes**:
- **q1, q2, q3**: Blue → Red (with smooth 0.3s transition)
- **Glow Effect**: Red glow appears around nodes
- **Border**: Increases from 2px to 3px

---

## Multiple File Scanning

When scanning multiple files, the system tracks which file visited which state:

```typescript
visitedStates = [
  { stateId: "q0", fileIndex: 0, status: "suspicious", severity: "high", timestamp: 100 },
  { stateId: "q1", fileIndex: 0, status: "suspicious", severity: "high", timestamp: 101 },
  { stateId: "q0", fileIndex: 1, status: "safe", severity: "safe", timestamp: 200 },
  { stateId: "q1", fileIndex: 1, status: "safe", severity: "safe", timestamp: 201 }
]
```

**State Visit Map** (most recent visit wins):
```typescript
stateVisitMap = {
  "q0": { status: "safe", severity: "safe", timestamp: 200 },    // File 1 (most recent)
  "q1": { status: "safe", severity: "safe", timestamp: 201 }     // File 1 (most recent)
}
```

**Result**: q0 and q1 are colored **BLUE** (safe) because the most recent visit was from a safe file.

---

## Key Design Decisions

### 1. **Placeholder States (Blue)**
- Initially, states are colored **blue** (safe) as placeholders
- This provides immediate visual feedback that the state was visited
- When the result is known, all states update to the correct color

### 2. **Most Recent Visit Wins**
- If a state is visited by multiple files, the **most recent visit** determines the color
- This ensures the graph reflects the latest scanning activity

### 3. **Timestamp-Based Updates**
- Each `VisitedState` has a `timestamp` to track when it was visited
- When a result is received, all states for that file are updated with new timestamps
- This ensures the color update is reflected immediately

### 4. **Smooth Transitions**
- CSS `transition: 'background-color 0.3s ease'` provides smooth color changes
- Users can see states change color in real-time, creating an engaging visual experience

### 5. **Glow Effects**
- Visited states have a subtle glow effect (`boxShadow`)
- This makes them stand out from unvisited states
- The glow color matches the node color (red glow for red nodes, blue glow for blue nodes)

---

## Summary

The progressive state coloring system provides:
1. **Real-time feedback**: States change color as files are processed
2. **Risk visualization**: Color indicates the risk level (red = high, yellow = medium, orange = low, blue = safe)
3. **Smooth animations**: 0.3s transitions make color changes visually appealing
4. **Glow effects**: Visited states have a subtle glow to distinguish them from unvisited states
5. **Multi-file support**: Handles multiple files with most-recent-visit logic

This creates an intuitive, engaging visualization that helps users understand how the DFA processes files and identifies suspicious patterns.

