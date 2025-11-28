import json
import os

# Expanded TCP Handshake Dataset Generator
# Creates 75 traces with realistic variations
# Save as: generate_tcp_expanded.py

tcp_traces = []
trace_counter = 1

# ==================== VALID SEQUENCES (15 traces) ====================

# Basic valid handshakes
for i in range(3):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "SYN-ACK", "ACK"],
        "valid": True,
        "description": f"Valid 3-way handshake (variant {i+1})",
        "category": "Normal"
    })
    trace_counter += 1

# Valid with data transfer
for i in range(3):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "SYN-ACK", "ACK", "DATA", "ACK"],
        "valid": True,
        "description": f"Valid handshake with data transfer (variant {i+1})",
        "category": "Normal"
    })
    trace_counter += 1

# Multiple consecutive handshakes
tcp_traces.append({
    "trace_id": f"T{trace_counter:03d}",
    "sequence": ["SYN", "SYN-ACK", "ACK", "SYN", "SYN-ACK", "ACK"],
    "valid": True,
    "description": "Two consecutive valid handshakes",
    "category": "Normal"
})
trace_counter += 1

tcp_traces.append({
    "trace_id": f"T{trace_counter:03d}",
    "sequence": ["SYN", "SYN-ACK", "ACK", "SYN", "SYN-ACK", "ACK", "SYN", "SYN-ACK", "ACK"],
    "valid": True,
    "description": "Three consecutive valid handshakes",
    "category": "Normal"
})
trace_counter += 1

# Valid connection lifecycle
for i in range(3):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "SYN-ACK", "ACK", "DATA", "ACK", "FIN", "ACK"],
        "valid": True,
        "description": f"Complete connection lifecycle (variant {i+1})",
        "category": "Normal"
    })
    trace_counter += 1

# Valid with connection close variations
tcp_traces.append({
    "trace_id": f"T{trace_counter:03d}",
    "sequence": ["SYN", "SYN-ACK", "ACK", "FIN", "ACK"],
    "valid": True,
    "description": "Valid handshake with immediate close",
    "category": "Normal"
})
trace_counter += 1

tcp_traces.append({
    "trace_id": f"T{trace_counter:03d}",
    "sequence": ["SYN", "SYN-ACK", "ACK", "DATA", "DATA", "ACK", "FIN", "ACK"],
    "valid": True,
    "description": "Valid handshake with multiple data packets",
    "category": "Normal"
})
trace_counter += 1

tcp_traces.append({
    "trace_id": f"T{trace_counter:03d}",
    "sequence": ["SYN", "SYN-ACK", "ACK", "DATA", "ACK", "DATA", "ACK"],
    "valid": True,
    "description": "Valid handshake with bidirectional data",
    "category": "Normal"
})
trace_counter += 1

# ==================== INCOMPLETE HANDSHAKES (10 traces) ====================

for i in range(5):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN"],
        "valid": False,
        "description": f"Incomplete - only SYN sent (variant {i+1})",
        "category": "Incomplete Handshake"
    })
    trace_counter += 1

for i in range(5):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "SYN-ACK"],
        "valid": False,
        "description": f"Incomplete - missing final ACK (variant {i+1})",
        "category": "Incomplete Handshake"
    })
    trace_counter += 1

# ==================== MALFORMED HANDSHAKES (15 traces) ====================

for i in range(5):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "ACK"],
        "valid": False,
        "description": f"Missing SYN-ACK in middle (variant {i+1})",
        "category": "Malformed Handshake"
    })
    trace_counter += 1

for i in range(5):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN-ACK", "ACK"],
        "valid": False,
        "description": f"Missing initial SYN (variant {i+1})",
        "category": "Malformed Handshake"
    })
    trace_counter += 1

for i in range(5):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["ACK"],
        "valid": False,
        "description": f"ACK without handshake (variant {i+1})",
        "category": "Malformed Handshake"
    })
    trace_counter += 1

# ==================== WRONG ORDER (10 traces) ====================

for i in range(3):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["ACK", "SYN", "SYN-ACK"],
        "valid": False,
        "description": f"Completely reversed order (variant {i+1})",
        "category": "Wrong Order"
    })
    trace_counter += 1

for i in range(3):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "ACK", "SYN-ACK"],
        "valid": False,
        "description": f"ACK before SYN-ACK (variant {i+1})",
        "category": "Wrong Order"
    })
    trace_counter += 1

for i in range(4):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN-ACK", "SYN", "ACK"],
        "valid": False,
        "description": f"SYN-ACK before SYN (variant {i+1})",
        "category": "Wrong Order"
    })
    trace_counter += 1

# ==================== DUPLICATE PACKETS (10 traces) ====================

for i in range(3):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "SYN", "ACK"],
        "valid": False,
        "description": f"Duplicate SYN (variant {i+1})",
        "category": "Duplicate Packets"
    })
    trace_counter += 1

for i in range(3):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "SYN-ACK", "SYN-ACK", "ACK"],
        "valid": False,
        "description": f"Duplicate SYN-ACK (variant {i+1})",
        "category": "Duplicate Packets"
    })
    trace_counter += 1

for i in range(4):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "SYN-ACK", "ACK", "ACK"],
        "valid": False,
        "description": f"Duplicate ACK after handshake (variant {i+1})",
        "category": "Duplicate Packets"
    })
    trace_counter += 1

# ==================== ATTACK PATTERNS (10 traces) ====================

# SYN Flood variations
for i in range(3):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "SYN", "SYN"],
        "valid": False,
        "description": f"SYN flood pattern - 3 SYNs (attack {i+1})",
        "category": "Attack Pattern"
    })
    trace_counter += 1

for i in range(2):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "SYN", "SYN", "SYN"],
        "valid": False,
        "description": f"SYN flood pattern - 4 SYNs (attack {i+1})",
        "category": "Attack Pattern"
    })
    trace_counter += 1

tcp_traces.append({
    "trace_id": f"T{trace_counter:03d}",
    "sequence": ["SYN", "SYN", "SYN", "SYN", "SYN"],
    "valid": False,
    "description": "Heavy SYN flood - 5 SYNs",
    "category": "Attack Pattern"
})
trace_counter += 1

# Reset attacks
for i in range(2):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["SYN", "RST"],
        "valid": False,
        "description": f"Handshake interrupted by reset (variant {i+1})",
        "category": "Attack Pattern"
    })
    trace_counter += 1

for i in range(2):
    tcp_traces.append({
        "trace_id": f"T{trace_counter:03d}",
        "sequence": ["RST"],
        "valid": False,
        "description": f"Reset without handshake (variant {i+1})",
        "category": "Attack Pattern"
    })
    trace_counter += 1

# ==================== OTHER ANOMALIES (5 traces) ====================

tcp_traces.append({
    "trace_id": f"T{trace_counter:03d}",
    "sequence": [],
    "valid": False,
    "description": "Empty sequence",
    "category": "Empty"
})
trace_counter += 1

tcp_traces.append({
    "trace_id": f"T{trace_counter:03d}",
    "sequence": ["SYN", "FIN"],
    "valid": False,
    "description": "FIN during handshake",
    "category": "Unexpected Packet"
})
trace_counter += 1

tcp_traces.append({
    "trace_id": f"T{trace_counter:03d}",
    "sequence": ["DATA"],
    "valid": False,
    "description": "Data without handshake",
    "category": "Unexpected Packet"
})
trace_counter += 1

tcp_traces.append({
    "trace_id": f"T{trace_counter:03d}",
    "sequence": ["SYN", "SYN-ACK", "ACK", "SYN"],
    "valid": False,
    "description": "New SYN after complete handshake",
    "category": "Unexpected Packet"
})
trace_counter += 1

tcp_traces.append({
    "trace_id": f"T{trace_counter:03d}",
    "sequence": ["SYN", "SYN", "SYN-ACK", "ACK"],
    "valid": False,
    "description": "SYN retransmission before response",
    "category": "Retransmission"
})
trace_counter += 1

# Write to JSONL file
# Output to archive/ directory (works from project root or .scripts/ directory)
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)  # Go up one level from .scripts/
archive_dir = os.path.join(project_root, "archive")
output_file = os.path.join(archive_dir, "tcp_handshake_traces_expanded.jsonl")

# Ensure archive directory exists
os.makedirs(archive_dir, exist_ok=True)
with open(output_file, 'w', encoding='utf-8') as f:
    for trace in tcp_traces:
        f.write(json.dumps(trace) + '\n')

print(f"[SUCCESS] Created {output_file} with {len(tcp_traces)} TCP handshake traces")
print(f"   - Valid sequences: {sum(1 for t in tcp_traces if t['valid'])}")
print(f"   - Invalid sequences: {sum(1 for t in tcp_traces if not t['valid'])}")
print(f"\n[BREAKDOWN BY CATEGORY]")
categories = {}
for trace in tcp_traces:
    cat = trace['category']
    categories[cat] = categories.get(cat, 0) + 1
for cat, count in sorted(categories.items()):
    print(f"   - {cat}: {count}")
print(f"\n[INFO] File saved to: archive/tcp_handshake_traces_expanded.jsonl")