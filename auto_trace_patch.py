# auto_trace_patch_named.py
import os

target_file = "src/network.cpp"
mutex_name = "peersMutex"

# Map line index → context name
context_hints = {
    "broadcastBlock": "broadcastBlock",
    "connectToPeer": "connectToPeer",
    "sendData": "sendData",
    "handlePeer": "handlePeer",
    "periodicSync": "periodicSync",
    "cleanupPeers": "cleanupPeers",
    "broadcastMessage": "broadcastMessage",
    "connectToNode": "connectToNode",
    "broadcastPeerList": "broadcastPeerList"
}

with open(target_file, 'r') as f:
    lines = f.readlines()

# Remove old ScopedLockTracer lines
lines = [line for line in lines if "ScopedLockTracer tracer(" not in line]

# Insert new ones with context labels
output = []
current_context = "unknown"

for i, line in enumerate(lines):
    # Detect function name for context
    if "Network::" in line and "(" in line and ")" in line and "{" in line:
        for key in context_hints:
            if key in line:
                current_context = context_hints[key]
                break

    if mutex_name in line and ("lock_guard" in line or "unique_lock" in line):
        indent = " " * (len(line) - len(line.lstrip()))
        output.append(f'{indent}ScopedLockTracer tracer("{current_context}");\n')

    output.append(line)

with open(target_file, 'w') as f:
    f.writelines(output)

print("✅ Named ScopedLockTracer inserted before each peersMutex lock.")
