import threading
import time
import json
import socket

def start_node(port):
    """Start a simulated AlynCoin node"""
    print(f"Starting node on port {port}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', port))
    server.listen(5)
    
    while True:
        conn, addr = server.accept()
        data = conn.recv(4096).decode('utf-8')
        if data:
            print(f"[Node {port}] Received: {data}")
            conn.sendall(b"Message received")
        conn.close()

def send_message(port, message):
    """Send a JSON message to a node"""
    time.sleep(2)  # Wait for nodes to start
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', port))
    client.sendall(json.dumps(message).encode('utf-8'))
    response = client.recv(4096).decode('utf-8')
    print(f"[Sent to {port}] Response: {response}")
    client.close()

# Start nodes in separate threads
ports = [5001, 5002, 5003]
nodes = []
for port in ports:
    thread = threading.Thread(target=start_node, args=(port,), daemon=True)
    nodes.append(thread)
    thread.start()

# Send transactions and blocks
time.sleep(3)
transaction_message = {
    "type": "transaction",
    "data": {
        "sender": "Alice",
        "recipient": "Bob",
        "amount": 10,
        "signature": "test_signature",
        "hash": "test_hash"
    }
}
block_message = {
    "type": "block",
    "data": {
        "index": 1,
        "previousHash": "0000",
        "timestamp": time.time(),
        "transactions": [transaction_message["data"]],
        "nonce": 100,
        "hash": "0000abcd"
    }
}

# Simulate network communication
for port in ports:
    send_message(port, transaction_message)
    send_message(port, block_message)

# Keep the script running to allow interactions
time.sleep(5)
