import sys
import re
import requests
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit, QHBoxLayout, QFrame
)
from PyQt5.QtCore import Qt, QTimer

def alyncoin_rpc(method, params=None):
    url = "http://127.0.0.1:1567/rpc"
    headers = {"Content-Type": "application/json"}
    body = {"method": method, "params": params or []}
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise Exception(data["error"])
        return data.get("result", None)
    except Exception as e:
        return {"error": str(e)}

def filter_miner_output(line: str) -> bool:
    # Always show errors/warnings
    if any(w in line for w in ["❌", "⛔", "[ERROR]", "⚠️"]):
        return True
    # Whitelist essential user lines only
    show_patterns = [
        r"^⛏️ Mining single block", r"^⛏️ Block reward", r"^⚙️ Difficulty set to",
        r"^⏳ \[mineBlock\]", r"^✅ \[mineBlock\] PoW Complete\.",
        r"^🔢 Final Nonce:", r"^🧬 Block Hash \(BLAKE3\):",
        r"^✅ Block mined and added successfully\.", r"^✅ Block mined by:",
        r"^🧱 Block Hash:"
    ]
    for pat in show_patterns:
        if re.search(pat, line):
            return True
    return False

class MinerTab(QWidget):
    def __init__(self, wallet_address_getter, parent=None):
        super().__init__(parent)
        self.parentWindow = parent
        self.wallet_address_getter = wallet_address_getter
        self.current_wallet = self.wallet_address_getter() or ""
        self.loop_active = False
        self.initUI()
        if hasattr(parent, "walletChanged"):
            parent.walletChanged.connect(self.onWalletChanged)
        self.updateMiningUIState()

    def initUI(self):
        layout = QVBoxLayout()
        self.status_label = QLabel("🟡 <b>AlynCoin Miner Status: Idle</b>")
        layout.addWidget(self.status_label)

        button_layout = QHBoxLayout()
        self.mine_once_button = QPushButton("Mine One Block")
        self.mine_loop_button = QPushButton("Start Mining Loop")
        self.stop_mining_button = QPushButton("Stop Mining")
        button_layout.addWidget(self.mine_once_button)
        button_layout.addWidget(self.mine_loop_button)
        button_layout.addWidget(self.stop_mining_button)
        layout.addLayout(button_layout)

        rollup_layout = QHBoxLayout()
        self.rollup_button = QPushButton("Generate Rollup")
        self.recursive_rollup_button = QPushButton("Generate Recursive Rollup")
        rollup_layout.addWidget(self.rollup_button)
        rollup_layout.addWidget(self.recursive_rollup_button)
        layout.addLayout(rollup_layout)

        self.mining_banner = QLabel("💎 <b><font color='#00FFFF'>Ready to mine AlynCoin!</font></b>")
        self.mining_banner.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.mining_banner)

        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setFrameShadow(QFrame.Sunken)
        layout.addWidget(divider)

        self.miner_output = QTextEdit()
        self.miner_output.setReadOnly(True)
        layout.addWidget(self.miner_output)
        self.setLayout(layout)

        self.mine_once_button.clicked.connect(self.mine_once)
        self.mine_loop_button.clicked.connect(self.start_mining_loop)
        self.stop_mining_button.clicked.connect(self.stop_mining)
        self.rollup_button.clicked.connect(self.trigger_rollup)
        self.recursive_rollup_button.clicked.connect(self.trigger_recursive_rollup)

    def onWalletChanged(self, address):
        self.current_wallet = address
        self.updateMiningUIState()

    def updateMiningUIState(self):
        wallet_loaded = bool(self.current_wallet)
        mining = self.loop_active
        for btn in [
            self.mine_once_button, self.mine_loop_button, self.rollup_button, self.recursive_rollup_button
        ]:
            btn.setEnabled(wallet_loaded and not mining)
        self.stop_mining_button.setEnabled(mining)

    def append_output(self, text: str):
        self.miner_output.append(text)
        self.miner_output.verticalScrollBar().setValue(
            self.miner_output.verticalScrollBar().maximum()
        )
        if hasattr(self.parentWindow, "appendOutput"):
            self.parentWindow.appendOutput(text)

    # --- MINING OPERATIONS USING RPC ---
    def mine_once(self):
        self.loop_active = False
        self.status_label.setText("🟢 <b>Mining one block...</b>")
        self.mining_banner.setText("Mining one block...")
        self.append_output("⏳ Mining one block...")
        self.run_rpc("mineonce", [self.current_wallet])

    def start_mining_loop(self):
        if self.loop_active:
            self.append_output("⚠️ Mining loop already running.")
            return
        self.loop_active = True
        self.status_label.setText("🟢 <b>Mining loop started...</b>")
        self.mining_banner.setText("Mining loop started...")
        self.append_output("⏳ Mining loop started...")
        self.run_loop_rpc("mineloop", [self.current_wallet])

    def stop_mining(self):
        if self.loop_active:
            self.loop_active = False
            self.status_label.setText("🟡 <b>AlynCoin Miner Status: Idle</b>")
            self.mining_banner.setText("💎 <b><font color='#00FFFF'>Ready to mine AlynCoin!</font></b>")
            self.append_output("⛔ Mining stopped by user.")
        self.updateMiningUIState()

    def trigger_rollup(self):
        self.append_output("⏳ Generating rollup block...")
        self.status_label.setText("🟢 <b>Generating Rollup Block...</b>")
        self.mining_banner.setText("Generating Rollup Block...")
        self.run_rpc("rollup", [self.current_wallet])

    def trigger_recursive_rollup(self):
        self.append_output("⏳ Generating recursive rollup...")
        self.status_label.setText("🟢 <b>Generating Recursive Rollup Block...</b>")
        self.mining_banner.setText("Generating Recursive Rollup Block...")
        self.run_rpc("recursive-rollup", [self.current_wallet])

    def run_rpc(self, method, params=None):
        def finish_rpc():
            self.status_label.setText("🟡 <b>AlynCoin Miner Status: Idle</b>")
            self.mining_banner.setText("💎 <b><font color='#00FFFF'>Ready to mine AlynCoin!</font></b>")
            self.updateMiningUIState()

        result = alyncoin_rpc(method, params)

        # Special handling for mining and rollup-related methods
        if method in ("mineonce", "rollup", "recursive-rollup"):
            if isinstance(result, dict) and "error" in result:
                self.append_output(f"❌ {result['error']}")
            elif isinstance(result, str) and re.fullmatch(r"[a-fA-F0-9]{40,}", result):
                label = "Block mined" if method == "mineonce" else (
                    "Rollup Block created" if method == "rollup" else "Recursive Rollup Block created"
                )
                self.append_output(f"✅ {label}! Hash: <b>{result}</b>")
            else:
                self.append_output(str(result))
            finish_rpc()
            return

        # Generic: for all other RPC calls
        if isinstance(result, dict) and "error" in result:
            self.append_output(f"❌ {result['error']}")
        elif isinstance(result, (dict, list)):
            lines = str(result).splitlines()
            for line in lines:
                if filter_miner_output(line) or "❌" in line or "⛔" in line or "[ERROR]" in line or "⚠️" in line:
                    self.append_output(line)
        elif isinstance(result, str):
            for line in result.splitlines():
                if filter_miner_output(line) or "❌" in line or "⛔" in line or "[ERROR]" in line or "⚠️" in line:
                    self.append_output(line)
        else:
            self.append_output(str(result))
        finish_rpc()

    def run_loop_rpc(self, method, params=None):
        # Simulated mining loop with periodic RPC calls (not a real infinite loop)
        def mine_step():
            if not self.loop_active:
                self.status_label.setText("🟡 <b>AlynCoin Miner Status: Idle</b>")
                self.mining_banner.setText("💎 <b><font color='#00FFFF'>Ready to mine AlynCoin!</font></b>")
                self.updateMiningUIState()
                return
            result = alyncoin_rpc(method, params)
            if isinstance(result, dict) and "error" in result:
                self.append_output(f"❌ {result['error']}")
                self.loop_active = False
            elif isinstance(result, (dict, list)):
                for line in str(result).splitlines():
                    if filter_miner_output(line):
                        self.append_output(line)
            elif isinstance(result, str):
                for line in result.splitlines():
                    if filter_miner_output(line):
                        self.append_output(line)
            else:
                self.append_output(str(result))
            if self.loop_active:
                QTimer.singleShot(3000, mine_step)
            else:
                self.status_label.setText("🟡 <b>AlynCoin Miner Status: Idle</b>")
                self.mining_banner.setText("💎 <b><font color='#00FFFF'>Ready to mine AlynCoin!</font></b>")
                self.updateMiningUIState()
        self.loop_active = True
        self.updateMiningUIState()
        mine_step()
