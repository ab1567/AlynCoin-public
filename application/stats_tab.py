import re
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton

from rpc_client import alyncoin_rpc, RpcClientError, RpcNotReady, RpcError

class StatsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main = parent
        self.initUI()
        if hasattr(parent, 'walletChanged'):
            parent.walletChanged.connect(self.onWalletChanged)

    def initUI(self):
        layout = QVBoxLayout()
        title = QLabel("📊 AlynCoin Stats Overview")
        title.setStyleSheet("color: cyan; font-size: 16px; font-weight: bold;")
        layout.addWidget(title)

        self.outputBox = QTextEdit()
        self.outputBox.setReadOnly(True)
        self.outputBox.setFont(QFont("Consolas", 10))
        layout.addWidget(self.outputBox)

        self.showStatsBtn = QPushButton("🔍 Show All Stats")
        self.showStatsBtn.setStyleSheet("padding: 10px; font-weight: bold;")
        self.showStatsBtn.clicked.connect(self.fetchStats)
        layout.addWidget(self.showStatsBtn)

        self.peerBtn = QPushButton("👥 Show Peers")
        self.peerBtn.setStyleSheet("padding: 10px; font-weight: bold;")
        self.peerBtn.clicked.connect(self.fetchPeers)
        layout.addWidget(self.peerBtn)

        self.syncBtn = QPushButton("🔄 Hard Sync")
        self.syncBtn.setStyleSheet("padding: 10px; font-weight: bold;")
        self.syncBtn.clicked.connect(self.triggerSync)
        layout.addWidget(self.syncBtn)

        self.setLayout(layout)

    def _handle_rpc_failure(self, exc, action="request"):
        if isinstance(exc, RpcNotReady):
            self.appendText(
                f"⚠️ Node RPC unavailable — {action} cannot be completed right now.",
                color="red",
            )
        elif isinstance(exc, RpcError):
            self.appendText(f"❌ RPC error while {action}: {exc}", color="red")
        else:
            self.appendText(f"❌ Failed to {action}: {exc}", color="red")

    def fetchStats(self):
        self.outputBox.clear()
        self.appendText("⏳ Fetching stats...", color="orange")
        self.showStatsBtn.setEnabled(False)

        try:
            result = alyncoin_rpc("stats")
        except RpcClientError as exc:
            self._handle_rpc_failure(exc, "fetch stats")
            self.showStatsBtn.setEnabled(True)
            return

        self.showStatsBtn.setEnabled(True)

        if isinstance(result, dict) and "error" in result:
            self.appendText(f"❌ {result['error']}", color="red")
            return
        if not result or not isinstance(result, dict):
            self.appendText("⚠️ Could not fetch stats from RPC server.", color="red")
            return

        # Parse and color-code stats
        try:
            if "blocks" in result:
                self.appendText(f"📦 Total Blocks: {result['blocks']}", color="cyan")
            if "difficulty" in result:
                self.appendText(f"🧩 Difficulty: {result['difficulty']}", color="orange")
            if "supply" in result:
                self.appendText(f"💰 Total Supply: {result['supply']} AlynCoin", color="green")
            if "block_reward" in result:
                self.appendText(f"⛏️ Block Reward: {result['block_reward']} AlynCoin", color="green")
            if "burned" in result:
                self.appendText(f"🔥 Total Burned: {result['burned']} AlynCoin", color="red")
            if "devfund" in result:
                self.appendText(f"🏛️ Dev Fund Balance: {result['devfund']} AlynCoin", color="cyan")
        except Exception as e:
            self.appendText(f"❌ Error parsing stats: {e}", color="red")

    def triggerSync(self):
        self.appendText("⏳ Initiating hard sync...", color="orange")
        self.syncBtn.setEnabled(False)
        try:
            result = alyncoin_rpc("selfheal")
        except RpcClientError as exc:
            self._handle_rpc_failure(exc, "trigger sync")
            self.syncBtn.setEnabled(True)
            return
        self.syncBtn.setEnabled(True)
        if isinstance(result, dict) and "error" in result:
            self.appendText(f"❌ {result['error']}", color="red")
        else:
            self.appendText("✅ Sync triggered. Check node output for progress.", color="green")

    def fetchPeers(self):
        self.outputBox.clear()
        self.appendText("⏳ Fetching peer list...", color="orange")
        try:
            result = alyncoin_rpc("peerlist")
        except RpcClientError as exc:
            self._handle_rpc_failure(exc, "fetch peers")
            return
        if isinstance(result, dict) and "error" in result:
            self.appendText(f"❌ {result['error']}", color="red")
            return
        if isinstance(result, list):
            self.appendText(f"Connected peers ({len(result)}):", color="cyan")
            for p in result:
                self.appendText(f"- {p}")
        else:
            self.appendText("⚠️ Could not fetch peers from RPC server.", color="red")

    def appendText(self, text, color="white"):
        color_map = {
            "red": QColor(255, 80, 80),
            "green": QColor(80, 255, 80),
            "cyan": QColor(80, 255, 255),
            "orange": QColor(255, 165, 0),
            "white": QColor(255, 255, 255)
        }
        self.outputBox.setTextColor(color_map.get(color, QColor(255, 255, 255)))
        self.outputBox.append(text)

    def onWalletChanged(self, address):
        # Optional: clear stats or refresh when wallet changes
        pass
