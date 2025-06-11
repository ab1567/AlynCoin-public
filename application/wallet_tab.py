import os
import re
import secrets
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPushButton,
    QLabel, QComboBox, QFileDialog, QHBoxLayout
)

from rpc_client import alyncoin_rpc

class WalletTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent=parent)
        self.parent = parent
        self.walletDir = os.path.expanduser("~/.alyncoin")  # Match CLI's getKeyDir()
        self.initUI()
        if hasattr(parent, 'walletChanged'):
            parent.walletChanged.connect(self.onWalletChanged)

    def initUI(self):
        layout = QVBoxLayout()

        self.addressInput = QLineEdit()
        self.addressInput.setPlaceholderText("Enter 20+ char alphanumeric or leave blank for auto")
        layout.addWidget(self.addressInput)

        self.walletSwitcher = QComboBox()
        self.refreshWalletList()
        self.walletSwitcher.currentIndexChanged.connect(self.onWalletSelected)
        layout.addWidget(self.walletSwitcher)

        buttonRow = QHBoxLayout()

        createBtn = QPushButton("Create Wallet")
        createBtn.clicked.connect(self.createWallet)
        buttonRow.addWidget(createBtn)

        loadBtn = QPushButton("Load Wallet")
        loadBtn.clicked.connect(self.loadWallet)
        buttonRow.addWidget(loadBtn)

        exportBtn = QPushButton("Backup Wallet")
        exportBtn.clicked.connect(self.exportWallet)
        buttonRow.addWidget(exportBtn)

        layout.addLayout(buttonRow)

        self.balanceBtn = QPushButton("Check Balance")
        self.balanceBtn.clicked.connect(self.checkBalance)
        layout.addWidget(self.balanceBtn)

        self.setLayout(layout)

    def appendOutput(self, text: str):
        if text.strip():
            self.parent.appendOutput(text)

    def refreshWalletList(self):
        self.walletSwitcher.clear()
        if os.path.exists(self.walletDir):
            for name in os.listdir(self.walletDir):
                if name.endswith("_private.pem"):
                    wallet_name = name.replace("_private.pem", "")
                    self.walletSwitcher.addItem(wallet_name)

    def onWalletSelected(self, index):
        name = self.walletSwitcher.currentText()
        if name:
            self.addressInput.setText(name)

    def createWallet(self):
        user_input = self.addressInput.text().strip()
        if user_input and (len(user_input) < 20 or not re.match(r'^[a-zA-Z0-9]+$', user_input)):
            self.appendOutput("⚠️ Wallet name must be alphanumeric & ≥ 20 chars.")
            return

        if not user_input:
            user_input = secrets.token_hex(20)
            self.appendOutput(f"⚙️ Auto-generating wallet name: {user_input}")

        # RPC: createwallet returns new wallet address
        result = alyncoin_rpc("createwallet", [user_input])
        if isinstance(result, dict) and "error" in result:
            self.appendOutput(f"❌ {result['error']}")
            return

        final_addr = user_input
        if isinstance(result, str) and re.match(r"^[a-f0-9]{40,64}$", result):
            final_addr = result

        self.addressInput.setText(final_addr)
        self.parent.set_wallet_address(final_addr)
        self.refreshWalletList()
        self.appendOutput(f"📬 Wallet Address: {final_addr}")

    def loadWallet(self):
        name = self.addressInput.text().strip()
        if not name:
            self.appendOutput("❌ Please enter a wallet name or address first.")
            return

        # RPC: loadwallet returns loaded address (or error)
        result = alyncoin_rpc("loadwallet", [name])
        if isinstance(result, dict) and "error" in result:
            self.appendOutput(f"❌ {result['error']}")
            return

        final_addr = name
        if isinstance(result, str) and re.match(r"^[a-f0-9]{40,64}$", result):
            final_addr = result

        self.addressInput.setText(final_addr)
        self.parent.set_wallet_address(final_addr)
        self.refreshWalletList()
        self.appendOutput(f"📬 Loaded Wallet: {final_addr}")

    def exportWallet(self):
        wallet = self.addressInput.text().strip()
        if not wallet:
            self.appendOutput("❌ No wallet selected to export.")
            return

        # Find all key files
        priv_path = os.path.join(self.walletDir, wallet + "_private.pem")
        dil_path = os.path.join(self.walletDir, wallet + "_dilithium.key")
        fal_path = os.path.join(self.walletDir, wallet + "_falcon.key")

        if not all(os.path.exists(p) for p in [priv_path, dil_path, fal_path]):
            self.appendOutput("❌ Key files not found for selected wallet.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Wallet Backup", f"{wallet}.bak")
        if not file_path:
            return

        try:
            with open(file_path, "w") as out:
                for p in [priv_path, dil_path, fal_path]:
                    with open(p, "r") as f:
                        out.write(f"----- {os.path.basename(p)} -----\n")
                        out.write(f.read() + "\n")
            self.appendOutput(f"💾 Backup created: {file_path}")
        except Exception as ex:
            self.appendOutput(f"❌ Error saving backup: {ex}")

    def checkBalance(self):
        addr = self.addressInput.text().strip()
        if not addr:
            self.appendOutput("❌ Please load a wallet first.")
            return

        self.appendOutput("🔍 Checking balance...")

        result = alyncoin_rpc("balance", [addr])
        if isinstance(result, dict) and "error" in result:
            self.appendOutput(f"❌ {result['error']}")
            return

        try:
            balance = float(result)
            self.appendOutput(f"💰 Balance: {balance} AlynCoin")
            self.appendOutput("✅ Done. You can check again anytime.")
        except Exception:
            self.appendOutput(f"⚠️ Could not parse balance from RPC output: {result}")

    def onWalletChanged(self, address):
        # Optionally update UI or refresh when wallet address changes
        pass
