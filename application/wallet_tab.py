import os
import re
import secrets
import json
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPushButton,
    QLabel, QComboBox, QFileDialog, QHBoxLayout, QInputDialog
)

from rpc_client import alyncoin_rpc

class WalletTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent=parent)
        self.parent = parent
        # Wallet keys and optional passphrase hashes live in ~/.alyncoin/keys
        # to match the node's DBPaths::getKeyDir().
        # Allow overriding the key directory via environment variable, expanding '~'
        self.walletDir = os.path.expanduser(os.environ.get("ALYNCOIN_KEY_DIR", "~/.alyncoin/keys"))
        if not os.path.exists(self.walletDir):
            try:
                os.makedirs(self.walletDir, exist_ok=True)
            except Exception as e:
                print(f"⚠️ Failed to create wallet directory '{self.walletDir}': {e}")
        self.initUI()
        if hasattr(parent, 'walletChanged'):
            parent.walletChanged.connect(self.onWalletChanged)

    def initUI(self):
        layout = QVBoxLayout()

        self.addressInput = QLineEdit()
        self.addressInput.setPlaceholderText("Enter wallet name to load. 'Create Wallet' will auto-generate")
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

        exportBtn = QPushButton("Export Wallet")
        exportBtn.clicked.connect(self.exportWallet)
        buttonRow.addWidget(exportBtn)

        importBtn = QPushButton("Import Wallet")
        importBtn.clicked.connect(self.importWallet)
        buttonRow.addWidget(importBtn)

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
        # Generate a unique wallet name using cryptographically secure randomness
        while True:
            user_input = secrets.token_hex(20)
            priv_path = os.path.join(self.walletDir, f"{user_input}_private.pem")
            if not os.path.exists(priv_path):
                break
        self.appendOutput(f"⚙️ Auto-generating wallet name: {user_input}")

        passphrase, _ = QInputDialog.getText(self, "Passphrase", "Enter passphrase (optional):", QLineEdit.Password)

        # RPC createwallet accepts [name, passphrase]
        result = alyncoin_rpc("createwallet", [user_input, passphrase])
        if isinstance(result, dict) and "error" in result:
            self.appendOutput(f"❌ {result['error']}")
            return

        final_addr = ""
        if isinstance(result, str) and re.match(r"^[a-f0-9]{40,64}$", result):
            final_addr = result

        # Show wallet name in the input box for future loads
        self.addressInput.setText(user_input)
        if final_addr:
            self.parent.set_wallet_address(final_addr, user_input)
            self.appendOutput(f"📬 Wallet Address: {final_addr}")
            self.appendOutput(f"🆔 Key Identifier: {user_input}")
        self.refreshWalletList()

    def loadWallet(self):
        name = self.addressInput.text().strip()
        if not name:
            self.appendOutput("❌ Please enter a wallet name or address first.")
            return

        passphrase, ok = QInputDialog.getText(self, "Passphrase", "Enter passphrase (leave blank if none):", QLineEdit.Password)
        if not ok:
            return

        # RPC: loadwallet returns loaded address (or error)
        result = alyncoin_rpc("loadwallet", [name, passphrase])
        if isinstance(result, dict) and "error" in result:
            self.appendOutput(f"❌ {result['error']}")
            return

        final_addr = ""
        if isinstance(result, str) and re.match(r"^[a-f0-9]{40,64}$", result):
            final_addr = result

        # Keep wallet name in the input box
        self.addressInput.setText(name)
        if final_addr:
            self.parent.set_wallet_address(final_addr, name)
            self.appendOutput(f"📬 Loaded Wallet: {final_addr}")
            self.appendOutput(f"🆔 Key Identifier: {name}")
        self.refreshWalletList()

    def exportWallet(self):
        wallet = self.addressInput.text().strip()
        if not wallet:
            self.appendOutput("❌ No wallet selected to export.")
            return
        result = alyncoin_rpc("exportwallet", [wallet])
        if isinstance(result, dict) and "error" in result:
            self.appendOutput(f"❌ {result['error']}")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Wallet Backup", f"{wallet}.json")
        if not file_path:
            return

        try:
            with open(file_path, "w") as out:
                json.dump(result, out, indent=2)
            self.appendOutput(f"💾 Wallet exported: {file_path}")
        except Exception as ex:
            self.appendOutput(f"❌ Failed to save wallet backup: {ex}")

    def importWallet(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Wallet Backup", "", "JSON Files (*.json)")
        if not file_path:
            return
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except Exception as ex:
            self.appendOutput(f"❌ Failed to read wallet backup: {ex}")
            return

        result = alyncoin_rpc("importwallet", [data])
        if isinstance(result, dict) and "error" in result:
            self.appendOutput(f"❌ {result['error']}")
            return

        wallet_name = data.get("address") or ""
        if isinstance(result, str):
            wallet_name = result
        if wallet_name:
            self.addressInput.setText(wallet_name)
            self.parent.set_wallet_address(wallet_name, wallet_name)
            self.appendOutput(f"📬 Imported Wallet: {wallet_name}")
            self.appendOutput(f"🆔 Key Identifier: {wallet_name}")
        else:
            self.appendOutput("⚠️ Wallet imported but no address returned.")
        self.refreshWalletList()

    def checkBalance(self):
        addr = self.parent.get_wallet_address()
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
