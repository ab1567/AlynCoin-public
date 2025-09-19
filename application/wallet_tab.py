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
from wallet_utils import get_wallet_dir

class WalletTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent=parent)
        self.parent = parent
        # Wallet keys and optional passphrase hashes live alongside the node in
        # ``~/.alyncoin/keys`` (or the directory pointed to by ALYNCOIN_KEY_DIR).
        self.walletDir = str(get_wallet_dir())
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
        self.addressInput.setPlaceholderText("Enter wallet name or address to load. 'Create Wallet' will auto-generate")
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
        while True:
            key_id = secrets.token_hex(20)
            priv_path = os.path.join(self.walletDir, f"{key_id}_private.pem")
            if not os.path.exists(priv_path):
                break
        self.appendOutput(f"⚙️ Auto-generating wallet name: {key_id}")

        pass1, ok = QInputDialog.getText(
            self,
            "Passphrase",
            "Enter passphrase (leave blank for none, ≥8 chars if set):",
            QLineEdit.Password,
        )
        if not ok:
            return
        pass1 = (pass1 or "").strip()
        if pass1 and len(pass1) < 8:
            self.appendOutput("⚠️ Passphrase must be at least 8 characters.")
            return

        pass2 = ""
        if pass1:
            pass2, ok2 = QInputDialog.getText(
                self,
                "Confirm passphrase",
                "Confirm passphrase:",
                QLineEdit.Password,
            )
            if not ok2:
                return
            if pass1 != pass2:
                self.appendOutput("❌ Passphrases do not match.")
                return

        try:
            result = alyncoin_rpc("createwallet", [key_id, pass1])
        except Exception as e:
            self.appendOutput(f"❌ Wallet creation failed: {e}")
            return

        if isinstance(result, dict) and "error" in result:
            self.appendOutput(f"❌ {result['error']}")
            return

        wallet_addr = result if isinstance(result, str) else ""
        self.addressInput.setText(key_id)
        if wallet_addr:
            self.parent.set_wallet_address(wallet_addr, key_id)
            self.appendOutput(f"📬 Wallet Address: {wallet_addr}")
            self.appendOutput(f"🆔 Key Identifier: {key_id}")
        self.refreshWalletList()

    def loadWallet(self):
        name = self.addressInput.text().strip()
        if not name:
            self.appendOutput("❌ Please enter a wallet name or address first.")
            return

        passphrase, ok = QInputDialog.getText(self, "Passphrase", "Enter passphrase (leave blank if none):", QLineEdit.Password)
        if not ok:
            return

        try:
            result = alyncoin_rpc("loadwallet", [name, passphrase])
        except Exception as e:
            self.appendOutput(f"❌ Wallet load failed: {e}")
            return

        if isinstance(result, dict) and "error" in result:
            self.appendOutput(f"❌ {result['error']}")
            return

        final_addr = ""
        resolved_key_id = name
        if isinstance(result, dict):
            addr_candidate = result.get("address")
            if isinstance(addr_candidate, str):
                final_addr = addr_candidate
            key_candidate = result.get("key_id")
            if isinstance(key_candidate, str) and key_candidate:
                resolved_key_id = key_candidate
        elif isinstance(result, str) and re.match(r"^[a-f0-9]{40,64}$", result):
            final_addr = result

        if final_addr:
            self.addressInput.setText(resolved_key_id or name)
            self.parent.set_wallet_address(final_addr, resolved_key_id or name)
            self.appendOutput(f"📬 Loaded Wallet: {final_addr}")
            if resolved_key_id:
                self.appendOutput(f"🆔 Key Identifier: {resolved_key_id}")
        else:
            self.appendOutput(f"❌ Unexpected wallet load response: {result}")
        self.refreshWalletList()

    def exportWallet(self):
        wallet = self.addressInput.text().strip()
        if not wallet:
            self.appendOutput("❌ No wallet selected to export.")
            return
        try:
            result = alyncoin_rpc("exportwallet", [wallet])
        except Exception as e:
            self.appendOutput(f"❌ Export failed: {e}")
            return
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

        try:
            result = alyncoin_rpc("importwallet", [data])
        except Exception as e:
            self.appendOutput(f"❌ Import failed: {e}")
            return
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

        try:
            result = alyncoin_rpc("balance", [addr])
        except Exception as e:
            self.appendOutput(f"❌ Balance check failed: {e}")
            return
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
