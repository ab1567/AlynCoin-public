import re
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QComboBox, QPushButton

from rpc_client import alyncoin_rpc

class SendTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.sender = ""
        self.sendInProgress = False
        self.initUI()
        if hasattr(parent, 'walletChanged'):
            parent.walletChanged.connect(self.onWalletChanged)

    def initUI(self):
        layout = QVBoxLayout()
        self.recipientInput = QLineEdit()
        self.recipientInput.setPlaceholderText("Recipient Address")
        layout.addWidget(self.recipientInput)

        self.amountInput = QLineEdit()
        self.amountInput.setPlaceholderText("Amount to Send")
        layout.addWidget(self.amountInput)

        self.layerSelector = QComboBox()
        self.layerSelector.addItems(["Layer 1 (L1)", "Layer 2 (L2)"])
        layout.addWidget(self.layerSelector)

        self.sendBtn = QPushButton("Send Transaction")
        self.sendBtn.clicked.connect(self.sendTransaction)
        layout.addWidget(self.sendBtn)

        self.setLayout(layout)
        self.updateSendUIState()

    def onWalletChanged(self, address):
        self.sender = address
        self.updateSendUIState()

    def updateSendUIState(self):
        wallet_loaded = bool(self.sender)
        self.sendBtn.setEnabled(wallet_loaded and not self.sendInProgress)
        self.recipientInput.setEnabled(wallet_loaded and not self.sendInProgress)
        self.amountInput.setEnabled(wallet_loaded and not self.sendInProgress)
        self.layerSelector.setEnabled(wallet_loaded and not self.sendInProgress)

    def sendTransaction(self):
        if self.sendInProgress:
            self.parent.appendOutput("⚠️ Please wait. A transaction is already in progress.")
            return

        self.sendInProgress = True
        self.updateSendUIState()
        sender = self.sender or self.parent.get_wallet_address()
        recipient = self.recipientInput.text().strip()
        amount_text = self.amountInput.text().strip()

        if not sender:
            self.parent.appendOutput("❌ Please load your wallet first.")
            self.resetState()
            return
        if not recipient or not amount_text:
            self.parent.appendOutput("❌ Missing recipient or amount.")
            self.resetState()
            return
        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError
        except ValueError:
            self.parent.appendOutput("❌ Amount must be a valid number.")
            self.resetState()
            return

        self.parent.appendOutput("📤 Sending transaction...")

        isL2 = (self.layerSelector.currentIndex() == 1)
        tx_type = "sendl2" if isL2 else "sendl1"
        metadata = "viaGUI"

        result = alyncoin_rpc(tx_type, [sender, recipient, amount, metadata])
        if isinstance(result, dict) and "error" in result:
            self.parent.appendOutput(f"❌ {result['error']}")
        elif isinstance(result, str) and "broadcasted" in result.lower():
            self.parent.appendOutput(
                f"✅ Transaction sent from {sender} to {recipient} for {amount} AlynCoin."
            )
        else:
            self.parent.appendOutput(f"❌ Transaction failed: {result}")

        self.resetState()

    def resetState(self):
        self.sendInProgress = False
        self.updateSendUIState()