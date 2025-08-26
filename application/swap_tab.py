import hashlib
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QDialog, QLineEdit,
    QFormLayout, QDialogButtonBox, QCheckBox
)
from PyQt5.QtCore import QProcess

SWAP_CLI = "/root/AlynCoin/build/swapcli"

class SwapTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.debugMode = False  # default: debug off
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.process_finished)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # 🔧 Toggle for Debug Logs
        self.debugToggle = QCheckBox("Show Debug Logs")
        self.debugToggle.stateChanged.connect(self.toggleDebug)
        layout.addWidget(self.debugToggle)

        # 🔘 Buttons
        self.addButton("🔄 Initiate Swap", self.initiateSwap, layout)
        self.addButton("🧩 Redeem Swap", self.redeemSwap, layout)
        self.addButton("⏱ Refund Swap", self.refundSwap, layout)
        self.addButton("🔍 Get Swap Info", self.getSwap, layout)
        self.addButton("📊 Swap State", self.getState, layout)
        self.addButton("🛡 Verify Swap Signature", self.verifySwap, layout)

        self.setLayout(layout)

    def addButton(self, label, callback, layout):
        btn = QPushButton(label)
        btn.clicked.connect(callback)
        layout.addWidget(btn)

    def toggleDebug(self, state):
        self.debugMode = bool(state)

    def runCLI(self, cmd):
        if self.process.state() != QProcess.NotRunning:
            self.parent.appendOutput("⚠️ Previous swap CLI still running.")
            return
        self.parent.appendOutput(f"🔄 Running Swap CLI command: {cmd}")
        self.process.start("wsl", ["bash", "-c", cmd])

    def handle_stdout(self):
        output = self.filterOutput(bytes(self.process.readAllStandardOutput()).decode("utf-8"))
        if output.strip():
            self.parent.appendOutput(output.strip())

    def handle_stderr(self):
        error = self.filterOutput(bytes(self.process.readAllStandardError()).decode("utf-8"))
        if error.strip():
            self.parent.appendOutput(f"⚠️ {error.strip()}")

    def filterOutput(self, text):
        lines = text.splitlines()
        clean = []
        for line in lines:
            if "libprotobuf ERROR" in line:
                continue
            if not self.debugMode:
                if any(sub in line for sub in [
                    "[DEBUG]",
                    "toHex()",
                    "fromHex()",
                    "Falcon Signing Initiated",
                    "crypto_sign_signature",
                    "Dilithium signing",
                    "Message size:",
                    "Private key size:",
                    "Converted",
                    "Calling Falcon",
                    "Starting Dilithium",
                    "Seed:",
                    "Seed len:",
                    "First 32 proof bytes",
                    "prevHash:",
                    "txRoot:",
                    "blockHash:",
                ]):
                    continue
            clean.append(line)
        return "\n".join(clean)

    def process_finished(self):
        self.parent.appendOutput("✅ Swap CLI task finished.\n")

    def getAddress(self):
        addr = self.parent.loadedAddress
        if not addr:
            self.parent.appendOutput("❌ Wallet not loaded.")
        return addr

    def initiateSwap(self):
        sender = self.getAddress()
        if not sender:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("🔄 Initiate Swap")
        form = QFormLayout(dialog)

        receiver = QLineEdit()
        amount = QLineEdit()
        secret = QLineEdit()
        duration = QLineEdit()

        receiver.setPlaceholderText("Receiver Address")
        amount.setPlaceholderText("Amount (numeric)")
        secret.setPlaceholderText("Secret Preimage")
        duration.setPlaceholderText("Duration in seconds (e.g. 300)")

        form.addRow("👤 Receiver:", receiver)
        form.addRow("💰 Amount:", amount)
        form.addRow("🧩 Secret:", secret)
        form.addRow("⏱ Duration:", duration)

        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(dialog.accept)
        box.rejected.connect(dialog.reject)
        form.addRow(box)

        if dialog.exec_():
            recv = receiver.text().strip()
            amt = amount.text().strip()
            sec = secret.text().strip()
            dur = duration.text().strip()

            if not recv or not amt or not sec or not dur:
                self.parent.appendOutput("❌ All fields are required.")
                return

            try:
                float(amt)
                int(dur)
            except ValueError:
                self.parent.appendOutput("❌ Amount and duration must be numeric.")
                return

            hashed = hashlib.sha256(sec.encode()).hexdigest()
            self.parent.appendOutput(f"🧮 Local Secret Hash (preview): {hashed}")
            cmd = f'{SWAP_CLI} initiate --sender "{sender}" --receiver "{recv}" --amount {amt} --hash "{sec}" --duration {dur}'
            self.runCLI(cmd)

    def redeemSwap(self):
        self._multiFieldDialog("🧩 Redeem Swap", [
            ("🆔 Swap ID", "id"),
            ("🧩 Secret Preimage", "secret")
        ], lambda d: self.runCLI(f'{SWAP_CLI} redeem --id "{d["id"]}" --secret "{d["secret"]}"'))

    def refundSwap(self):
        self._singleFieldDialog("⏱ Refund Swap", "Swap ID",
            lambda sid: self.runCLI(f'{SWAP_CLI} refund --id "{sid}"'))

    def getSwap(self):
        self._singleFieldDialog("🔍 Get Swap Info", "Swap ID",
            lambda sid: self.runCLI(f'{SWAP_CLI} get --id "{sid}"'))

    def getState(self):
        self._singleFieldDialog("📊 Swap State", "Swap ID",
            lambda sid: self.runCLI(f'{SWAP_CLI} state --id "{sid}"'))

    def verifySwap(self):
        self._singleFieldDialog("🛡 Verify Swap Signature", "Swap ID",
            lambda sid: self.runCLI(f'{SWAP_CLI} verify --id "{sid}"'))

    def _singleFieldDialog(self, title, label, callback):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        form = QFormLayout(dialog)

        field = QLineEdit()
        field.setPlaceholderText(label)
        form.addRow(label + ":", field)

        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(dialog.accept)
        box.rejected.connect(dialog.reject)
        form.addRow(box)

        if dialog.exec_():
            val = field.text().strip()
            if not val:
                self.parent.appendOutput(f"❌ {label} required.")
                return
            callback(val)

    def _multiFieldDialog(self, title, fields, callback):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        form = QFormLayout(dialog)
        inputs = {}

        for label, key in fields:
            line = QLineEdit()
            line.setPlaceholderText(label)
            form.addRow(label + ":", line)
            inputs[key] = line

        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(dialog.accept)
        box.rejected.connect(dialog.reject)
        form.addRow(box)

        if dialog.exec_():
            result = {}
            for key, widget in inputs.items():
                val = widget.text().strip()
                if not val:
                    self.parent.appendOutput(f"❌ {key} is required.")
                    return
                result[key] = val
            callback(result)
