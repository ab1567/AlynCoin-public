"""Swap-related GUI actions."""

# blake3 is used to hash secrets before sending them to the chain.  The
# dependency may not be installed in all environments (e.g. when running the
# GUI without `pip install -r requirements.txt`).  Import it lazily so the
# application can still start and provide a helpful runtime message instead of
# crashing on import.
try:  # pragma: no cover - import guard
    from blake3 import blake3
except ModuleNotFoundError:  # pragma: no cover - handled at runtime
    blake3 = None

# pycryptodome provides the Keccak hashing function.  It might not be
# installed in all environments, so guard its import and provide a helpful
# runtime message instead of crashing at import time.
try:  # pragma: no cover - import guard
    from Crypto.Hash import keccak
except ModuleNotFoundError:  # pragma: no cover - handled at runtime
    keccak = None

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QDialog, QLineEdit,
    QFormLayout, QDialogButtonBox
)

from rpc_client import safe_alyncoin_rpc


class SwapTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        self.addButton("🔄 Initiate Swap", self.initiateSwap, layout)
        self.addButton("🧩 Redeem Swap", self.redeemSwap, layout)
        self.addButton("⏱ Refund Swap", self.refundSwap, layout)
        self.addButton("🔍 Get Swap Info", self.getSwap, layout)
        self.addButton("📊 Swap State", self.getState, layout)
        self.addButton("🛡 Verify Swap Signature", self.verifySwap, layout)
        self.setLayout(layout)

    def onWalletChanged(self, addr: str):
        if not addr:
            return
        key_id = getattr(self.parent, "loadedKeyId", "")
        if key_id:
            self.parent.appendOutput(
                f"📬 Active Wallet for Swaps: {addr} (Key ID: {key_id})"
            )
        else:
            self.parent.appendOutput(f"📬 Active Wallet for Swaps: {addr}")

    def addButton(self, label, callback, layout):
        btn = QPushButton(label)
        btn.clicked.connect(callback)
        layout.addWidget(btn)

    def getAddress(self):
        addr = getattr(self.parent, "loadedAddress", "")
        if not addr:
            self.parent.appendOutput("❌ Wallet not loaded.")
        return addr

    def showResult(self, result):
        if isinstance(result, dict) and "error" in result:
            self.parent.appendOutput(f"❌ {result['error']}")
        else:
            self.parent.appendOutput(str(result))

    def initiateSwap(self):
        addr = self.getAddress()
        if not addr:
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

            if blake3 is None:
                self.parent.appendOutput(
                    "❌ blake3 package is missing. Install it with 'pip install blake3'."
                )
                return

            if keccak is None:
                self.parent.appendOutput(
                    "❌ pycryptodome package is missing. Install it with 'pip install pycryptodome'."
                )
                return

            # Match the chain's hybrid hash: keccak256(blake3(secret))
            b3 = blake3(sec.encode()).hexdigest()
            hashed = keccak.new(digest_bits=256, data=b3.encode()).hexdigest()
            self.parent.appendOutput(f"🧮 Local Secret Hash (preview): {hashed}")
            params = [addr, recv, amt, hashed, dur]
            result = self._rpc("swap-initiate", params)
            self.showResult(result)

    def redeemSwap(self):
        self._multiFieldDialog(
            "🧩 Redeem Swap",
            [("🆔 Swap ID", "id"), ("🧩 Secret Preimage", "secret")],
            lambda d: self.showResult(
                self._rpc("swap-redeem", [d["id"], d["secret"]]) if d["secret"].strip() else {"error": "Secret cannot be empty"}
            ),
        )

    def refundSwap(self):
        self._singleFieldDialog(
            "⏱ Refund Swap",
            "Swap ID",
            lambda sid: self.showResult(self._rpc("swap-refund", [sid])),
        )

    def getSwap(self):
        self._singleFieldDialog(
            "🔍 Get Swap Info",
            "Swap ID",
            lambda sid: self.showResult(self._rpc("swap-get", [sid])),
        )

    def getState(self):
        self._singleFieldDialog(
            "📊 Swap State",
            "Swap ID",
            lambda sid: self.showResult(self._rpc("swap-state", [sid])),
        )

    def verifySwap(self):
        self._singleFieldDialog(
            "🛡 Verify Swap Signature",
            "Swap ID",
            lambda sid: self.showResult(self._rpc("swap-verify", [sid])),
        )

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

    def _rpc(self, method: str, params=None):
        result = safe_alyncoin_rpc(method, params)
        if isinstance(result, dict) and "error" in result:
            err = result["error"].lower()
            if "rpc request failed" in err or "connection refused" in err:
                return {"error": "Unable to reach the local node RPC. Ensure the node is running."}
        return result

