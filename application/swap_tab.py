import hashlib
from concurrent.futures import ThreadPoolExecutor

from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QPushButton,
    QDialog,
    QLineEdit,
    QFormLayout,
    QDialogButtonBox,
)
from PyQt5.QtCore import QTimer

from rpc_client import alyncoin_rpc


class SwapTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        self.addButton("\U0001f504 Initiate Swap", self.initiateSwap, layout)
        self.addButton("\U0001f9e9 Redeem Swap", self.redeemSwap, layout)
        self.addButton("\u23f1 Refund Swap", self.refundSwap, layout)
        self.addButton("\U0001f50d Get Swap Info", self.getSwap, layout)
        self.addButton("\U0001f4ca Swap State", self.getState, layout)
        self.addButton("\U0001f6e1 Verify Swap Signature", self.verifySwap, layout)
        self.setLayout(layout)

    def addButton(self, label, callback, layout):
        btn = QPushButton(label)
        btn.clicked.connect(callback)
        layout.addWidget(btn)

    def runRPC(self, method, params):
        self.parent.appendOutput(f"\U0001f504 Calling swap RPC: {method}")
        fut = self.executor.submit(lambda: alyncoin_rpc(method, params))
        fut.add_done_callback(
            lambda f: QTimer.singleShot(0, lambda: self._finishRPC(method, f))
        )

    def _finishRPC(self, method, future):
        try:
            result = future.result()
            if isinstance(result, dict) and "error" in result:
                self.parent.appendOutput(f"\u274c {result['error']}")
            else:
                self.parent.appendOutput(str(result))
        except Exception as e:
            self.parent.appendOutput(f"\u274c {e}")
        self.parent.appendOutput("\u2705 Swap RPC task finished.\n")

    def getAddress(self):
        addr = getattr(self.parent, "loadedAddress", "")
        if not addr:
            self.parent.appendOutput("\u274c Wallet not loaded.")
        return addr

    def initiateSwap(self):
        sender = self.getAddress()
        if not sender:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("\U0001f504 Initiate Swap")
        form = QFormLayout(dialog)

        receiver = QLineEdit()
        amount = QLineEdit()
        secret = QLineEdit()
        duration = QLineEdit()

        receiver.setPlaceholderText("Receiver Address")
        amount.setPlaceholderText("Amount (numeric)")
        secret.setPlaceholderText("Secret Preimage")
        duration.setPlaceholderText("Duration in seconds (e.g. 300)")

        form.addRow("\U0001f464 Receiver:", receiver)
        form.addRow("\U0001f4b0 Amount:", amount)
        form.addRow("\U0001f9e9 Secret:", secret)
        form.addRow("\u23f1 Duration:", duration)

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
                self.parent.appendOutput("\u274c All fields are required.")
                return

            try:
                int_amt = int(amt)
                int_dur = int(dur)
            except ValueError:
                self.parent.appendOutput(
                    "\u274c Amount and duration must be numeric."
                )
                return

            hashed = hashlib.sha256(sec.encode()).hexdigest()
            self.parent.appendOutput(
                f"\U0001f9ee Local Secret Hash (preview): {hashed}"
            )
            params = [sender, recv, int_amt, sec, int_dur]
            self.runRPC("swap-initiate", params)

    def redeemSwap(self):
        self._multiFieldDialog(
            "\U0001f9e9 Redeem Swap",
            [
                ("\U0001f194 Swap ID", "id"),
                ("\U0001f9e9 Secret Preimage", "secret"),
            ],
            lambda d: self.runRPC("swap-redeem", [d["id"], d["secret"]]),
        )

    def refundSwap(self):
        self._singleFieldDialog(
            "\u23f1 Refund Swap",
            "Swap ID",
            lambda sid: self.runRPC("swap-refund", [sid]),
        )

    def getSwap(self):
        self._singleFieldDialog(
            "\U0001f50d Get Swap Info",
            "Swap ID",
            lambda sid: self.runRPC("swap-get", [sid]),
        )

    def getState(self):
        self._singleFieldDialog(
            "\U0001f4ca Swap State",
            "Swap ID",
            lambda sid: self.runRPC("swap-state", [sid]),
        )

    def verifySwap(self):
        self._singleFieldDialog(
            "\U0001f6e1 Verify Swap Signature",
            "Swap ID",
            lambda sid: self.runRPC("swap-verify", [sid]),
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
                self.parent.appendOutput(f"\u274c {label} required.")
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
            data = {}
            for key, widget in inputs.items():
                val = widget.text().strip()
                if not val:
                    self.parent.appendOutput(f"\u274c {key} is required.")
                    return
                data[key] = val
            callback(data)

    def closeEvent(self, ev):
        try:
            self.executor.shutdown(wait=False, cancel_futures=True)
        finally:
            super().closeEvent(ev)

