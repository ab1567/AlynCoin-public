import json
import subprocess
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPushButton, QFileDialog
)

CLI_PATH = "/root/AlynCoin/build/alyncoin-cli"


def _run_cli(args):
    try:
        out = subprocess.check_output([CLI_PATH] + args, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        out = e.output
    return out.strip()


class PolicyTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.multisigInput = QLineEdit()
        self.multisigInput.setPlaceholderText("Multisig m-of-n (e.g. 2-of-3)")
        layout.addWidget(self.multisigInput)

        self.dailyInput = QLineEdit()
        self.dailyInput.setPlaceholderText("Daily limit amount")
        layout.addWidget(self.dailyInput)

        self.allowInput = QLineEdit()
        self.allowInput.setPlaceholderText("Allowlist addresses (comma-separated)")
        layout.addWidget(self.allowInput)

        self.lockInput = QLineEdit()
        self.lockInput.setPlaceholderText("Lock-large threshold:minutes (e.g. 50:30)")
        layout.addWidget(self.lockInput)

        setBtn = QPushButton("Set Policy")
        setBtn.clicked.connect(self.setPolicy)
        layout.addWidget(setBtn)

        showBtn = QPushButton("Show Policy")
        showBtn.clicked.connect(self.showPolicy)
        layout.addWidget(showBtn)

        clearBtn = QPushButton("Clear Policy")
        clearBtn.clicked.connect(self.clearPolicy)
        layout.addWidget(clearBtn)

        exportBtn = QPushButton("Export Policy")
        exportBtn.clicked.connect(self.exportPolicy)
        layout.addWidget(exportBtn)

        importBtn = QPushButton("Import Policy")
        importBtn.clicked.connect(self.importPolicy)
        layout.addWidget(importBtn)

        self.setLayout(layout)

    def setPolicy(self):
        args = ["policy", "set"]
        if self.multisigInput.text().strip():
            args += ["--multisig", self.multisigInput.text().strip()]
        if self.dailyInput.text().strip():
            args += ["--daily", self.dailyInput.text().strip()]
        if self.allowInput.text().strip():
            args += ["--allow", self.allowInput.text().strip()]
        if self.lockInput.text().strip():
            args += ["--lock-large", self.lockInput.text().strip()]
        self.parent.appendOutput(_run_cli(args))

    def showPolicy(self):
        self.parent.appendOutput(_run_cli(["policy", "show"]))

    def clearPolicy(self):
        self.parent.appendOutput(_run_cli(["policy", "clear"]))

    def exportPolicy(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Policy", "policy.json", "JSON Files (*.json)")
        if path:
            self.parent.appendOutput(_run_cli(["policy", "export", path]))

    def importPolicy(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Policy", "", "JSON Files (*.json)")
        if path:
            self.parent.appendOutput(_run_cli(["policy", "import", path]))
