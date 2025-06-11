import os
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QDialog,
    QFormLayout, QLineEdit, QDialogButtonBox
)
from PyQt5.QtCore import QProcess

IDENTITY_CLI = "/root/AlynCoin/build/identitycli"

def filter_debug_output(raw_output):
    """
    Filters and cleans raw CLI output to exclude extra debug logs and retain only user-relevant messages.
    """
    cleaned_lines = []
    for line in raw_output.splitlines():
        if any(kw in line for kw in [
            "[DEBUG]", "[ZK]", "[zkSTARK]", "✅ [DEBUG]", "⚠️ [DEBUG]"
        ]):
            continue
        cleaned_lines.append(line.strip())
    return "\n".join(cleaned_lines)

class IdentityTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.process_finished)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        viewBtn = QPushButton("🔍 View My Identity")
        createBtn = QPushButton("🪪 Create Identity")
        listBtn = QPushButton("📋 List All Identities")
        deleteBtn = QPushButton("❌ Delete Identity")

        viewBtn.clicked.connect(self.viewIdentity)
        createBtn.clicked.connect(self.createIdentity)
        listBtn.clicked.connect(self.listIdentities)
        deleteBtn.clicked.connect(self.deleteIdentity)

        layout.addWidget(viewBtn)
        layout.addWidget(createBtn)
        layout.addWidget(listBtn)
        layout.addWidget(deleteBtn)
        self.setLayout(layout)

    def runCLI(self, args):
        if self.process.state() != QProcess.NotRunning:
            self.parent.appendOutput("⚠️ Previous identity CLI still running.")
            return
        cmd = f"{IDENTITY_CLI} {args}"
        self.parent.appendOutput(f"🔐 Running Identity CLI command: {cmd}")
        self.process.start("wsl", ["bash", "-c", cmd])

    def handle_stdout(self):
        output = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace").strip()
        if output:
            clean = filter_debug_output(output)
            if clean:
                self.parent.appendOutput(clean)

    def handle_stderr(self):
        error = bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace").strip()
        if error:
            self.parent.appendOutput(f"⚠️ {error}")

    def process_finished(self):
        self.parent.appendOutput("✅ Identity CLI task finished.\n")

    def getAddress(self):
        addr = self.parent.loadedAddress
        if not addr:
            self.parent.appendOutput("❌ Wallet not loaded.")
        return addr

    def viewIdentity(self):
        addr = self.getAddress()
        if addr:
            self.runCLI(f'view "{addr}"')

    def createIdentity(self):
        addr = self.getAddress()
        if not addr:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("🪪 Create zk-Identity")
        form = QFormLayout(dialog)

        name = QLineEdit()
        name.setPlaceholderText("Display name (e.g. Alyana)")

        form.addRow("👤 Name:", name)

        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(dialog.accept)
        box.rejected.connect(dialog.reject)
        form.addRow(box)

        if dialog.exec_():
            displayName = name.text().strip()
            if not displayName:
                self.parent.appendOutput("❌ Display name required.")
                return
            self.runCLI(f'create "{addr}" "{displayName}"')

    def listIdentities(self):
        self.runCLI("list")

    def deleteIdentity(self):
        addr = self.getAddress()
        if addr:
            self.runCLI(f'delete "{addr}"')
