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


class L2Tab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Deploy
        self.wasmInput = QLineEdit()
        self.wasmInput.setPlaceholderText("Path to Wasm file")
        layout.addWidget(self.wasmInput)
        deployBtn = QPushButton("Deploy")
        deployBtn.clicked.connect(self.deploy)
        layout.addWidget(deployBtn)

        # Call
        self.callAddrInput = QLineEdit()
        self.callAddrInput.setPlaceholderText("Contract address")
        layout.addWidget(self.callAddrInput)
        self.callDataInput = QLineEdit()
        self.callDataInput.setPlaceholderText("Hex calldata (e.g. 0x010203)")
        layout.addWidget(self.callDataInput)
        self.gasInput = QLineEdit()
        self.gasInput.setPlaceholderText("Gas limit")
        layout.addWidget(self.gasInput)
        callBtn = QPushButton("Call")
        callBtn.clicked.connect(self.call)
        layout.addWidget(callBtn)

        # Query
        self.queryAddrInput = QLineEdit()
        self.queryAddrInput.setPlaceholderText("Contract address")
        layout.addWidget(self.queryAddrInput)
        self.queryKeyInput = QLineEdit()
        self.queryKeyInput.setPlaceholderText("Storage key (hex)")
        layout.addWidget(self.queryKeyInput)
        queryBtn = QPushButton("Query")
        queryBtn.clicked.connect(self.query)
        layout.addWidget(queryBtn)

        self.setLayout(layout)

    def deploy(self):
        path = self.wasmInput.text().strip()
        if not path:
            path, _ = QFileDialog.getOpenFileName(self, "Select Wasm", "", "Wasm Files (*.wasm)")
            if not path:
                return
            self.wasmInput.setText(path)
        self.parent.appendOutput(_run_cli(["l2", "deploy", path]))

    def call(self):
        addr = self.callAddrInput.text().strip()
        data = self.callDataInput.text().strip()
        gas = self.gasInput.text().strip() or "0"
        if not addr or not data:
            self.parent.appendOutput("❌ Missing address or calldata")
            return
        args = ["l2", "call", addr, data]
        if gas:
            args += ["--gas", gas]
        self.parent.appendOutput(_run_cli(args))

    def query(self):
        addr = self.queryAddrInput.text().strip()
        key = self.queryKeyInput.text().strip()
        if not addr or not key:
            self.parent.appendOutput("❌ Missing address or key")
            return
        self.parent.appendOutput(_run_cli(["l2", "query", addr, key]))
