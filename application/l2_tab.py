from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPushButton, QFileDialog
)

from rpc_client import l2_deploy, l2_call, l2_query


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
        with open(path, "rb") as f:
            wasm = f.read()
        addr = l2_deploy({"to": "", "data": wasm})
        self.parent.appendOutput(str(addr))

    def call(self):
        addr = self.callAddrInput.text().strip()
        data = self.callDataInput.text().strip()
        if not addr or not data:
            self.parent.appendOutput("❌ Missing address or calldata")
            return
        data_bytes = bytes.fromhex(data[2:] if data.startswith("0x") else data)
        res = l2_call({"to": addr, "data": data_bytes})
        self.parent.appendOutput(str(res))

    def query(self):
        addr = self.queryAddrInput.text().strip()
        key = self.queryKeyInput.text().strip()
        if not addr or not key:
            self.parent.appendOutput("❌ Missing address or key")
            return
        key_bytes = bytes.fromhex(key[2:] if key.startswith("0x") else key)
        res = l2_query({"to": addr, "data": key_bytes})
        self.parent.appendOutput(str(res))
