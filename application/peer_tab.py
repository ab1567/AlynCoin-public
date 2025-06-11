from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLineEdit

class PeerTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent  # Access to main window
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.peerInput = QLineEdit()
        self.peerInput.setPlaceholderText("Enter peer address (e.g. 192.168.1.5)")
        layout.addWidget(self.peerInput)

        blacklistBtn = QPushButton("Blacklist Peer")
        blacklistBtn.clicked.connect(self.blacklistPeer)
        layout.addWidget(blacklistBtn)

        unblacklistBtn = QPushButton("Remove from Blacklist")
        unblacklistBtn.clicked.connect(self.unblacklistPeer)
        layout.addWidget(unblacklistBtn)

        viewBtn = QPushButton("View Blacklisted Peers")
        viewBtn.clicked.connect(self.viewBlacklist)
        layout.addWidget(viewBtn)

        self.setLayout(layout)

    def blacklistPeer(self):
        addr = self.peerInput.text().strip()
        if not addr:
            self.parent.appendOutput("❌ Please enter a peer address.")
            return
        cmd = f"/root/AlynCoin/build/alyncoin-cli blacklist-add {addr}"
        self.parent.appendOutput(self.parent.runCommand(cmd))

    def unblacklistPeer(self):
        addr = self.peerInput.text().strip()
        if not addr:
            self.parent.appendOutput("❌ Please enter a peer address.")
            return
        cmd = f"/root/AlynCoin/build/alyncoin-cli blacklist-remove {addr}"
        self.parent.appendOutput(self.parent.runCommand(cmd))

    def viewBlacklist(self):
        cmd = "/root/AlynCoin/build/alyncoin-cli blacklist-view"
        self.parent.appendOutput(self.parent.runCommand(cmd))
