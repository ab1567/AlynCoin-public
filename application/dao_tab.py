import requests
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout, QDialog,
    QFormLayout, QLineEdit, QComboBox, QDialogButtonBox, QTextEdit
)
from PyQt5.QtCore import Qt

def alyncoin_rpc(method, params=None):
    url = "http://127.0.0.1:1567/rpc"
    headers = {"Content-Type": "application/json"}
    body = {"method": method, "params": params or []}
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise Exception(data["error"])
        return data.get("result", None)
    except Exception as e:
        return {"error": str(e)}

class DAOTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        btnLayout = QHBoxLayout()

        submitBtn = QPushButton("📄 Submit Proposal")
        submitBtn.clicked.connect(self.submitProposal)
        btnLayout.addWidget(submitBtn)

        voteBtn = QPushButton("🗳️ Vote on Proposal")
        voteBtn.clicked.connect(self.voteProposal)
        btnLayout.addWidget(voteBtn)

        viewBtn = QPushButton("📜 View All Proposals")
        viewBtn.clicked.connect(self.viewProposals)
        btnLayout.addWidget(viewBtn)

        layout.addLayout(btnLayout)
        self.setLayout(layout)

    def submitProposal(self):
        addr = getattr(self.parent, "loadedAddress", "")
        if not addr:
            self.parent.appendOutput("❌ Wallet not loaded.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("📄 Submit DAO Proposal")
        dialog.setMinimumWidth(500)
        form = QFormLayout(dialog)
        description = QTextEdit()
        description.setPlaceholderText("Enter your proposal description here...")
        description.setMinimumHeight(80)
        form.addRow("📝 Description:", description)

        proposalType = QComboBox()
        proposalType.addItems(["Protocol Upgrade", "Fund Allocation", "Blacklist Appeal", "Custom Action"])
        form.addRow("📌 Proposal Type:", proposalType)

        amountField = QLineEdit()
        amountField.setPlaceholderText("Only for Fund Allocation")
        form.addRow("💸 Amount:", amountField)

        targetField = QLineEdit()
        targetField.setPlaceholderText("Only for Fund Allocation")
        form.addRow("🎯 Target Address:", targetField)

        def updateVisibility(index):
            isFund = proposalType.currentText() == "Fund Allocation"
            amountField.setVisible(isFund)
            targetField.setVisible(isFund)
            form.labelForField(amountField).setVisible(isFund)
            form.labelForField(targetField).setVisible(isFund)

        proposalType.currentIndexChanged.connect(updateVisibility)
        updateVisibility(proposalType.currentIndex())

        buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttonBox.accepted.connect(dialog.accept)
        buttonBox.rejected.connect(dialog.reject)
        form.addRow(buttonBox)

        if dialog.exec_():
            desc_val = description.toPlainText().strip()
            ptype_val = proposalType.currentIndex()
            if not desc_val:
                self.parent.appendOutput("❌ Proposal description is required.")
                return

            if ptype_val == 1:
                amount_val = amountField.text().strip()
                target_val = targetField.text().strip()
                if not amount_val or not target_val:
                    self.parent.appendOutput("❌ Fund Allocation requires amount and target address.")
                    return
                params = [addr, desc_val, ptype_val, amount_val, target_val]
            else:
                params = [addr, desc_val, ptype_val]

            result = alyncoin_rpc("dao_submit", params)
            if isinstance(result, dict) and "error" in result:
                self.parent.appendOutput(f"❌ {result['error']}")
            else:
                self.parent.appendOutput(f"✅ Proposal submitted.\n{result}")

    def voteProposal(self):
        addr = getattr(self.parent, "loadedAddress", "")
        if not addr:
            self.parent.appendOutput("❌ Wallet not loaded.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("🗳️ Vote on DAO Proposal")
        dialog.setMinimumWidth(400)
        form = QFormLayout(dialog)
        proposalID = QLineEdit()
        proposalID.setPlaceholderText("Enter Proposal ID (from View All)")
        form.addRow("📜 Proposal ID:", proposalID)

        voteChoice = QComboBox()
        voteChoice.addItems(["YES", "NO"])
        form.addRow("✅ Your Vote:", voteChoice)

        buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttonBox.accepted.connect(dialog.accept)
        buttonBox.rejected.connect(dialog.reject)
        form.addRow(buttonBox)

        if dialog.exec_():
            pid = proposalID.text().strip()
            vote = voteChoice.currentText()
            if not pid:
                self.parent.appendOutput("❌ Proposal ID is required.")
                return
            params = [addr, pid, vote]
            result = alyncoin_rpc("dao_vote", params)
            if isinstance(result, dict) and "error" in result:
                self.parent.appendOutput(f"❌ {result['error']}")
            else:
                self.parent.appendOutput(f"✅ Vote submitted.\n{result}")
            self.viewProposals()

    def viewProposals(self):
        self.parent.clearOutput()
        self.parent.appendOutput("📜 Fetching all DAO proposals...")
        result = alyncoin_rpc("dao_view")
        if isinstance(result, dict) and "error" in result:
            self.parent.appendOutput(f"❌ {result['error']}")
            return
        proposals = result if isinstance(result, list) else []
        status_map = {0: "Pending", 1: "Approved", 2: "Rejected", 3: "Expired"}
        for p in proposals:
            self.parent.appendOutput(
                f"\n🆔 Proposal ID: {p.get('id')}\n"
                f"📝 {p.get('desc')}\n"
                f"📌 Type: {p.get('type')}\n"
                f"📌 Status: {status_map.get(p.get('status', 0), 'Unknown')}\n"
                f"✅ YES: {p.get('yes_votes',0):,} | ❌ NO: {p.get('no_votes',0):,}\n"
                f"By: {p.get('creator')}\n"
                f"---"
            )
        if not proposals:
            self.parent.appendOutput("⚠️ No proposals found.")
        else:
            self.parent.appendOutput(f"✅ {len(proposals)} proposals listed.")

