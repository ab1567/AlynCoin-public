import os
import re
import csv
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog,
    QLabel, QLineEdit, QDateEdit, QGroupBox, QGridLayout
)
from PyQt5.QtCore import QDate

from rpc_client import alyncoin_rpc, RpcClientError, RpcNotReady, RpcError
from wallet_utils import ensure_wallet_ready

class HistoryTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main = parent
        self.parsed_transactions = []
        self.filtered_transactions = []
        self.proof_path = ""
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        filter_group = QGroupBox("🔎 Filter Options")
        filter_layout = QGridLayout()
        filter_layout.addWidget(QLabel("📅 From Date:"), 0, 0)
        self.fromDate = QDateEdit(calendarPopup=True)
        self.fromDate.setDate(QDate.currentDate().addMonths(-1))
        filter_layout.addWidget(self.fromDate, 0, 1)
        filter_layout.addWidget(QLabel("📅 To Date:"), 0, 2)
        self.toDate = QDateEdit(calendarPopup=True)
        self.toDate.setDate(QDate.currentDate())
        filter_layout.addWidget(self.toDate, 0, 3)
        filter_layout.addWidget(QLabel("💰 Min Amount:"), 1, 0)
        self.minAmount = QLineEdit()
        filter_layout.addWidget(self.minAmount, 1, 1)
        filter_layout.addWidget(QLabel("💰 Max Amount:"), 1, 2)
        self.maxAmount = QLineEdit()
        filter_layout.addWidget(self.maxAmount, 1, 3)
        self.filterBtn = QPushButton("Apply Filters")
        self.filterBtn.setFixedHeight(28)
        self.filterBtn.clicked.connect(self.applyFilters)
        filter_layout.addWidget(self.filterBtn, 2, 0, 1, 4)
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        self.fetchBtn = QPushButton("📜 Load Transaction History")
        self.fetchBtn.setFixedHeight(32)
        self.fetchBtn.clicked.connect(self.fetchHistory)
        layout.addWidget(self.fetchBtn)
        self.exportBtn = QPushButton("📁 Export Filtered to CSV")
        self.exportBtn.setFixedHeight(32)
        self.exportBtn.clicked.connect(self.exportToCSV)
        self.exportBtn.setEnabled(False)
        layout.addWidget(self.exportBtn)
        self.proofBtn = QPushButton("🧠 Generate zk-STARK Proof (Filtered)")
        self.proofBtn.setFixedHeight(32)
        self.proofBtn.clicked.connect(self.generateProof)
        self.proofBtn.setEnabled(False)
        layout.addWidget(self.proofBtn)
        self.setLayout(layout)

    def _require_wallet(self):
        address = self.main.get_wallet_address()
        key_id = self.main.get_wallet_key_id() if hasattr(self.main, "get_wallet_key_id") else ""
        if not address:
            self.appendText("❌ Please load a wallet first.")
            return None
        ok, msg = ensure_wallet_ready(address, key_id)
        if not ok:
            self.appendText(f"❌ {msg}")
            return None
        return address

    def _safe_rpc(self, method, params=None, action="perform this action"):
        try:
            return alyncoin_rpc(method, params)
        except RpcNotReady as exc:
            self.appendText(f"⚠️ Node RPC unavailable — unable to {action}. ({exc})")
        except RpcError as exc:
            self.appendText(f"❌ RPC error while attempting to {action}: {exc}")
        except RpcClientError as exc:
            self.appendText(f"❌ Failed to {action}: {exc}")
        return None

    def fetchHistory(self):
        address = self._require_wallet()
        if not address:
            return
        self.appendText("⏳ Fetching transaction history...")
        self.fetchBtn.setEnabled(False)
        self.exportBtn.setEnabled(False)
        self.proofBtn.setEnabled(False)
        self.parsed_transactions.clear()

        result = self._safe_rpc("history", [address], action="fetch transaction history")
        if result is None:
            self.fetchBtn.setEnabled(True)
            return
        if isinstance(result, dict) and "error" in result:
            self.appendText(f"❌ {result['error']}")
            self.fetchBtn.setEnabled(True)
            return

        txs = result if isinstance(result, list) else []
        # Ensure all txs have required fields
        parsed_txs = []
        for tx in txs:
            try:
                # rpc returns: timestamp(int), from, to, amount, metadata, hash, type
                ts = tx.get('timestamp', tx.get('time'))
                if ts:
                    try:
                        ts = int(ts)
                        tstamp = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        tstamp = str(ts)
                else:
                    tstamp = ''

                from_ = tx.get('from', '')
                to_ = tx.get('to', '')
                amt = tx.get('amount', '')
                meta = tx.get('metadata', tx.get('meta', ''))
                hash_ = tx.get('hash', '')
                typ = tx.get('type', '')
                if tstamp and amt and hash_:
                    parsed_txs.append(
                        (
                            tstamp,
                            from_,
                            to_,
                            amt,
                            meta,
                            hash_,
                            typ,
                        )
                    )
            except Exception:
                continue
        # Consolidate mining reward duplicates ("L1" + "Mined")
        unique = []
        reward_map = {}
        for tx in parsed_txs:
            ts, frm, to_, amt, meta, hsh, typ = tx
            if str(meta).lower() == "miningreward":
                key = (ts, to_.lower(), str(amt))
                if key in reward_map:
                    idx = reward_map[key]
                    existing = unique[idx]
                    if existing[6] == "L1" and typ == "Mined":
                        unique[idx] = tx
                    continue
                reward_map[key] = len(unique)
            unique.append(tx)

        self.parsed_transactions = unique
        self.fetchBtn.setEnabled(True)
        self.applyFilters()

    def applyFilters(self):
        self.filtered_transactions.clear()
        date_from = self.fromDate.date().toPyDate()
        date_to = self.toDate.date().toPyDate()
        try:
            min_amt = float(self.minAmount.text() or 0)
        except Exception:
            min_amt = 0
        try:
            max_amt = float(self.maxAmount.text() or 999999999)
        except Exception:
            max_amt = 999999999
        for tx in self.parsed_transactions:
            try:
                tx_date = datetime.strptime(tx[0], "%Y-%m-%d %H:%M:%S").date()
                amt = float(tx[3])
                if date_from <= tx_date <= date_to and min_amt <= amt <= max_amt:
                    self.filtered_transactions.append(tx)
            except Exception:
                continue
        self.main.outputBox.clear()
        for tx in self.filtered_transactions:
            self.appendText(
                f"🕒 {tx[0]} [{tx[6]}]\nFrom: {tx[1]}\nTo: {tx[2]}\n💰 Amount: {tx[3]} AlynCoin\n📎 Metadata: {tx[4]}\n🔑 TxHash: {tx[5]}\n---")
        if self.filtered_transactions:
            self.exportBtn.setEnabled(True)
            self.proofBtn.setEnabled(True)
            self.appendText(f"✅ Showing {len(self.filtered_transactions)} filtered transaction(s).")
        else:
            self.appendText("⚠️ No transactions match your filters.")

    def exportToCSV(self):
        if not self.filtered_transactions:
            self.appendText("⚠️ Apply filters before exporting.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save CSV", os.path.expanduser("~/alyncoin_filtered.csv"), "CSV Files (*.csv)")
        if not file_path:
            return
        try:
            with open(file_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "From", "To", "Amount", "Metadata", "Transaction Hash"])
                for row in self.filtered_transactions:
                    writer.writerow(row[:6])
            self.appendText(f"✅ Exported to: {file_path}")
        except Exception as e:
            self.appendText(f"❌ Export failed: {str(e)}")

    def generateProof(self):
        address = self._require_wallet()
        if not address:
            return
        if not self.filtered_transactions:
            self.appendText("⚠️ Apply filters to select transactions for proof.")
            return
        tx_count = len(self.filtered_transactions)
        self.appendText(f"🔐 Generating zk-STARK proof for {tx_count} filtered transaction(s)...")
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save zk-STARK Proof", os.path.expanduser("~/recursive_filtered_proof.json"), "JSON Files (*.json)"
        )
        if not file_path:
            self.appendText("⚠️ Proof generation canceled.")
            return
        if not file_path.lower().endswith(".json"):
            file_path += ".json"
        self.proof_path = file_path

        result = self._safe_rpc("recursiveproof", [address, tx_count], action="generate zk proof")
        if result is None:
            return
        if isinstance(result, dict) and "error" in result:
            self.appendText(f"❌ {result['error']}")
            return
        try:
            with open(file_path, "w") as f:
                f.write(result if isinstance(result, str) else str(result))
            self.appendText(f"📁 Proof file saved to: {file_path}")
        except Exception as e:
            self.appendText(f"❌ Could not save proof: {e}")

    def appendText(self, text):
        self.main.outputBox.append(text)
        # Scroll to bottom
        try:
            sb = self.main.outputBox.verticalScrollBar()
            sb.setValue(sb.maximum())
        except Exception:
            pass
