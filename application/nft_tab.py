import os
import hashlib
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QHBoxLayout, QDialog,
    QFormLayout, QLineEdit, QDialogButtonBox, QFileDialog
)

from rpc_client import alyncoin_rpc, RpcClientError, RpcNotReady, RpcError
from wallet_utils import ensure_wallet_ready

class NFTTab(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.initUI()
        if hasattr(parent, "walletChanged"):
            parent.walletChanged.connect(self.onWalletChanged)

    def initUI(self):
        layout = QVBoxLayout()
        row1 = QHBoxLayout()
        row2 = QHBoxLayout()
        row3 = QHBoxLayout()
        self.addButton("🎨 Mint NFT", self.mintNFT, row1)
        self.addButton("📁 Media → NFT", self.mintMediaNFT, row1)
        self.addButton("📂 Verify Media", self.verifyMedia, row1)
        self.addButton("🔁 Transfer NFT", self.transferNFT, row1)
        self.addButton("🖼️ View My NFTs", self.viewMyNFTs, row2)
        self.addButton("🛠️ Re-Mint NFT", self.remintNFT, row2)
        self.addButton("💾 Export NFT", self.exportNFT, row2)
        self.addButton("📊 NFT Stats", self.showStats, row3)
        self.addButton("🔐 Encrypt Metadata", self.encryptMetadata, row3)
        self.addButton("🔓 Decrypt Metadata", self.decryptMetadata, row3)
        layout.addLayout(row1)
        layout.addLayout(row2)
        layout.addLayout(row3)
        self.setLayout(layout)

    def addButton(self, label, callback, layout):
        btn = QPushButton(label)
        btn.clicked.connect(callback)
        layout.addWidget(btn)

    def _require_wallet(self):
        addr = getattr(self.parent, "loadedAddress", "")
        key_id = getattr(self.parent, "loadedKeyId", "")
        if not addr:
            self.parent.appendOutput("❌ Wallet not loaded.")
            return None
        ok, msg = ensure_wallet_ready(addr, key_id)
        if not ok:
            self.parent.appendOutput(f"❌ {msg}")
            return None
        return addr, key_id

    def _call_rpc(self, method, params=None, action="perform this action"):
        try:
            return alyncoin_rpc(method, params)
        except RpcNotReady as exc:
            self.parent.appendOutput(f"⚠️ Node RPC unavailable — unable to {action} right now. ({exc})")
        except RpcError as exc:
            self.parent.appendOutput(f"❌ RPC error: {exc}")
        except RpcClientError as exc:
            self.parent.appendOutput(f"❌ Failed to {action}: {exc}")
        return None

    def showResult(self, result):
        if isinstance(result, dict) and "error" in result:
            self.parent.appendOutput(f"❌ {result['error']}")
        elif isinstance(result, (dict, list)):
            self.parent.appendOutput(str(result))
        elif isinstance(result, str):
            self.parent.appendOutput(result)
        else:
            self.parent.appendOutput("❌ Unknown response from RPC.")

    # ----- NFT Actions -----
    def mintNFT(self):
        wallet = self._require_wallet()
        if not wallet:
            return
        addr, _ = wallet
        dialog = QDialog(self)
        dialog.setWindowTitle("🎨 Mint NFT")
        form = QFormLayout(dialog)
        meta = QLineEdit()
        meta.setPlaceholderText("Example: 'Artwork by Alyana'")
        image = QLineEdit()
        image.setPlaceholderText("SHA256 of image or content")
        identity = QLineEdit()
        identity.setPlaceholderText("Optional: Creator tag")
        form.addRow("📝 Metadata:", meta)
        form.addRow("🖼️ Image Hash:", image)
        form.addRow("👤 Identity:", identity)
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(dialog.accept)
        box.rejected.connect(dialog.reject)
        form.addRow(box)
        if dialog.exec_():
            m = meta.text().strip()
            i = image.text().strip()
            idt = identity.text().strip()
            if not m or not i:
                self.parent.appendOutput("❌ Metadata and Image Hash required.")
                return
            params = [addr, m, i]
            if idt: params.append(idt)
            result = self._call_rpc("nft-mint", params, action="mint NFT")
            self.showResult(result)

    def mintMediaNFT(self):
        wallet = self._require_wallet()
        if not wallet:
            return
        addr, _ = wallet
        filePath, _ = QFileDialog.getOpenFileName(self, "Select Media File")
        if not filePath:
            self.parent.appendOutput("❌ No file selected.")
            return
        try:
            with open(filePath, "rb") as f:
                content = f.read()
            sha256 = hashlib.sha256(content).hexdigest()
        except Exception as e:
            self.parent.appendOutput(f"❌ Failed to hash file: {str(e)}")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("🎨 Mint Media NFT")
        form = QFormLayout(dialog)
        meta = QLineEdit()
        meta.setPlaceholderText("Example: 'Photo of Moon'")
        identity = QLineEdit()
        identity.setPlaceholderText("Optional: Creator tag")
        form.addRow("📝 Metadata:", meta)
        form.addRow("👤 Identity:", identity)
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(dialog.accept)
        box.rejected.connect(dialog.reject)
        form.addRow(box)
        if dialog.exec_():
            m = meta.text().strip()
            idt = identity.text().strip()
            if not m:
                self.parent.appendOutput("❌ Metadata is required.")
                return
            params = [addr, m, sha256]
            if idt: params.append(idt)
            result = self._call_rpc("nft-mint", params, action="mint NFT")
            self.showResult(result)

    def verifyMedia(self):
        filePath, _ = QFileDialog.getOpenFileName(self, "Select File to Verify")
        if not filePath:
            self.parent.appendOutput("❌ No file selected.")
            return
        try:
            with open(filePath, "rb") as f:
                contents = f.read()
            file_hash = hashlib.sha256(contents).hexdigest()
        except Exception as e:
            self.parent.appendOutput(f"❌ Failed to hash file: {str(e)}")
            return
        result = self._call_rpc("nft-verifyhash", [filePath], action="verify NFT hash")
        self.showResult(result)

    def transferNFT(self):
        wallet = self._require_wallet()
        if not wallet:
            return
        addr, _ = wallet
        dialog = QDialog(self)
        dialog.setWindowTitle("🔁 Transfer NFT")
        form = QFormLayout(dialog)
        nftID = QLineEdit()
        newOwner = QLineEdit()
        nftID.setPlaceholderText("NFT ID to transfer")
        newOwner.setPlaceholderText("Recipient wallet address")
        form.addRow("🆔 NFT ID:", nftID)
        form.addRow("➡️ New Owner:", newOwner)
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(dialog.accept)
        box.rejected.connect(dialog.reject)
        form.addRow(box)
        if dialog.exec_():
            id = nftID.text().strip()
            owner = newOwner.text().strip()
            if not id or not owner:
                self.parent.appendOutput("❌ Both fields required.")
                return
            result = self._call_rpc("nft-transfer", [id, owner, addr], action="transfer NFT")
            self.showResult(result)

    def viewMyNFTs(self):
        wallet = self._require_wallet()
        if not wallet:
            return
        addr, _ = wallet
        result = self._call_rpc("nft-my", [addr], action="fetch NFTs")
        self.showResult(result)

    def remintNFT(self):
        wallet = self._require_wallet()
        if not wallet:
            return
        addr, _ = wallet
        dialog = QDialog(self)
        dialog.setWindowTitle("🛠️ Re-Mint NFT")
        form = QFormLayout(dialog)
        nftID = QLineEdit()
        newMeta = QLineEdit()
        reason = QLineEdit()
        nftID.setPlaceholderText("Existing NFT ID")
        newMeta.setPlaceholderText("New metadata (v2)")
        reason.setPlaceholderText("Why are you updating?")
        form.addRow("🆔 NFT ID:", nftID)
        form.addRow("🆕 New Metadata:", newMeta)
        form.addRow("📌 Reason:", reason)
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(dialog.accept)
        box.rejected.connect(dialog.reject)
        form.addRow(box)
        if dialog.exec_():
            id = nftID.text().strip()
            meta = newMeta.text().strip()
            why = reason.text().strip()
            if not id or not meta or not why:
                self.parent.appendOutput("❌ All fields required.")
                return
            result = self._call_rpc("nft-remint", [id, meta, why, addr], action="re-mint NFT")
            self.showResult(result)

    def exportNFT(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("💾 Export NFT")
        form = QFormLayout(dialog)
        nftID = QLineEdit()
        nftID.setPlaceholderText("NFT ID to export")
        form.addRow("🆔 NFT ID:", nftID)
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(dialog.accept)
        box.rejected.connect(dialog.reject)
        form.addRow(box)
        if dialog.exec_():
            id = nftID.text().strip()
            if not id:
                self.parent.appendOutput("❌ NFT ID is required.")
                return
            result = self._call_rpc("nft-export", [id], action="export NFT")
            self.showResult(result)

    def showStats(self):
        result = self._call_rpc("nft-stats", action="fetch NFT stats")
        self.showResult(result)

    def encryptMetadata(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("🔐 Encrypt Metadata")
        form = QFormLayout(dialog)
        nftID = QLineEdit()
        data = QLineEdit()
        pw = QLineEdit()
        pw.setEchoMode(QLineEdit.Password)
        nftID.setPlaceholderText("NFT ID")
        data.setPlaceholderText("Metadata to encrypt")
        pw.setPlaceholderText("Password")
        form.addRow("🆔 NFT ID:", nftID)
        form.addRow("🔒 Metadata:", data)
        form.addRow("🔑 Password:", pw)
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(dialog.accept)
        box.rejected.connect(dialog.reject)
        form.addRow(box)
        if dialog.exec_():
            id = nftID.text().strip()
            d = data.text().strip()
            p = pw.text().strip()
            if not id or not d or not p:
                self.parent.appendOutput("❌ All fields required.")
                return
            result = self._call_rpc("nft-encrypt", [id, d, p], action="encrypt metadata")
            self.showResult(result)

    def decryptMetadata(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("🔓 Decrypt Metadata")
        form = QFormLayout(dialog)
        nftID = QLineEdit()
        pw = QLineEdit()
        pw.setEchoMode(QLineEdit.Password)
        nftID.setPlaceholderText("NFT ID")
        pw.setPlaceholderText("Password")
        form.addRow("🆔 NFT ID:", nftID)
        form.addRow("🔑 Password:", pw)
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(dialog.accept)
        box.rejected.connect(dialog.reject)
        form.addRow(box)
        if dialog.exec_():
            id = nftID.text().strip()
            p = pw.text().strip()
            if not id or not p:
                self.parent.appendOutput("❌ All fields required.")
                return
            result = self._call_rpc("nft-decrypt", [id, p], action="decrypt metadata")
            self.showResult(result)

    def onWalletChanged(self, address):
        pass
