import sys
import os
import socket
import subprocess
import time
import platform
import dns.resolver

from rpc_client import alyncoin_rpc, RPC_HOST, RPC_PORT

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QTextEdit, QVBoxLayout,
    QWidget, QLabel, QMessageBox, QFileDialog
)
from PyQt5.QtGui import QIcon, QFont, QPixmap
from PyQt5.QtCore import Qt, pyqtSlot, pyqtSignal

from wallet_tab import WalletTab
from send_tab import SendTab
from history_tab import HistoryTab
from miner_tab import MinerTab
from dao_tab import DAOTab
from stats_tab import StatsTab
from nft_tab import NFTTab

# Fallback peer(s) if DNS resolution fails
# Must mirror the list in src/network.cpp
DEFAULT_DNS_PEERS = [
    "49.206.56.213:15672",
    "35.209.49.156:15671",
]


# ---- DNS Peer Resolver (returns ALL peers) ----
def get_peers_from_dns():
    peers = []
    try:
        answers = dns.resolver.resolve("peers.alyncoin.com", "TXT", lifetime=3)
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            for peer in txt.split(","):
                peer = peer.strip()
                if ":" in peer and peer not in peers:
                    peers.append(peer)
    except Exception as e:
        print(f"[WARN] DNS peer resolution failed: {e}")
    if not peers:
        peers = DEFAULT_DNS_PEERS
    return peers

def is_alyncoin_dns_accessible():
    try:
        answers = dns.resolver.resolve("peers.alyncoin.com", "TXT", lifetime=3)
        return any(answers)
    except Exception:
        # Consider reachable if fallback peers are available
        return bool(DEFAULT_DNS_PEERS)

# ---- Node Launch/Detect Helpers ----
def is_rpc_up(host=RPC_HOST, port=RPC_PORT):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except Exception:
        return False

def ensure_alyncoin_node(block=True):
    if is_rpc_up():
        return True  # Node already running

    # If RPC host is remote, don't attempt to launch local node
    if RPC_HOST not in ("127.0.0.1", "localhost"):
        print(f"🔌 Remote RPC {RPC_HOST}:{RPC_PORT} unreachable.")
        return False

    exe_dir = os.path.dirname(sys.executable if hasattr(sys, 'frozen') else os.path.abspath(__file__))
    candidates = [
        os.path.join(exe_dir, "alyncoin"),
        os.path.join(exe_dir, "alyncoin", "alyncoin"),
        os.path.join(exe_dir, "build", "alyncoin")
    ]
    if platform.system() == "Windows":
        candidates.extend([
            os.path.join(exe_dir, "alyncoin.exe"),
            os.path.join(exe_dir, "alyncoin", "alyncoin.exe"),
            os.path.join(exe_dir, "build", "alyncoin.exe"),
        ])
    bin_path = None
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            bin_path = c
            break
    if not bin_path:
        print("❌ Could not find 'alyncoin' node binary. Please ensure it's in the same folder or in 'build'.")
        return False

    # Check for missing shared library dependencies on Linux where ldd is available
    if platform.system() == "Linux":
        try:
            ldd_output = subprocess.check_output(["ldd", bin_path], text=True)
            missing = [line.strip() for line in ldd_output.splitlines() if "not found" in line]
            if missing:
                print("❌ Missing shared libraries for 'alyncoin':")
                for m in missing:
                    print("   ", m)
                print("Please install the required libraries (e.g. RocksDB) and try again.")
                return False
        except FileNotFoundError:
            print("⚠️ 'ldd' not found; skipping shared library check")
        except Exception as e:
            print(f"⚠️ Could not verify shared libraries: {e}")
    log_path = os.path.join(os.path.dirname(bin_path), "alyncoin_node.log")
    log_file = open(log_path, "a")

    if platform.system() == "Windows":
        vbs_path = os.path.join(os.path.dirname(bin_path), "launch_alyncoin_wsl.vbs")
        if os.path.exists(vbs_path):
            try:
                subprocess.Popen(
                    ["wscript", vbs_path],
                    stdout=log_file, stderr=log_file, stdin=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )
                print(f"🚀 Launched WSL node via launch_alyncoin_wsl.vbs (log: {log_path})")
            except Exception as e:
                print(f"❌ Failed to launch node via VBS: {e}")
                log_file.close()
                return False
        else:
            print(f"❌ launch_alyncoin_wsl.vbs not found in {os.path.dirname(bin_path)}")
            log_file.close()
            return False

    else:
        # Linux/macOS launch
        try:
            p = subprocess.Popen(
                [bin_path],
                stdout=log_file, stderr=log_file, stdin=subprocess.DEVNULL,
                close_fds=True, start_new_session=True
            )
            print(f"🚀 Launched node: {bin_path} (PID={p.pid}, log: {log_path})")
        except Exception as e:
            print(f"❌ Failed to launch node: {e}")
            log_file.close()
            return False

    if block:
        for _ in range(40):  # up to 20 seconds
            if is_rpc_up():
                log_file.close()
                return True
            time.sleep(0.5)
        print("❌ Node RPC did not become available after launch.")
        log_file.close()
        return False
    log_file.close()
    return True

# ---- PyInstaller Resource Path Helper ----
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def get_logo_path():
    candidates = [
        os.path.join(os.getcwd(), "logo.png"),
        os.path.join(os.path.dirname(sys.argv[0]), "logo.png"),
        resource_path("logo.png"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None

class AlynCoinApp(QMainWindow):
    walletChanged = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AlynCoin Wallet & Miner")
        self.setGeometry(200, 100, 720, 600)
        self.loadedAddress = ""
        self.miningActive = False

        # -- Use all discovered DNS peers
        self.dns_peers = get_peers_from_dns()
        self.initUI(get_logo_path())
        self.applyDarkTheme()

    def initUI(self, logo_path=None):
        centralWidget = QWidget()
        self.setCentralWidget(centralWidget)
        layout = QVBoxLayout()

        logoLabel = QLabel()
        if logo_path:
            pixmap = QPixmap(logo_path)
            if not pixmap.isNull():
                logoLabel.setPixmap(pixmap.scaled(120, 120, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            logoLabel.setText("AlynCoin")
            logoLabel.setFont(QFont("Segoe UI", 22, QFont.Bold))
        logoLabel.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
        layout.addWidget(logoLabel)

        # No DNS/peer addresses are shown for security
        if is_alyncoin_dns_accessible():
            peer_status = "🌐 AlynCoin Network: Online"
            color = "#44e"
        else:
            peer_status = "🌐 AlynCoin Network: Offline"
            color = "#f44"
        self.peerBanner = QLabel(peer_status)
        self.peerBanner.setAlignment(Qt.AlignCenter)
        self.peerBanner.setStyleSheet(f"background-color: #191919; color: {color}; padding: 4px; font-weight: bold;")
        layout.addWidget(self.peerBanner)

        self.statusBanner = QLabel("⚠️ Only one blockchain action can run at a time. Mining locks access.")
        self.statusBanner.setAlignment(Qt.AlignCenter)
        self.statusBanner.setStyleSheet("background-color: #222; color: #ffaa00; padding: 6px; font-weight: bold;")
        layout.addWidget(self.statusBanner)

        self.tabs = QTabWidget()
        self.outputBox = QTextEdit()
        self.outputBox.setReadOnly(True)
        self.outputBox.setFont(QFont("Consolas", 10))

        self.walletTab = WalletTab(self)
        self.sendTab = SendTab(self)
        self.historyTab = HistoryTab(self)
        self.minerTab = MinerTab(self.get_wallet_address, self)
        self.daoTab = DAOTab(self)
        self.statsTab = StatsTab(self)
        self.nftTab = NFTTab(self)

        self.tabs.addTab(self.walletTab, "Wallet")
        self.tabs.addTab(self.sendTab, "Send")
        self.tabs.addTab(self.historyTab, "History")
        self.tabs.addTab(self.minerTab, "Miner")
        self.tabs.addTab(self.daoTab, "DAO")
        self.tabs.addTab(self.statsTab, "Stats")
        self.tabs.addTab(self.nftTab, "NFT")

        layout.addWidget(self.tabs)
        layout.addWidget(self.outputBox)
        centralWidget.setLayout(layout)

        self.walletChanged.connect(self.sendTab.onWalletChanged)
        self.walletChanged.connect(self.minerTab.onWalletChanged)
        self.walletChanged.connect(self.statsTab.onWalletChanged)
        self.walletChanged.connect(self.nftTab.onWalletChanged)

    @pyqtSlot(str)
    def appendOutput(self, text):
        self.outputBox.append(text)

    def clearOutput(self):
        self.outputBox.clear()

    def get_wallet_address(self):
        return self.loadedAddress if self.loadedAddress else ""

    def set_wallet_address(self, addr):
        self.loadedAddress = addr
        self.walletChanged.emit(addr)

    def applyDarkTheme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0d0d0d;
                color: #eeeeee;
                font-family: "Segoe UI", sans-serif;
                font-size: 14px;
            }
            QLabel {
                color: #eeeeee;
                font-weight: 500;
                font-size: 14px;
            }
            QPushButton {
                background-color: #222222;
                color: #ffffff;
                border-radius: 8px;
                padding: 6px 14px;
                border: 1px solid #444444;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #333333;
                border: 1px solid #00ffcc;
                color: #00ffcc;
            }
            QLineEdit, QComboBox {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #444444;
                border-radius: 6px;
                padding: 6px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #00ffcc;
                background-color: #1e1e1e;
                color: #00ffcc;
            }
            QTextEdit {
                background-color: #121212;
                color: #00ffcc;
                border: 1px solid #444444;
                border-radius: 6px;
                padding: 8px;
                font-family: Consolas, monospace;
                font-size: 13px;
            }
            QTabWidget::pane {
                border: 1px solid #444444;
                top: -1px;
                background-color: #101010;
            }
            QTabBar::tab {
                background: #202020;
                border: 1px solid #444;
                border-bottom: none;
                padding: 8px 18px;
                color: #cccccc;
                font-weight: 500;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background: #2a2a2a;
                color: #ffffff;
                border: 1px solid #00ffcc;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background: #333333;
                color: #00ffcc;
                border: 1px solid #00cc99;
            }
            QScrollBar:vertical {
                background: #1a1a1a;
                width: 10px;
                margin: 0px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #444444;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background: #00ffcc;
            }
        """)

    def updateStatusBanner(self, text, color="#ffaa00"):
        self.statusBanner.setText(text)
        self.statusBanner.setStyleSheet(
            f"background-color: #222; color: {color}; padding: 6px; font-weight: bold;"
        )

    def showSuccess(self, msg):
        self.updateStatusBanner(msg, "#22dd55")

    def showError(self, msg):
        self.updateStatusBanner(msg, "#ff4444")

    def lockUI(self):
        self.tabs.setEnabled(False)
        self.miningActive = True
        self.updateStatusBanner("⛏️ Mining in progress... Please wait.", "#ffaa00")

    def unlockUI(self):
        self.tabs.setEnabled(True)
        self.miningActive = False
        self.updateStatusBanner("✅ Ready.", "#22dd55")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # --- Try to launch the background node ---
    if not ensure_alyncoin_node():
        QMessageBox.critical(None, "AlynCoin Node Missing",
                             "Could not start AlynCoin node process.\nMake sure 'alyncoin' is in the same folder.")
        sys.exit(1)
    # --- DNS requirement ---
    if not is_alyncoin_dns_accessible():
        msg = (
            "🛑 Cannot reach AlynCoin peer DNS (peers.alyncoin.com).\n"
            "Please contact alyncoin.com"
        )
        QMessageBox.critical(None, "DNS Unreachable", msg)
        sys.exit(1)

    sync_info = alyncoin_rpc("syncstatus")
    if not isinstance(sync_info, dict) or not sync_info.get("synced", False):
        QMessageBox.critical(None, "Node Sync", "Local node is not synced.\nPlease contact alyncoin.com")
        sys.exit(1)
    window = AlynCoinApp()
    window.show()
    sys.exit(app.exec_())
