from __future__ import annotations

import sys
import os
import socket
import subprocess
import threading
import time
import platform
import shutil
from typing import Optional

# ``requests`` is optional on macOS; fall back to ``urllib`` if it's missing
try:  # pragma: no cover - simple import guard
    import requests  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    import urllib.request

    class _SimpleResponse:
        def __init__(self, resp: urllib.request.addinfourl):
            self.text = resp.read().decode("utf-8", errors="ignore")
            self.status_code = resp.getcode() or 0

    class _SimpleRequests:
        @staticmethod
        def get(url: str, timeout: int = 2) -> _SimpleResponse:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                return _SimpleResponse(resp)

    requests = _SimpleRequests()  # type: ignore
try:
    import dns.resolver
except Exception as e:
    dns = None
    print(f"[WARN] dnspython unavailable: {e}; using fallback peers only")

from rpc_client import (
    alyncoin_rpc,
    RPC_HOST,
    RPC_PORT,
    wait_for_rpc_ready,
    fetch_peer_status,
)

def resource_path(filename):
    """Return path to resource bundled by PyInstaller or next to the script."""
    try:
        base = sys._MEIPASS
    except AttributeError:
        base = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base, filename)

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QTabWidget, QTextEdit, QVBoxLayout,
        QWidget, QLabel, QMessageBox, QFileDialog
    )
    from PyQt5.QtGui import QIcon, QFont, QPixmap
    from PyQt5.QtCore import Qt, pyqtSlot, pyqtSignal, QTimer
    from PyQt5.QtNetwork import QLocalServer, QLocalSocket
except ModuleNotFoundError as exc:  # pragma: no cover - guard for missing GUI deps
    missing = exc.name or "PyQt5"
    print(
        f"❌ Required dependency '{missing}' is not installed.\n"
        "   Install the desktop UI requirements with\n"
        "   `python -m pip install -r requirements.txt` from the `application` directory.",
        file=sys.stderr,
    )
    sys.exit(1)

from wallet_tab import WalletTab
from send_tab import SendTab
from history_tab import HistoryTab
from miner_tab import MinerTab
from dao_tab import DAOTab
from stats_tab import StatsTab
from nft_tab import NFTTab
from swap_tab import SwapTab

_singleton_server: Optional[QLocalServer] = None

def acquire_single_instance(name: str) -> bool:
    sock = QLocalSocket()
    sock.connectToServer(name)
    if sock.waitForConnected(100):
        sock.close()
        return False
    try:
        QLocalServer.removeServer(name)
    except Exception:
        pass
    global _singleton_server
    _singleton_server = QLocalServer()
    if not _singleton_server.listen(name):
        QLocalServer.removeServer(name)
        if not _singleton_server.listen(name):
            return False
    return True

# Fallback peer if DNS resolution fails. This mirrors the seed in
# src/network.cpp but avoids embedding a fixed IP so DNS changes
# propagate automatically.
DEFAULT_DNS_PEERS = [
    "peers.alyncoin.com:15671",
]

# Keep track of the launched node process so we can terminate it on exit
node_process = None

# ---- DNS Peer Resolver (returns ALL peers) ----
def get_peers_from_dns():
    peers = []
    if dns is not None:
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
    if dns is None:
        return bool(DEFAULT_DNS_PEERS)
    try:
        answers = dns.resolver.resolve("peers.alyncoin.com", "TXT", lifetime=3)
        return any(answers)
    except Exception:
        return bool(DEFAULT_DNS_PEERS)

def get_peer_count():
    """Return the current number of connected peers via the metrics endpoint."""
    url = f"http://{RPC_HOST}:{RPC_PORT}/metrics"
    try:
        resp = requests.get(url, timeout=2)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if line.startswith("peer_count"):
                    parts = line.split()
                    if len(parts) == 2:
                        return int(float(parts[1]))
    except Exception as e:
        print(f"[WARN] Unable to fetch peer count: {e}")
    return 0


def rpc_peer_status():
    """Return connection status via RPC or ``None`` when unavailable."""

    try:
        status = fetch_peer_status()
    except RuntimeError as e:
        print(f"⚠️  RPC 'peerstatus' failed: {e}")
        return None

    return status

# ---- Data Directory Helpers ----
def ensure_blockchain_db_dir():
    """Create the RocksDB directory if it doesn't exist."""
    db_path = os.environ.get(
        "ALYNCOIN_BLOCKCHAIN_DB",
        os.path.expanduser("~/.alyncoin/blockchain_db")
    )
    try:
        os.makedirs(db_path, exist_ok=True)
    except Exception as e:
        print(f"❌ Failed to create blockchain DB directory '{db_path}': {e}")
        return False
    if not os.access(db_path, os.W_OK):
        print(f"❌ Blockchain DB directory '{db_path}' is not writable.")
        return False
    return True

# ---- Node Launch/Detect Helpers ----
def is_rpc_up(host=RPC_HOST, port=RPC_PORT):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except Exception:
        return False


def _read_magic(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(4)
    except Exception:
        return b""


def _bin_flavor(path: str) -> str:
    """Return 'win' if PE (MZ..), 'elf' if ELF, else 'unknown'."""
    m = _read_magic(path)
    if m.startswith(b"MZ"):
        return "win"
    if m.startswith(b"\x7fELF"):
        return "elf"
    return "unknown"


def _resource_dir() -> str:
    return os.path.dirname(sys.executable if hasattr(sys, "frozen") else os.path.abspath(__file__))


def _discover_node_binary() -> Optional[str]:
    """
    Find the node in common places. Accept both Windows and Linux binaries
    because Windows users may run the Linux binary via WSL.
    """
    cand = []

    # 1) explicit env
    env_bin = os.environ.get("ALYNCOIN_NODE")
    if env_bin:
        cand.append(env_bin)

    base = _resource_dir()                        # .../Contents/MacOS
    contents = os.path.abspath(os.path.join(base, '..'))
    # Prefer the known-good Frameworks placement
    cand += [
        os.path.join(contents, "Frameworks", "alyncoin"),
        os.path.join(contents, "Resources", "alyncoin"),
        os.path.join(base, "alyncoin"),
    ]

    # 2) next to app / packaged resource
    if platform.system() == "Windows":
        cand += [
            os.path.join(base, "alyncoin.exe"),
            os.path.join(base, "alyncoin"),
            resource_path("alyncoin.exe"),
            resource_path("alyncoin"),
        ]
    else:
        cand += [
            os.path.join(base, "alyncoin"),
            os.path.join(base, "alyncoin.exe"),
            resource_path("alyncoin"),
            resource_path("alyncoin.exe"),
        ]

    # 3) common subfolders
    if platform.system() == "Windows":
        cand += [
            os.path.join(base, "build", "alyncoin.exe"),
            os.path.join(base, "build", "alyncoin"),
            os.path.join(base, "alyncoin", "alyncoin.exe"),
            os.path.join(base, "alyncoin", "alyncoin"),
        ]
    else:
        cand += [
            os.path.join(base, "build", "alyncoin"),
            os.path.join(base, "build", "alyncoin.exe"),
            os.path.join(base, "alyncoin", "alyncoin"),
            os.path.join(base, "alyncoin", "alyncoin.exe"),
        ]

    # 4) PATH
    for name in ("alyncoin.exe" if platform.system() == "Windows" else "alyncoin", "alyncoin"):
        p = shutil.which(name)
        if p:
            cand.append(p)

    seen = set()
    for c in cand:
        if not c or c in seen:
            continue
        seen.add(c)
        try:
            if os.path.isfile(c):
                return c
        except Exception:
            pass
    return None


def windows_to_wsl_path(path: str) -> str:
    drive, rest = os.path.splitdrive(path)
    drive = drive.rstrip(":").lower()
    rest = rest.replace("\\", "/")
    return f"/mnt/{drive}{rest}"


def ensure_alyncoin_node(block: bool = True) -> bool:
    """
    Start the node if needed and wait for RPC. Supports:
    - Native Windows .exe
    - Linux ELF via WSL on Windows (explicit or auto-detected)
    - Native Linux / macOS
    """
    global node_process

    if is_rpc_up():
        return True
    if node_process and node_process.poll() is None:
        return True

    if not ensure_blockchain_db_dir():
        return False

    if RPC_HOST not in ("127.0.0.1", "localhost"):
        print(f"🔌 Remote RPC {RPC_HOST}:{RPC_PORT} unreachable.")
        return False

    bin_path = _discover_node_binary()
    if not bin_path:
        print("❌ Could not find 'alyncoin' node binary.\n"
              "   Put 'alyncoin(.exe)' next to the app or in 'build', set ALYNCOIN_NODE, or place it on PATH.")
        return False

    flavor = _bin_flavor(bin_path)  # 'win', 'elf', or 'unknown'
    use_wsl = os.environ.get("ALYNCOIN_USE_WSL", "0") == "1"
    log_file = open(os.devnull, "w")

    try:
        if platform.system() == "Windows":
            if flavor == "win" and bin_path.lower().endswith(".exe") and not use_wsl:
                # Native Windows exe
                flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
                node_process = subprocess.Popen(
                    [bin_path],
                    stdout=log_file, stderr=log_file, stdin=subprocess.DEVNULL,
                    creationflags=flags
                )
                print(f"🚀 Launched node: {bin_path} (PID={node_process.pid})")
            else:
                # Linux ELF or forced WSL
                distro = os.environ.get("ALYNCOIN_WSL_DISTRO", "Ubuntu")
                workdir = windows_to_wsl_path(os.path.dirname(bin_path))
                cmd = ["wsl", "-d", distro, "--cd", workdir, "--", "bash", "-lc", "chmod +x ./alyncoin || true && ./alyncoin"]
                node_process = subprocess.Popen(
                    cmd,
                    stdout=log_file, stderr=log_file, stdin=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
                )
                print(f"🚀 Launched WSL node ({distro}) from {workdir} (PID={node_process.pid})")
        else:
            # Linux/macOS
            if platform.system() == "Linux":
                try:
                    ldd_out = subprocess.check_output(["ldd", bin_path], text=True)
                    if any("not found" in ln for ln in ldd_out.splitlines()):
                        print("❌ Missing shared libraries for 'alyncoin'. Install RocksDB/libsodium etc. and try again.")
                        log_file.close()
                        return False
                except Exception:
                    pass
            node_process = subprocess.Popen(
                [bin_path],
                stdout=log_file, stderr=log_file, stdin=subprocess.DEVNULL,
                close_fds=True, start_new_session=True
            )
            print(f"🚀 Launched node: {bin_path} (PID={node_process.pid})")

    except Exception as e:
        if getattr(e, "winerror", None) == 193:
            print("❌ Tried to run a Linux binary natively on Windows.\n"
                  "   Provide alyncoin.exe or set ALYNCOIN_USE_WSL=1 to launch via WSL.")
        else:
            print(f"❌ Failed to launch node: {e}")
        log_file.close()
        return False

    if block:
        for _ in range(40):  # ~20s
            if is_rpc_up():
                log_file.close()
                return True
            time.sleep(0.5)
        print("❌ Node RPC did not become available after launch.")
        log_file.close()
        return False

    log_file.close()
    return True


def terminate_alyncoin_node():
    """Gracefully stop the background node process (if launched)."""
    global node_process
    if node_process and node_process.poll() is None:
        try:
            node_process.terminate()
            node_process.wait(timeout=5)
        except Exception:
            node_process.kill()
        finally:
            node_process = None

    # Extra cleanup for WSL launches
    if platform.system() == "Windows":
        try:
            distro = os.environ.get("ALYNCOIN_WSL_DISTRO", "Ubuntu")
            subprocess.run(["wsl", "-d", distro, "pkill", "-f", "alyncoin"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

# ---- Resource helpers ----
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
    peerStatusReady = pyqtSignal(str, str, bool)
    rpcReadyChecked = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AlynCoin Wallet & Miner")
        self.setGeometry(200, 100, 720, 600)
        self.loadedAddress = ""
        self.loadedKeyId = ""
        self.miningActive = False
        self._rpcReadyTimer = None
        self._rpcReadyWorkerActive = False
        self.peerStatusReady.connect(self._applyPeerBanner)
        self.rpcReadyChecked.connect(self._onRpcReadyChecked)
        self._peerWorkerActive = False
        self._peerBackoffUntil = 0.0
        self._peerNormalInterval = 3000
        self._peerBackoffInterval = 12000

        # -- Use all discovered DNS peers
        self.dns_peers = get_peers_from_dns()
        self.initUI(get_logo_path())
        self.applyDarkTheme()
        self.appendOutput(
            "ℹ️ Peer connections are restored automatically from peers.txt. "
            "Use the Stats tab to review current peers."
        )

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

        # Display network status based on actual peer connections
        self.peerBanner = QLabel("🌐 AlynCoin Network: Checking…")
        self.peerBanner.setAlignment(Qt.AlignCenter)
        self.peerBanner.setStyleSheet(
            "background-color: #191919; color: #ffaa00; padding: 4px; font-weight: bold;"
        )
        layout.addWidget(self.peerBanner)

        self.peerTimer = QTimer(self)
        self.peerTimer.setInterval(self._peerNormalInterval)
        self.peerTimer.timeout.connect(self._schedulePeerBannerRefresh)
        self.peerTimer.start()
        self._schedulePeerBannerRefresh()

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
        self.swapTab = SwapTab(self)

        self.tabs.addTab(self.walletTab, "Wallet")
        self.tabs.addTab(self.sendTab, "Send")
        self.tabs.addTab(self.historyTab, "History")
        self.tabs.addTab(self.minerTab, "Miner")
        self.tabs.addTab(self.daoTab, "DAO")
        self.tabs.addTab(self.statsTab, "Stats")
        self.tabs.addTab(self.nftTab, "NFT")
        self.tabs.addTab(self.swapTab, "Atomic Swap")

        layout.addWidget(self.tabs)
        layout.addWidget(self.outputBox)
        centralWidget.setLayout(layout)

        self.walletChanged.connect(self.sendTab.onWalletChanged)
        self.walletChanged.connect(self.minerTab.onWalletChanged)
        self.walletChanged.connect(self.statsTab.onWalletChanged)
        self.walletChanged.connect(self.nftTab.onWalletChanged)
        self.walletChanged.connect(self.swapTab.onWalletChanged)

    @pyqtSlot(str)
    def appendOutput(self, text):
        self.outputBox.append(text)

    def clearOutput(self):
        self.outputBox.clear()

    def get_wallet_address(self):
        return self.loadedAddress if self.loadedAddress else ""

    def get_wallet_key_id(self):
        return self.loadedKeyId if self.loadedKeyId else ""

    def set_wallet_address(self, addr, key_id=None):
        self.loadedAddress = addr or ""
        if key_id is not None:
            self.loadedKeyId = key_id or ""
        self.walletChanged.emit(self.loadedAddress)

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

    def _resolve_peer_banner(self):
        status = rpc_peer_status()
        if status:
            state = (status.get("state") or "").lower()
            connected = status.get("connected", 0)
            if connected and connected > 0:
                return "🌐 AlynCoin Network: Connected", "#44e", False
            if state == "connecting":
                return "🌐 AlynCoin Network: Connecting…", "#ffaa00", False
            if state == "offline":
                return "🌐 AlynCoin Network: Offline", "#f44", True

        count = get_peer_count()
        if count > 0:
            return "🌐 AlynCoin Network: Connected", "#44e", False

        if is_rpc_up():
            return "🌐 AlynCoin Network: Connecting…", "#ffaa00", False

        return "🌐 AlynCoin Network: Offline", "#f44", True

    def refreshPeerBanner(self):
        self._schedulePeerBannerRefresh()

    def _schedulePeerBannerRefresh(self):
        if self._peerWorkerActive:
            return
        now = time.monotonic()
        if now < self._peerBackoffUntil:
            return
        self._peerWorkerActive = True

        def worker():
            offline = True
            try:
                status, color, offline = self._resolve_peer_banner()
            except Exception:
                status, color, offline = "🌐 AlynCoin Network: Offline", "#f44", True
            finally:
                self.peerStatusReady.emit(status, color, offline)

        threading.Thread(target=worker, daemon=True).start()

    def _applyPeerBanner(self, status, color, offline):
        self.peerBanner.setText(status)
        self.peerBanner.setStyleSheet(
            f"background-color: #191919; color: {color}; padding: 4px; font-weight: bold;"
        )
        self._peerWorkerActive = False
        if offline:
            self._peerBackoffUntil = time.monotonic() + (self._peerBackoffInterval / 1000.0)
            self.peerTimer.setInterval(self._peerBackoffInterval)
        else:
            self._peerBackoffUntil = 0.0
            if self.peerTimer.interval() != self._peerNormalInterval:
                self.peerTimer.setInterval(self._peerNormalInterval)

    def lockUI(self):
        self.tabs.setEnabled(False)
        self.miningActive = True
        self.updateStatusBanner("⛏️ Mining in progress... Please wait.", "#ffaa00")

    def unlockUI(self):
        self.tabs.setEnabled(True)
        self.miningActive = False
        self.updateStatusBanner("✅ Ready.", "#22dd55")

    def restart_node(self) -> bool:
        terminate_alyncoin_node()
        time.sleep(0.5)
        return ensure_alyncoin_node(block=True)

    def closeEvent(self, event):
        terminate_alyncoin_node()
        super().closeEvent(event)

    def beginRpcReadyPolling(self):
        if self._rpcReadyTimer:
            return
        self._rpcReadyTimer = QTimer(self)
        self._rpcReadyTimer.setInterval(2000)
        self._rpcReadyTimer.timeout.connect(self._scheduleRpcReadyCheck)
        self._rpcReadyTimer.start()
        self._scheduleRpcReadyCheck()

    def _scheduleRpcReadyCheck(self):
        if self._rpcReadyWorkerActive:
            return

        def worker():
            ready = False
            try:
                alyncoin_rpc("peercount")
                ready = True
            except Exception:
                ready = False
            finally:
                self.rpcReadyChecked.emit(ready)

        self._rpcReadyWorkerActive = True
        threading.Thread(target=worker, daemon=True).start()

    def _onRpcReadyChecked(self, ready: bool):
        self._rpcReadyWorkerActive = False
        if not ready:
            return
        if self._rpcReadyTimer:
            self._rpcReadyTimer.stop()
            self._rpcReadyTimer = None
        self.tabs.setEnabled(True)
        self.updateStatusBanner("✅ Ready.", "#22dd55")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    if not acquire_single_instance("com.alyncoin.wallet"):
        QMessageBox.information(None, "AlynCoin", "AlynCoin is already running.")
        sys.exit(0)
    # --- Try to launch the background node ---
    if not ensure_alyncoin_node():
        QMessageBox.critical(None, "AlynCoin Node Missing",
                             "Could not start AlynCoin node process.\nMake sure 'alyncoin' is in the same folder.")
        sys.exit(1)
    # --- DNS requirement ---
    dns_warning = None
    if not is_alyncoin_dns_accessible():
        dns_warning = (
            "⚠️ Unable to reach peers.alyncoin.com for DNS bootstrap.\n"
            "The node will continue using the built-in bootstrap list and any peers saved "
            "in peers.txt."
        )
        print(dns_warning)

    rpc_ready = wait_for_rpc_ready(timeout=15.0)
    if not rpc_ready:
        QMessageBox.warning(
            None,
            "RPC Unavailable",
            "The local AlynCoin node has not started its RPC interface yet.\n"
            "The wallet will continue to open, but some features may be temporarily unavailable.",
        )

    sync_info = None
    if rpc_ready:
        try:
            sync_info = alyncoin_rpc("syncstatus")
        except RuntimeError as e:
            print(f"⚠️  RPC 'syncstatus' failed: {e}")

    if sync_info is not None:
        if isinstance(sync_info, dict) and "error" in sync_info:
            print("⚠️  RPC 'syncstatus' not available; skipping sync check")
        elif not isinstance(sync_info, dict):
            QMessageBox.warning(None, "Node Sync", "Unable to determine sync status.")
        elif not sync_info.get("synced", False):
            QMessageBox.warning(None, "Node Sync",
                                 "Local node is still syncing. The wallet will open, but some features may be unavailable.")
    window = AlynCoinApp()
    if dns_warning:
        QMessageBox.warning(window, "Peer Discovery", dns_warning)
        window.appendOutput(dns_warning)
    if not rpc_ready:
        window.tabs.setEnabled(False)
        window.updateStatusBanner("⚠️ Waiting for node RPC interface…", "#ffaa00")
        window.beginRpcReadyPolling()
    window.show()
    exit_code = app.exec_()
    terminate_alyncoin_node()
    sys.exit(exit_code)
