import sys, re, traceback
from concurrent.futures import ThreadPoolExecutor
from PyQt5.QtCore    import Qt, QTimer, pyqtSignal
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel,
    QTextEdit, QHBoxLayout, QFrame
)

from rpc_client import alyncoin_rpc                 # unchanged

# ---------- helpers ----------------------------------------------------------

def filter_miner_output(line: str) -> bool:
    """Return True for lines we want to surface in the GUI."""
    if any(tok in line for tok in ("❌", "⛔", "[ERROR]", "⚠️")):
        return True
    whitelist = (
        r"^⛏️ Mining single block", r"^⛏️ Block reward", r"^⚙️ Difficulty set to",
        r"^⏳ \[mineBlock\]",        r"^✅ \[mineBlock\] PoW Complete\.",
        r"^🔢 Final Nonce:",         r"^🧬 Block Hash \(BLAKE3\):",
        r"^✅ Block mined and added successfully\.", r"^✅ Block mined by:",
        r"^🧱 Block Hash:",          r"^✅ Block mined!|^✅ Rollup|^✅ Recursive"
    )
    return any(re.search(pat, line) for pat in whitelist)

# ---------- MinerTab ---------------------------------------------------------

class MinerTab(QWidget):
    """Qt tab that drives mining via RPC without freezing the GUI."""

    # When a block is found we emit a signal so *other* tabs could react
    blockMined = pyqtSignal(str)

    def __init__(self, walletAddrFn, parent=None):
        super().__init__(parent)
        self.getWallet   = walletAddrFn     # callback that returns address
        self.parentWin   = parent
        self.loop_active = False            # True while “mining loop” toggle is on
        self.pending     = False            # True while one RPC is in-flight
        self.executor    = ThreadPoolExecutor(max_workers=1)
        self._build_ui()
        if hasattr(parent, "walletChanged"):
            parent.walletChanged.connect(self.onWalletChanged)
        self.onWalletChanged(self.getWallet() or "")

    # ---------- Qt life-cycle ----------

    def closeEvent(self, ev):
        # make sure no threads linger after the app closes
        try:
            self.executor.shutdown(wait=False, cancel_futures=True)
        finally:
            super().closeEvent(ev)

    # ---------- UI helpers ----------

    def _build_ui(self):
        lay = QVBoxLayout(self)

        # banner / status
        self.status = QLabel("🟡 <b>AlynCoin Miner Status: Idle</b>")
        lay.addWidget(self.status)

        # main buttons
        row = QHBoxLayout()
        self.btn_mine_once    = QPushButton("Mine One Block")
        self.btn_start_loop   = QPushButton("Start Mining Loop")
        self.btn_stop_loop    = QPushButton("Stop Mining")
        row.addWidget(self.btn_mine_once)
        row.addWidget(self.btn_start_loop)
        row.addWidget(self.btn_stop_loop)
        lay.addLayout(row)

        # rollup buttons
        row2 = QHBoxLayout()
        self.btn_rollup       = QPushButton("Generate Rollup")
        self.btn_rec_rollup   = QPushButton("Generate Recursive Rollup")
        row2.addWidget(self.btn_rollup)
        row2.addWidget(self.btn_rec_rollup)
        lay.addLayout(row2)

        # pretty banner
        self.banner = QLabel("💎 <b><font color='#00FFFF'>Ready to mine AlynCoin!</font></b>")
        self.banner.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.banner)

        # divider
        line = QFrame(); line.setFrameShape(QFrame.HLine); line.setFrameShadow(QFrame.Sunken)
        lay.addWidget(line)

        # scrolling output
        self.out = QTextEdit(readOnly=True)
        lay.addWidget(self.out)

        # wire buttons
        self.btn_mine_once.clicked.connect(self._mine_once_clicked)
        self.btn_start_loop.clicked.connect(self._start_loop_clicked)
        self.btn_stop_loop.clicked.connect(self._stop_loop_clicked)
        self.btn_rollup.clicked.connect(self._rollup_clicked)
        self.btn_rec_rollup.clicked.connect(self._rec_rollup_clicked)

    def _append(self, txt: str):
        self.out.append(txt)
        self.out.verticalScrollBar().setValue(self.out.verticalScrollBar().maximum())
        if self.parentWin and hasattr(self.parentWin, "appendOutput"):
            self.parentWin.appendOutput(txt)

    def _set_idle(self):
        self.banner.setText("💎 <b><font color='#00FFFF'>Ready to mine AlynCoin!</font></b>")
        self.status.setText("🟡 <b>AlynCoin Miner Status: Idle</b>")
        self._refresh_buttons()

    def _refresh_buttons(self):
        wallet_loaded = bool(self.getWallet())
        busy          = self.loop_active or self.pending
        for b in (self.btn_mine_once, self.btn_start_loop, self.btn_rollup, self.btn_rec_rollup):
            b.setEnabled(wallet_loaded and not busy)
        self.btn_stop_loop.setEnabled(self.loop_active)

    # ---------- wallet change ----------

    def _on_wallet_changed(self, addr):
        self._refresh_buttons()

    # Compatibility slot expected by main.py and other tabs
    def onWalletChanged(self, addr):
        self._on_wallet_changed(addr)

    # ---------- clicks ----------

    def _mine_once_clicked(self):
        self.loop_active = False
        self._one_off_rpc("mineonce")

    def _start_loop_clicked(self):
        if self.loop_active:                                     # already on
            return
        self.loop_active = True
        self._append("⏳ Mining loop started…")
        self.status.setText("🟢 <b>Mining loop running…</b>")
        self._refresh_buttons()
        self._schedule_next_loop_rpc(0)                          # fire immediately

    def _stop_loop_clicked(self):
        if self.loop_active:
            self.loop_active = False
            self._append("⛔ Mining stopped by user.")
        self._set_idle()

    def _rollup_clicked(self):
        self._one_off_rpc("rollup")

    def _rec_rollup_clicked(self):
        self._one_off_rpc("recursive-rollup")

    # ---------- RPC helpers (threaded) ----------

    def _one_off_rpc(self, method):
        """A single RPC that changes banner, shows result, then goes idle."""
        if self.pending:
            self._append("⚠️ Another request is still running, please wait.")
            return
        self.pending = True
        self.banner.setText(f"Running <b>{method}</b> …")
        self.status.setText("🟢 <b>Working…</b>")
        self._refresh_buttons()

        def _work():
            try:
                return alyncoin_rpc(method, [self.getWallet()])
            except Exception as e:
                return {"error": f"{type(e).__name__}: {e}"}

        future = self.executor.submit(_work)
        # QTimer.singleShot invoked with a receiver ensures the callback runs
        # in the GUI thread even when this lambda executes in the worker
        future.add_done_callback(
            lambda f: QTimer.singleShot(0, self, lambda: self._finish_rpc(method, f))
        )

    def _finish_rpc(self, method, future):
        self.pending = False
        try:
            res = future.result()
        except Exception:
            res = {"error": traceback.format_exc(limit=1)}
        self._display_result(method, res)
        if not self.loop_active:          # if we weren't a loop iteration
            self._set_idle()
        self._refresh_buttons()

    # --------- mining loop helpers ---------

    def _schedule_next_loop_rpc(self, delay_ms=0):
        """Schedule next mineonce in the loop."""
        if not self.loop_active:
            return
        QTimer.singleShot(delay_ms, self._loop_rpc_step)

    def _loop_rpc_step(self):
        if not self.loop_active:
            self._set_idle(); return
        if self.pending:                  # shouldn't happen, but double-check
            self._schedule_next_loop_rpc(1000)
            return
        self.pending = True
        self.status.setText("🟢 <b>Mining…</b>")
        self.banner.setText("Mining loop running…")

        def _work():
            try:
                return alyncoin_rpc("mineonce", [self.getWallet()])
            except Exception as e:
                return {"error": f"{type(e).__name__}: {e}"}

        fut = self.executor.submit(_work)
        fut.add_done_callback(
            lambda f: QTimer.singleShot(0, self, lambda: self._loop_finished(f))
        )

    def _loop_finished(self, future):
        self.pending = False
        res = future.result()
        self._display_result("mineonce", res)
        # schedule the next attempt in 3 s (or immediately if error)
        delay = 3000 if not (isinstance(res, dict) and "error" in res) else 1000
        self._schedule_next_loop_rpc(delay)

    # ---------- common result display ----------

    def _display_result(self, method, result):
        """Pretty-print an RPC result in the output box."""
        if isinstance(result, dict) and "error" in result:
            self._append(f"❌ {result['error']}")
            return

        # special case: mine/rollup returning a hash
        if isinstance(result, str) and re.fullmatch(r"[a-fA-F0-9]{40,}", result):
            label = {
                "mineonce": "Block mined",
                "rollup": "Rollup block created",
                "recursive-rollup": "Recursive rollup block created"
            }.get(method, "Success")
            self._append(f"✅ {label}! Hash: <b>{result}</b>")
            if method == "mineonce":
                self.blockMined.emit(result)
            return

        # generic prints, filter for noise
        for line in str(result).splitlines():
            if filter_miner_output(line):
                self._append(line)
