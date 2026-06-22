"""
Docker Manager Window — create, run, monitor, and manage AWE tool containers.

Layout
──────
  Toolbar: status indicator | [Refresh] [Prune stopped]
  ┌ Left panel (containers + images) ─────┐ ┌ Right panel ──────────────────────┐
  │  Containers tab                        │ │  Logs tab  (live stream)          │
  │    QTableWidget: name│image│status│... │ │    QTextEdit (read-only, mono)    │
  │    [Stop] [Remove] per row             │ │    [Copy] [Clear]                 │
  │  Images tab                            │ ├ Launch tab (run a tool now) ──────┤
  │    QTableWidget: tag│size│[Remove]     │ │  Tool selector (QComboBox)        │
  │    Pull: QLineEdit + [Pull]            │ │  Dynamic param form               │
  │    Build: tool selector + [Build]      │ │  Output dir field                 │
  └────────────────────────────────────────┘ │  [Run in Docker]                  │
                                             └───────────────────────────────────┘
"""
import os
from datetime import datetime

from PySide6.QtCore import QThread, Signal, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QTextCursor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFormLayout, QFrame,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QSizePolicy, QSplitter, QTabWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from containers.docker_manager import DockerManager, DockerUnavailableError, manager as _mgr
from containers.tool_registry import TOOL_REGISTRY, TOOL_CATEGORIES


# ── background threads ────────────────────────────────────────────────────────

class _LogStreamer(QThread):
    line = Signal(str)
    finished = Signal()

    def __init__(self, container_id: str, mgr: DockerManager):
        super().__init__()
        self._id = container_id
        self._mgr = mgr
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        for text in self._mgr.stream_logs(self._id):
            if self._stop:
                break
            self.line.emit(text)
        self.finished.emit()


class _PullWorker(QThread):
    progress = Signal(str)
    done = Signal(bool, str)

    def __init__(self, image: str, mgr: DockerManager):
        super().__init__()
        self._image = image
        self._mgr = mgr

    def run(self):
        try:
            for status in self._mgr.pull_image(self._image):
                self.progress.emit(status)
            self.done.emit(True, f"Pulled {self._image}")
        except Exception as exc:
            self.done.emit(False, str(exc))


class _BuildWorker(QThread):
    progress = Signal(str)
    done = Signal(bool, str)

    def __init__(self, dockerfile: str, tag: str, mgr: DockerManager):
        super().__init__()
        self._df = dockerfile
        self._tag = tag
        self._mgr = mgr

    def run(self):
        try:
            for line in self._mgr.build_image(self._df, self._tag):
                self.progress.emit(line)
            self.done.emit(True, f"Built {self._tag}")
        except Exception as exc:
            self.done.emit(False, str(exc))


class _RunToolWorker(QThread):
    log = Signal(str)
    done = Signal(bool, str)

    def __init__(self, tool_key: str, params: dict, output_dir: str, mgr: DockerManager):
        super().__init__()
        self._tool_key = tool_key
        self._params = params
        self._output_dir = output_dir
        self._mgr = mgr

    def run(self):
        tool = TOOL_REGISTRY[self._tool_key]
        try:
            if not self._mgr.image_exists(tool.image):
                self.log.emit(f"Image {tool.image} not found locally.")
                if tool.dockerfile:
                    self.log.emit(f"Building from {tool.dockerfile} …")
                    for line in self._mgr.build_image(tool.dockerfile, tool.image):
                        self.log.emit(line)
                else:
                    self.log.emit(f"Pulling {tool.image} …")
                    for status in self._mgr.pull_image(tool.image):
                        self.log.emit(status)

            command = tool.build_command(**self._params)
            volumes = tool.get_volumes(self._output_dir)
            name = tool.container_name()
            self.log.emit(f"Starting container {name} …")
            self.log.emit(f"  image:   {tool.image}")
            self.log.emit(f"  command: {command}")
            c = self._mgr.run_container(
                image=tool.image,
                command=command,
                name=name,
                volumes=volumes,
            )
            self.log.emit(f"Container {c.short_id} started — streaming logs:\n")
            for line in self._mgr.stream_logs(c.id):
                self.log.emit(line)
            self.done.emit(True, f"{tool.display_name} finished.")
        except Exception as exc:
            self.done.emit(False, str(exc))


# ── helpers ───────────────────────────────────────────────────────────────────

_STATUS_COLOR = {
    "running":  "#A6E3A1",
    "exited":   "#A6ADC8",
    "created":  "#89B4FA",
    "paused":   "#FAB387",
    "dead":     "#F38BA8",
    "removing": "#F38BA8",
}


def _colored_item(text: str, color: str | None = None) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
    if color:
        item.setForeground(QColor(color))
    return item


def _icon_btn(label: str, tooltip: str) -> QPushButton:
    b = QPushButton(label)
    b.setToolTip(tooltip)
    b.setFixedSize(28, 24)
    return b


# ── batch image operation ─────────────────────────────────────────────────────

class _BatchTask:
    __slots__ = ("tool_key", "image", "op", "dockerfile")
    def __init__(self, tool_key: str, image: str, op: str, dockerfile: str | None = None):
        self.tool_key   = tool_key
        self.image      = image
        self.op         = op          # "pull" | "build"
        self.dockerfile = dockerfile


class _BatchImageWorker(QThread):
    image_started  = Signal(str)            # tool_key
    image_progress = Signal(str, str)       # tool_key, message
    image_done     = Signal(str, bool, str) # tool_key, ok, message
    all_done       = Signal(int, int)       # n_ok, n_fail

    def __init__(self, tasks: list[_BatchTask], mgr: DockerManager):
        super().__init__()
        self._tasks  = tasks
        self._mgr    = mgr
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        n_ok = n_fail = 0
        for task in self._tasks:
            if self._cancel:
                break
            self.image_started.emit(task.tool_key)
            try:
                if task.op == "pull":
                    for status in self._mgr.pull_image(task.image):
                        if self._cancel:
                            break
                        if status.strip():
                            self.image_progress.emit(task.tool_key, status.strip())
                else:
                    for line in self._mgr.build_image(task.dockerfile, task.image):
                        if self._cancel:
                            break
                        if line.strip():
                            self.image_progress.emit(task.tool_key, line.strip())
                verb = "Built" if task.op == "build" else "Pulled"
                self.image_done.emit(task.tool_key, True, f"{verb} {task.image}")
                n_ok += 1
            except Exception as exc:
                self.image_done.emit(task.tool_key, False, str(exc))
                n_fail += 1
        self.all_done.emit(n_ok, n_fail)


class _BatchProgressDialog(QDialog):
    _PB = """
        QProgressBar {{
            background:#1E1E2E; border:1px solid #45475A;
            border-radius:3px; max-height:10px;
        }}
        QProgressBar::chunk {{ background:{color}; border-radius:2px; }}
    """
    _BTN = ("QPushButton{{background:#313244;color:{c};border:1px solid #45475A;"
            "border-radius:4px;padding:2px 14px;font-size:10px;min-height:26px;}}"
            "QPushButton:hover{{background:#45475A;}}"
            "QPushButton:disabled{{color:#45475A;background:#1E1E2E;border-color:#313244;}}")

    def __init__(self, tool_entries: list[tuple], mode: str,
                 mgr: DockerManager, parent=None):
        """
        tool_entries : [(tool_key, cfg, local_size_or_None), …]
        mode         : "pull" | "build" | "all"
        """
        super().__init__(parent)
        _titles = {"pull": "Pull All Hub Images",
                   "build": "Build All Local Images",
                   "all":   "Setup All Tool Images"}
        self.setWindowTitle(_titles[mode])
        self.setMinimumSize(740, 560)
        self.setModal(True)
        self.setStyleSheet("QDialog{background:#181825;} QLabel{color:#CDD6F4;}")

        self._mgr    = mgr
        self._worker: _BatchImageWorker | None = None
        self._rows:   dict[str, dict]          = {}  # tool_key → {pb, st_item, row}
        self._tasks   = self._collect_tasks(tool_entries, mode)
        self._n_total = len(self._tasks)
        self._n_done  = 0
        self._task_keys = {t.tool_key for t in self._tasks}

        self._build_ui(tool_entries)
        self._start()

    # ── build UI ──────────────────────────────────────────────────────────────

    def _build_ui(self, tool_entries: list[tuple]):
        vb = QVBoxLayout(self)
        vb.setSpacing(8)
        vb.setContentsMargins(14, 14, 14, 14)

        # overall progress row
        ovr = QHBoxLayout()
        ovr_lbl = QLabel("Overall")
        ovr_lbl.setStyleSheet("color:#6C7086; font-size:10px;")
        ovr.addWidget(ovr_lbl)

        self._overall_pb = QProgressBar()
        self._overall_pb.setRange(0, max(self._n_total, 1))
        self._overall_pb.setValue(0)
        self._overall_pb.setFixedHeight(12)
        self._overall_pb.setTextVisible(False)
        self._overall_pb.setStyleSheet(self._PB.format(color="#89B4FA"))
        ovr.addWidget(self._overall_pb, stretch=1)

        self._overall_txt = QLabel(f"0 / {self._n_total}")
        self._overall_txt.setStyleSheet("color:#6C7086; font-size:10px; min-width:55px;")
        ovr.addWidget(self._overall_txt)
        vb.addLayout(ovr)

        # per-image table
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Tool", "Source", "Status", "Progress"])
        hh = self._table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Fixed);   self._table.setColumnWidth(0, 150)
        hh.setSectionResizeMode(1, QHeaderView.Fixed);   self._table.setColumnWidth(1, 58)
        hh.setSectionResizeMode(2, QHeaderView.Fixed);   self._table.setColumnWidth(2, 200)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setShowGrid(False)
        self._table.setSelectionMode(QTableWidget.NoSelection)
        vb.addWidget(self._table, stretch=1)

        for tool_key, cfg, local_size in tool_entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 34)

            self._table.setItem(row, 0, _colored_item(cfg.display_name))

            is_build = bool(cfg.dockerfile)
            self._table.setItem(row, 1, _colored_item(
                "Build" if is_build else "Hub",
                "#F9E2AF" if is_build else "#89B4FA"))

            st = QTableWidgetItem()
            st.setFlags(Qt.ItemIsEnabled)
            self._table.setItem(row, 2, st)

            pb = QProgressBar()
            pb.setRange(0, 100)
            pb.setFixedHeight(8)
            pb.setTextVisible(False)

            pb_cell = QWidget()
            pb_cell.setStyleSheet("background:transparent;")
            ph = QHBoxLayout(pb_cell)
            ph.setContentsMargins(6, 13, 6, 13)
            ph.addWidget(pb)
            self._table.setCellWidget(row, 3, pb_cell)

            if local_size is not None:
                st.setText(f"✓  Already available  ({local_size:.0f} MB)")
                st.setForeground(QColor("#A6E3A1"))
                pb.setValue(100)
                pb.setStyleSheet(self._PB.format(color="#A6E3A1"))
            elif tool_key not in self._task_keys:
                st.setText("—  Skipped (mode filter)")
                st.setForeground(QColor("#45475A"))
                pb.setValue(0)
                pb.setStyleSheet(self._PB.format(color="#313244"))
            else:
                st.setText("⏳  Queued")
                st.setForeground(QColor("#6C7086"))
                pb.setValue(0)
                pb.setStyleSheet(self._PB.format(color="#45475A"))

            self._rows[tool_key] = {"pb": pb, "st": st, "row": row}

        # log
        div = QFrame(); div.setFrameShape(QFrame.HLine)
        div.setStyleSheet("background:#313244; border:none;"); div.setFixedHeight(1)
        vb.addWidget(div)

        log_hdr = QHBoxLayout()
        log_hdr.addWidget(QLabel("Log"))
        log_hdr.addStretch()
        clr = QPushButton("Clear")
        clr.setFixedHeight(20)
        clr.setStyleSheet(self._BTN.format(c="#6C7086"))
        log_hdr.addWidget(clr)
        vb.addLayout(log_hdr)

        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setFixedHeight(120)
        self._log_view.setFont(QFont("Cascadia Code", 8))
        self._log_view.setStyleSheet(
            "QTextEdit{background:#11111B;color:#A6ADC8;border:none;padding:4px;}")
        clr.clicked.connect(self._log_view.clear)
        vb.addWidget(self._log_view)

        # action row
        btn_row = QHBoxLayout()
        self._cancel_btn = QPushButton("⊘  Cancel")
        self._cancel_btn.setStyleSheet(self._BTN.format(c="#F38BA8"))
        self._cancel_btn.clicked.connect(self._do_cancel)
        btn_row.addWidget(self._cancel_btn)
        btn_row.addStretch()
        self._close_btn = QPushButton("Close")
        self._close_btn.setEnabled(False)
        self._close_btn.setStyleSheet(self._BTN.format(c="#CDD6F4"))
        self._close_btn.clicked.connect(self.accept)
        btn_row.addWidget(self._close_btn)
        vb.addLayout(btn_row)

    # ── logic ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _collect_tasks(tool_entries, mode) -> list[_BatchTask]:
        tasks = []
        for tool_key, cfg, local_size in tool_entries:
            if local_size is not None:
                continue
            if mode == "pull" and cfg.dockerfile:
                continue
            if mode == "build" and not cfg.dockerfile:
                continue
            tasks.append(_BatchTask(
                tool_key, cfg.image,
                "build" if cfg.dockerfile else "pull",
                cfg.dockerfile,
            ))
        return tasks

    def _start(self):
        if not self._tasks:
            self._log("Nothing to do — all matching images are already available.")
            self._finish()
            return
        self._worker = _BatchImageWorker(self._tasks, self._mgr)
        self._worker.image_started.connect(self._on_started)
        self._worker.image_progress.connect(self._on_progress)
        self._worker.image_done.connect(self._on_done)
        self._worker.all_done.connect(self._on_all_done)
        self._worker.start()

    def _on_started(self, tool_key: str):
        w = self._rows.get(tool_key)
        if not w:
            return
        cfg = TOOL_REGISTRY.get(tool_key)
        verb = "Building" if (cfg and cfg.dockerfile) else "Pulling"
        w["st"].setText(f"⟳  {verb}…")
        w["st"].setForeground(QColor("#FAB387"))
        w["pb"].setRange(0, 0)    # indeterminate pulse
        w["pb"].setStyleSheet(self._PB.format(color="#FAB387"))
        self._table.scrollToItem(self._table.item(w["row"], 0))

    def _on_progress(self, tool_key: str, message: str):
        self._log(message)

    def _on_done(self, tool_key: str, ok: bool, message: str):
        w = self._rows.get(tool_key)
        if w:
            if ok:
                w["st"].setText("✓  Done")
                w["st"].setForeground(QColor("#A6E3A1"))
                w["pb"].setRange(0, 100); w["pb"].setValue(100)
                w["pb"].setStyleSheet(self._PB.format(color="#A6E3A1"))
            else:
                w["st"].setText("✗  Failed")
                w["st"].setForeground(QColor("#F38BA8"))
                w["pb"].setRange(0, 100); w["pb"].setValue(100)
                w["pb"].setStyleSheet(self._PB.format(color="#F38BA8"))
        self._n_done += 1
        self._overall_pb.setValue(self._n_done)
        self._overall_txt.setText(f"{self._n_done} / {self._n_total}")
        self._log(("✓  " if ok else "✗  ") + message)

    def _on_all_done(self, n_ok: int, n_fail: int):
        parts = []
        if n_ok:   parts.append(f"✓ {n_ok} succeeded")
        if n_fail: parts.append(f"✗ {n_fail} failed")
        self._log("  —  ".join(parts) if parts else "Done.")
        self._finish()

    def _finish(self):
        self._cancel_btn.setEnabled(False)
        self._close_btn.setEnabled(True)

    def _do_cancel(self):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._log("⊘  Cancelling after current operation completes…")
        self._cancel_btn.setEnabled(False)

    def _log(self, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_view.append(
            f"<span style='color:#585B70'>[{ts}]</span> {text}")
        self._log_view.moveCursor(QTextCursor.End)

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(3000)
        super().closeEvent(event)


# ── main window ───────────────────────────────────────────────────────────────

class DockerManagerWindow(QMainWindow):
    def __init__(self, parent=None, default_output_dir: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Docker Manager")
        self.resize(1200, 680)
        self._mgr = _mgr
        self._default_output_dir = default_output_dir
        self._log_streamer: _LogStreamer | None = None
        self._workers: list[QThread] = []
        self._param_widgets: dict[str, QWidget] = {}

        self._image_workers: dict[str, QThread] = {}   # tool_key → active worker
        self._build_ui()
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(6000)
        self._refresh_timer.timeout.connect(self._refresh_containers)
        self._refresh_timer.start()
        self._check_docker_status()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        vbox = QVBoxLayout(root)
        vbox.setContentsMargins(8, 4, 8, 8)
        vbox.setSpacing(0)

        # toolbar
        toolbar = self._build_toolbar()
        toolbar.setFixedHeight(36)
        vbox.addWidget(toolbar)
        vbox.addWidget(self._hline())

        splitter = QSplitter(Qt.Horizontal)

        # left: containers + images tabs
        left_tabs = QTabWidget()
        left_tabs.setObjectName("dockerLeftTabs")
        left_tabs.addTab(self._build_containers_tab(), "Containers")
        left_tabs.addTab(self._build_images_tab(), "Images")
        splitter.addWidget(left_tabs)

        # right: logs + launcher tabs
        right_tabs = QTabWidget()
        right_tabs.setObjectName("dockerRightTabs")
        right_tabs.addTab(self._build_logs_tab(), "Logs")
        right_tabs.addTab(self._build_launcher_tab(), "Launch Tool")
        splitter.addWidget(right_tabs)

        splitter.setSizes([560, 600])
        vbox.addWidget(splitter)

    def _build_toolbar(self) -> QWidget:
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)

        self.statusDot = QLabel("●")
        self.statusDot.setObjectName("dockerStatusDot")
        self.statusMsg = QLabel("Checking Docker…")
        self.statusMsg.setObjectName("dockerStatusMsg")
        row.addWidget(self.statusDot)
        row.addWidget(self.statusMsg)
        row.addStretch()

        refreshBtn = QPushButton("Refresh")
        refreshBtn.clicked.connect(self._refresh_all)
        row.addWidget(refreshBtn)

        pruneBtn = QPushButton("Prune Stopped")
        pruneBtn.setObjectName("deleteButton")
        pruneBtn.clicked.connect(self._prune_stopped)
        row.addWidget(pruneBtn)
        return w

    # ── containers tab ────────────────────────────────────────────────────────

    def _build_containers_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(6, 6, 6, 6)

        self.containerTable = QTableWidget(0, 5)
        self.containerTable.setHorizontalHeaderLabels(
            ["Name", "Image", "Status", "Started", "Actions"]
        )
        self.containerTable.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.containerTable.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.containerTable.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.containerTable.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.containerTable.horizontalHeader().setSectionResizeMode(4, QHeaderView.Fixed)
        self.containerTable.setColumnWidth(4, 76)
        self.containerTable.setSelectionBehavior(QTableWidget.SelectRows)
        self.containerTable.setEditTriggers(QTableWidget.NoEditTriggers)
        self.containerTable.verticalHeader().setVisible(False)
        self.containerTable.itemSelectionChanged.connect(self._on_container_selected)
        vbox.addWidget(self.containerTable)
        return w

    def _refresh_containers(self):
        try:
            rows = self._mgr.list_awe_containers()
        except DockerUnavailableError:
            return

        self.containerTable.setRowCount(len(rows))
        for i, info in enumerate(rows):
            color = _STATUS_COLOR.get(info["status"], "#CDD6F4")
            self.containerTable.setItem(i, 0, _colored_item(info["name"]))
            self.containerTable.setItem(i, 1, _colored_item(info["image"]))
            self.containerTable.setItem(i, 2, _colored_item(info["status"], color))
            self.containerTable.setItem(i, 3, _colored_item(info["started"]))

            cell = QWidget()
            cell_layout = QHBoxLayout(cell)
            cell_layout.setContentsMargins(2, 0, 2, 0)
            cell_layout.setSpacing(4)

            stop_btn = _icon_btn("■", "Stop container")
            stop_btn.setEnabled(info["status"] == "running")
            stop_btn.clicked.connect(lambda _, cid=info["full_id"]: self._stop_container(cid))

            rm_btn = _icon_btn("✕", "Remove container")
            rm_btn.clicked.connect(lambda _, cid=info["full_id"]: self._remove_container(cid))

            cell_layout.addWidget(stop_btn)
            cell_layout.addWidget(rm_btn)
            self.containerTable.setCellWidget(i, 4, cell)

            # store full_id in first column's data
            self.containerTable.item(i, 0).setData(Qt.UserRole, info["full_id"])

    def _on_container_selected(self):
        rows = self.containerTable.selectedItems()
        if not rows:
            return
        full_id = self.containerTable.item(rows[0].row(), 0).data(Qt.UserRole)
        self._start_log_stream(full_id)

    def _stop_container(self, container_id: str):
        try:
            self._mgr.stop_container(container_id)
            self._refresh_containers()
        except Exception as exc:
            self._log(f"Stop failed: {exc}")

    def _remove_container(self, container_id: str):
        try:
            self._mgr.remove_container(container_id)
            self._refresh_containers()
        except Exception as exc:
            self._log(f"Remove failed: {exc}")

    def _prune_stopped(self):
        try:
            n = self._mgr.prune_stopped()
            self._log(f"Removed {n} stopped container(s).")
            self._refresh_containers()
        except DockerUnavailableError as exc:
            self._log(str(exc))

    # ── images tab ────────────────────────────────────────────────────────────

    def _build_images_tab(self) -> QWidget:
        w = QWidget()
        vb = QVBoxLayout(w)
        vb.setContentsMargins(6, 6, 6, 6)
        vb.setSpacing(6)

        # header
        hdr = QHBoxLayout()
        title = QLabel("Tool Images")
        title.setStyleSheet("color:#CDD6F4; font-weight:bold; font-size:11px;")
        hdr.addWidget(title)
        hdr.addStretch()

        _btn_ss = ("QPushButton{background:#313244;color:%s;border:1px solid #45475A;"
                   "border-radius:4px;padding:1px 10px;font-size:9px;min-height:24px;}"
                   "QPushButton:hover{background:#45475A;}")

        pull_all_btn = QPushButton("↓  Pull All")
        pull_all_btn.setFixedHeight(26)
        pull_all_btn.setToolTip("Pull all Hub images that are not yet available")
        pull_all_btn.setStyleSheet(_btn_ss % "#89B4FA")
        pull_all_btn.clicked.connect(lambda: self._launch_batch("pull"))
        hdr.addWidget(pull_all_btn)

        build_all_btn = QPushButton("⚒  Build All")
        build_all_btn.setFixedHeight(26)
        build_all_btn.setToolTip("Build all Dockerfile images that are not yet available")
        build_all_btn.setStyleSheet(_btn_ss % "#F9E2AF")
        build_all_btn.clicked.connect(lambda: self._launch_batch("build"))
        hdr.addWidget(build_all_btn)

        setup_all_btn = QPushButton("⚡  Setup All")
        setup_all_btn.setFixedHeight(26)
        setup_all_btn.setToolTip("Pull and build every missing tool image in one go")
        setup_all_btn.setStyleSheet(_btn_ss % "#A6E3A1")
        setup_all_btn.clicked.connect(lambda: self._launch_batch("all"))
        hdr.addWidget(setup_all_btn)

        hdr.addSpacing(6)
        ref_btn = QPushButton("↺")
        ref_btn.setFixedSize(26, 26)
        ref_btn.setToolTip("Refresh image list")
        ref_btn.setStyleSheet(_btn_ss % "#6C7086")
        ref_btn.clicked.connect(self._refresh_images)
        hdr.addWidget(ref_btn)
        vb.addLayout(hdr)

        split = QSplitter(Qt.Vertical)
        split.setChildrenCollapsible(False)
        split.setStyleSheet("QSplitter::handle{background:#313244;height:4px;}")

        # ── top pane: table ───────────────────────────────────────────────────
        self.imageTable = QTableWidget(0, 5)
        self.imageTable.setHorizontalHeaderLabels(
            ["Tool", "Image", "Source", "Status", "Actions"]
        )
        hh = self.imageTable.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Fixed);     self.imageTable.setColumnWidth(0, 130)
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.Fixed);     self.imageTable.setColumnWidth(2, 64)
        hh.setSectionResizeMode(3, QHeaderView.Fixed);     self.imageTable.setColumnWidth(3, 118)
        hh.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.imageTable.setEditTriggers(QTableWidget.NoEditTriggers)
        self.imageTable.verticalHeader().setVisible(False)
        self.imageTable.setSelectionBehavior(QTableWidget.SelectRows)
        self.imageTable.setAlternatingRowColors(True)
        split.addWidget(self.imageTable)

        # ── bottom pane: image operations log ─────────────────────────────────
        log_pane = QWidget()
        log_vb = QVBoxLayout(log_pane)
        log_vb.setContentsMargins(0, 4, 0, 0)
        log_vb.setSpacing(4)

        img_log_hdr = QHBoxLayout()
        log_title = QLabel("Image operations log")
        log_title.setStyleSheet("color:#6C7086; font-size:10px;")
        img_log_hdr.addWidget(log_title)
        img_log_hdr.addStretch()
        clr = QPushButton("Clear")
        clr.setFixedHeight(22)
        clr.setStyleSheet(
            "QPushButton{background:#313244;color:#6C7086;border:1px solid #45475A;"
            "border-radius:3px;padding:0 8px;font-size:9px;}"
            "QPushButton:hover{background:#45475A;}")
        img_log_hdr.addWidget(clr)
        log_vb.addLayout(img_log_hdr)

        self._imgLogView = QTextEdit()
        self._imgLogView.setReadOnly(True)
        self._imgLogView.setFont(QFont("Cascadia Code", 8))
        self._imgLogView.setStyleSheet(
            "QTextEdit{background:#11111B;color:#A6ADC8;border:none;padding:4px;}")
        clr.clicked.connect(self._imgLogView.clear)
        log_vb.addWidget(self._imgLogView)
        split.addWidget(log_pane)

        split.setSizes([340, 160])
        vb.addWidget(split)
        return w

    def _refresh_images(self):
        try:
            local_imgs = self._mgr.list_images()
        except DockerUnavailableError:
            return

        # build tag → size_mb lookup (match with or without explicit :latest)
        local_map: dict[str, float] = {}
        for img in local_imgs:
            for tag in img["tags"]:
                local_map[tag] = img["size_mb"]

        def _local_size(image: str) -> float | None:
            if image in local_map:
                return local_map[image]
            base = image.split(":")[0]
            for k, v in local_map.items():
                if k.split(":")[0] == base:
                    return v
            return None

        self.imageTable.setRowCount(0)
        for tool_key, cfg in TOOL_REGISTRY.items():
            row = self.imageTable.rowCount()
            self.imageTable.insertRow(row)
            self.imageTable.setRowHeight(row, 36)

            self.imageTable.setItem(row, 0, _colored_item(cfg.display_name))
            self.imageTable.item(row, 0).setData(Qt.UserRole, tool_key)
            self.imageTable.setItem(row, 1, _colored_item(cfg.image))

            is_build = bool(cfg.dockerfile)
            src_lbl   = "Build" if is_build else "Hub"
            src_color = "#F9E2AF" if is_build else "#89B4FA"
            self.imageTable.setItem(row, 2, _colored_item(src_lbl, src_color))

            busy = (tool_key in self._image_workers
                    and self._image_workers[tool_key].isRunning())
            size = _local_size(cfg.image)

            if busy:
                verb = "Building" if is_build else "Pulling"
                st_txt, st_col = f"⟳  {verb}…", "#FAB387"
            elif size is not None:
                st_txt, st_col = f"●  {size:.0f} MB", "#A6E3A1"
            else:
                st_txt, st_col = "○  Not available", "#6C7086"
            self.imageTable.setItem(row, 3, _colored_item(st_txt, st_col))

            self.imageTable.setCellWidget(row, 4,
                self._image_action_cell(tool_key, cfg, size, busy))

    def _image_action_cell(self, tool_key: str, cfg, size, busy: bool) -> QWidget:
        cell = QWidget()
        hl   = QHBoxLayout(cell)
        hl.setContentsMargins(4, 3, 4, 3)
        hl.setSpacing(4)

        _btn_base = (
            "QPushButton{border-radius:4px;font-size:9px;padding:0 10px;}"
            "QPushButton:disabled{color:#45475A;background:#1E1E2E;border:1px solid #313244;}"
        )

        if size is not None:
            rm = QPushButton("✕  Remove")
            rm.setEnabled(not busy)
            rm.setStyleSheet(
                _btn_base +
                "QPushButton{background:#313244;color:#F38BA8;border:1px solid #45475A;}"
                "QPushButton:hover{background:#45475A;border-color:#F38BA8;}")
            rm.clicked.connect(lambda _, t=cfg.image: self._remove_image(t))
            hl.addWidget(rm)
        else:
            is_build = bool(cfg.dockerfile)
            lbl   = "⚒  Build" if is_build else "↓  Pull"
            color = "#F9E2AF"   if is_build else "#89B4FA"
            act   = QPushButton(lbl)
            act.setEnabled(not busy)
            act.setStyleSheet(
                _btn_base +
                f"QPushButton{{background:#313244;color:{color};border:1px solid #45475A;}}"
                f"QPushButton:hover{{background:#45475A;border-color:{color};}}")
            if is_build:
                act.clicked.connect(
                    lambda _, k=tool_key: self._start_image_op(k, "build"))
            else:
                act.clicked.connect(
                    lambda _, k=tool_key: self._start_image_op(k, "pull"))
            hl.addWidget(act)

        return cell

    def _start_image_op(self, tool_key: str, op: str):
        cfg = TOOL_REGISTRY[tool_key]
        if op == "build":
            self._img_log(f"Building {cfg.image} …")
            w = _BuildWorker(cfg.dockerfile, cfg.image, self._mgr)
        else:
            self._img_log(f"Pulling {cfg.image} …")
            w = _PullWorker(cfg.image, self._mgr)

        w.progress.connect(self._img_log)
        w.done.connect(lambda ok, msg, k=tool_key: self._on_image_op_done(ok, msg, k))
        self._image_workers[tool_key] = w
        self._workers.append(w)
        w.start()
        self._refresh_images()   # immediately show ⟳

    def _on_image_op_done(self, ok: bool, msg: str, tool_key: str):
        self._img_log(("✓  " if ok else "✗  ") + msg)
        self._image_workers.pop(tool_key, None)
        self._refresh_images()

    def _launch_batch(self, mode: str):
        """Open the batch-progress dialog for pull-all / build-all / setup-all."""
        try:
            local_imgs = self._mgr.list_images()
        except DockerUnavailableError:
            self._img_log("Docker unavailable — cannot start batch operation.")
            return

        local_map: dict[str, float] = {}
        for img in local_imgs:
            for tag in img["tags"]:
                local_map[tag] = img["size_mb"]

        def _size(image: str) -> float | None:
            if image in local_map:
                return local_map[image]
            base = image.split(":")[0]
            for k, v in local_map.items():
                if k.split(":")[0] == base:
                    return v
            return None

        entries = [(k, cfg, _size(cfg.image)) for k, cfg in TOOL_REGISTRY.items()]
        dlg = _BatchProgressDialog(entries, mode, self._mgr, parent=self)
        dlg.finished.connect(self._refresh_images)
        dlg.exec()

    def _img_log(self, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._imgLogView.append(
            f"<span style='color:#585B70'>[{ts}]</span> {text}")
        self._imgLogView.moveCursor(QTextCursor.End)

    def _remove_image(self, tag: str):
        try:
            self._mgr.remove_image(tag)
            self._refresh_images()
        except Exception as exc:
            self._img_log(f"Remove failed: {exc}")

    # ── logs tab ──────────────────────────────────────────────────────────────

    def _build_logs_tab(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(6, 6, 6, 6)

        self.logHeader = QLabel("Select a container to stream its logs.")
        self.logHeader.setObjectName("dockerLogHeader")
        vbox.addWidget(self.logHeader)

        self.logView = QTextEdit()
        self.logView.setReadOnly(True)
        self.logView.setObjectName("dockerLogView")
        mono = QFont("Cascadia Code", 9)
        self.logView.setFont(mono)
        vbox.addWidget(self.logView)

        btn_row = QHBoxLayout()
        copyBtn = QPushButton("Copy All")
        copyBtn.clicked.connect(lambda: QApplication.clipboard().setText(self.logView.toPlainText()))
        clearBtn = QPushButton("Clear")
        clearBtn.clicked.connect(self.logView.clear)
        btn_row.addWidget(copyBtn)
        btn_row.addWidget(clearBtn)
        btn_row.addStretch()
        vbox.addLayout(btn_row)
        return w

    def _start_log_stream(self, container_id: str):
        if self._log_streamer and self._log_streamer.isRunning():
            self._log_streamer.stop()
            self._log_streamer.wait(1000)
        self.logView.clear()
        c = self._mgr.get_container(container_id)
        if c is None:
            return
        self.logHeader.setText(f"Logs: {c.name}  [{c.short_id}]  ({c.status})")
        self._log_streamer = _LogStreamer(container_id, self._mgr)
        self._log_streamer.line.connect(self._append_log_line)
        self._log_streamer.start()

    def _append_log_line(self, text: str):
        self.logView.append(text)
        self.logView.moveCursor(QTextCursor.End)

    # ── launch tab ────────────────────────────────────────────────────────────

    def _build_launcher_tab(self) -> QWidget:
        w = QWidget()
        self._launcher_vbox = QVBoxLayout(w)
        self._launcher_vbox.setContentsMargins(8, 8, 8, 8)
        self._launcher_vbox.setSpacing(8)

        top_form = QFormLayout()

        # category filter
        self.categoryCombo = QComboBox()
        self.categoryCombo.addItem("All categories", "all")
        for cat in sorted(TOOL_CATEGORIES.keys()):
            label = cat.replace("_", " ").title()
            self.categoryCombo.addItem(f"{label}  ({len(TOOL_CATEGORIES[cat])})", cat)
        self.categoryCombo.currentIndexChanged.connect(self._on_category_changed)
        top_form.addRow("Category:", self.categoryCombo)

        self.toolCombo = QComboBox()
        self.toolCombo.currentIndexChanged.connect(self._rebuild_param_form)
        top_form.addRow("Tool:", self.toolCombo)

        self.outputDirEdit = QLineEdit()
        self.outputDirEdit.setText(self._default_output_dir)
        self.outputDirEdit.setPlaceholderText("/path/to/project/output")
        top_form.addRow("Output dir:", self.outputDirEdit)
        self._launcher_vbox.addLayout(top_form)
        self._launcher_vbox.addWidget(self._hline())

        # placeholder frame for dynamic param form — must exist before _populate_tool_combo
        self._param_frame = QWidget()
        self._param_frame_layout = QFormLayout(self._param_frame)
        self._launcher_vbox.addWidget(self._param_frame)

        self._launcher_vbox.addWidget(self._hline())
        runBtn = QPushButton("Run in Docker")
        runBtn.setObjectName("primaryButton")
        runBtn.setFixedHeight(34)
        runBtn.clicked.connect(self._run_tool)
        self._launcher_vbox.addWidget(runBtn)
        self._launcher_vbox.addStretch()

        # populate tool combo now that _param_frame_layout exists
        self._populate_tool_combo("all")
        return w

    def _populate_tool_combo(self, category: str):
        self.toolCombo.blockSignals(True)
        self.toolCombo.clear()
        keys = TOOL_CATEGORIES.get(category, list(TOOL_REGISTRY.keys())) \
               if category != "all" else list(TOOL_REGISTRY.keys())
        for key in keys:
            cfg = TOOL_REGISTRY[key]
            self.toolCombo.addItem(cfg.display_name, key)
        self.toolCombo.blockSignals(False)
        self._rebuild_param_form()

    def _on_category_changed(self):
        cat = self.categoryCombo.currentData()
        self._populate_tool_combo(cat)

    def _rebuild_param_form(self):
        while self._param_frame_layout.rowCount():
            self._param_frame_layout.removeRow(0)
        self._param_widgets.clear()

        key = self.toolCombo.currentData()
        if key is None:
            return
        cfg = TOOL_REGISTRY[key]

        for spec in cfg.param_spec():
            pkey = spec["key"]
            if spec["type"] == "text":
                widget = QLineEdit()
                widget.setText(str(spec.get("default", "")))
            elif spec["type"] == "check":
                widget = QCheckBox()
                widget.setChecked(bool(spec.get("default", False)))
            elif spec["type"] == "combo":
                widget = QComboBox()
                for opt in spec.get("options", []):
                    widget.addItem(opt)
                default = spec.get("default", "")
                idx = widget.findText(default)
                if idx >= 0:
                    widget.setCurrentIndex(idx)
            else:
                widget = QLineEdit()
            self._param_frame_layout.addRow(spec["label"] + ":", widget)
            self._param_widgets[pkey] = widget

        # show custom image / dockerfile notice
        if cfg.dockerfile:
            note = QLabel(f"Image: {cfg.image}  (will auto-build if not found)")
            note.setObjectName("certDialogSubtitle")
            self._param_frame_layout.addRow("", note)

    def _collect_params(self) -> dict:
        result = {}
        for key, widget in self._param_widgets.items():
            if isinstance(widget, QLineEdit):
                result[key] = widget.text().strip()
            elif isinstance(widget, QCheckBox):
                result[key] = widget.isChecked()
            elif isinstance(widget, QComboBox):
                result[key] = widget.currentText()
        return result

    def _run_tool(self):
        key = self.toolCombo.currentData()
        if key is None:
            return
        output_dir = self.outputDirEdit.text().strip()
        if not output_dir:
            self._log("Output directory is required.")
            return
        params = self._collect_params()
        self._log(f"▶ Launching {TOOL_REGISTRY[key].display_name} …")

        w = _RunToolWorker(key, params, output_dir, self._mgr)
        w.log.connect(self._log)
        w.done.connect(lambda ok, msg: (
            self._log(("✓ " if ok else "✗ ") + msg),
            self._refresh_containers()
        ))
        self._workers.append(w)
        w.start()

    # ── docker status ─────────────────────────────────────────────────────────

    def _check_docker_status(self):
        ok, msg = self._mgr.is_available()
        if ok:
            self.statusDot.setStyleSheet("color: #A6E3A1;")
            self.statusMsg.setText(f"Docker running — version {self._mgr.server_version()}")
            self._refresh_all()
        else:
            self.statusDot.setStyleSheet("color: #F38BA8;")
            short = msg.split("\n")[0]
            self.statusMsg.setText(f"Docker unavailable: {short}")

    def _refresh_all(self):
        self._refresh_containers()
        self._refresh_images()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _log(self, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.logView.append(f"<span style='color:#585B70'>[{ts}]</span> {text}")
        self.logView.moveCursor(QTextCursor.End)

    @staticmethod
    def _hline() -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setObjectName("certDivider")
        return line

    def closeEvent(self, event):
        if self._log_streamer and self._log_streamer.isRunning():
            self._log_streamer.stop()
            self._log_streamer.wait(1000)
        self._refresh_timer.stop()
        super().closeEvent(event)
