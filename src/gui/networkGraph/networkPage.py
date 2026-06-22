import logging

from PySide6.QtCore import Qt, QRectF, QTimer, Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QLabel,
    QPushButton, QMessageBox, QDialog,
)

from .networkGraphScene import NetworkGraphScene
from .networkGraphView import NetworkGraphView
from .detailPanel import DetailPanel
from .graphDataLoader import GraphDataLoader
from .manualDataRepository import ManualDataRepository
from ._models import GraphData, GraphNode
from ._constants import _NS, _LANE_COLUMNS, _LANE_HEADER_H, _LANE_PAD_TOP
from ._dialogs import (
    _AddSubdomainDlg, _AddPortDlg, _AddTechDlg, _AddVulnDlg, _AddEndpointDlg,
    _AddOSINTDlg, _AddCdnDlg, _InfoNoteDlg, _AddCustomNodeDlg, _AddOriginServerDlg,
)
from ._helpers import _legend_chip, _SearchEdit

logger = logging.getLogger(__name__)


# ── Full network page ─────────────────────────────────────────────────────────

class NetworkPage(QWidget):
    send_to_repeater = Signal(str)   # forwarded from DetailPanel.sendToRepeater

    def __init__(self, project_dir: str, target: str, proxy_col=None, parent=None):
        super().__init__(parent)
        self._project_dir = project_dir
        self._target      = target
        self._proxy_col   = proxy_col   # pymongo Collection | None
        self._scope       = None   # ScopeConfig | None — set via on_scope_changed
        self._data: GraphData | None = None
        self._loader: GraphDataLoader | None = None
        self._manual_repo = ManualDataRepository(project_dir, target)
        self._lane_mode   = True     # lane layout is the default

        self._scene = NetworkGraphScene(project_dir, target)
        self._scene.nodeClicked.connect(self._on_node_clicked)
        self._scene.addDataRequested.connect(self._on_add_requested)

        self._view   = NetworkGraphView(self._scene)
        self._detail = DetailPanel(proxy_col=proxy_col)
        self._detail.openInBrowser.connect(self._on_open_browser)
        self._detail.sendToRepeater.connect(self.send_to_repeater)

        toolbar     = self._build_toolbar()
        # Wire zoom observer now that _zoom_lbl exists (created inside _build_toolbar)
        self._view._zoom_observer = self._on_zoom_changed
        self._status = QLabel("Loading…")
        self._status.setStyleSheet(
            "color:#6C7086; font-size:10px; padding:3px 10px; background:#11111B;")

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._view)
        splitter.addWidget(self._detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setStyleSheet("QSplitter::handle{background:#313244;width:2px;}")

        vb = QVBoxLayout(self)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)
        vb.addWidget(toolbar)
        vb.addWidget(splitter, stretch=1)
        vb.addWidget(self._status)

        # _load_data() is NOT called here.  _wire_scope_signals() in
        # TargetWindow calls on_scope_changed() with the persisted scope
        # immediately after all pages are built, which triggers the first load
        # with the correct scope already set.

    # ── Toolbar ───────────────────────────────────────────────────────────────

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(42)
        bar.setStyleSheet("background:#181825; border-bottom:1px solid #313244;")
        hl = QHBoxLayout(bar)
        hl.setContentsMargins(10, 0, 10, 0)
        hl.setSpacing(6)

        title = QLabel("⊗  Attack Surface Graph")
        title.setStyleSheet(
            "color:#94E2D5; font-size:11px; font-weight:bold; background:transparent;")
        hl.addWidget(title)
        hl.addStretch()

        for kind in _NS:
            hl.addWidget(_legend_chip(kind))

        hl.addStretch()

        # ── Search bar ────────────────────────────────────────────────────────
        search_lbl = QLabel("⌕")
        search_lbl.setStyleSheet("color:#6C7086; font-size:14px; background:transparent;")
        hl.addWidget(search_lbl)

        self._search_edit = _SearchEdit()
        self._search_edit.setPlaceholderText("Search nodes…")
        self._search_edit.setFixedSize(160, 26)
        self._search_edit.setStyleSheet(
            "QLineEdit{background:#1E1E2E;color:#CDD6F4;"
            "border:1px solid #45475A;border-radius:4px;"
            "padding:0 8px;font-size:10px;}"
            "QLineEdit:focus{border-color:#89B4FA;}"
        )
        # Debounce: fire 150 ms after the user stops typing
        self._search_debounce = QTimer(self)
        self._search_debounce.setSingleShot(True)
        self._search_debounce.setInterval(150)
        self._search_debounce.timeout.connect(
            lambda: self._scene.set_search(self._search_edit.text())
        )
        self._search_edit.textChanged.connect(self._search_debounce.start)
        hl.addWidget(self._search_edit)

        _btn_ss = ("QPushButton{background:#313244;color:#CDD6F4;"
                   "border:1px solid #45475A;border-radius:4px;"
                   "padding:2px 10px;font-size:10px;min-height:26px;}"
                   "QPushButton:hover{background:#45475A;}")
        _focus_ss_active = ("QPushButton{background:#3D2B1F;color:#FAB387;"
                            "border:1px solid #FE640B;border-radius:4px;"
                            "padding:2px 10px;font-size:10px;min-height:26px;}"
                            "QPushButton:hover{background:#4D3B2F;}")
        _lane_ss_on = ("QPushButton{background:#1A2E1A;color:#A6E3A1;"
                       "border:1px solid #A6E3A1;border-radius:4px;"
                       "padding:2px 10px;font-size:10px;min-height:26px;}"
                       "QPushButton:hover{background:#2A3E2A;}")

        # ── Lane mode toggle ──────────────────────────────────────────────────
        self._lane_btn = QPushButton("⊟ Lane")
        self._lane_btn.setFixedHeight(26)
        self._lane_btn.setStyleSheet(_btn_ss)
        self._lane_btn.setToolTip(
            "Toggle tabular lane layout\n"
            "Columns: Domain → Subdomain → IP → Port → Tech/CDN → Findings"
        )
        self._lane_btn.clicked.connect(self._toggle_lane_mode)
        hl.addWidget(self._lane_btn)
        self._lane_btn._ss_off = _btn_ss
        self._lane_btn._ss_on  = _lane_ss_on
        # Reflect the default-active state immediately
        if self._lane_mode:
            self._lane_btn.setStyleSheet(_lane_ss_on)
            self._lane_btn.setText("⊟ Lane ✓")

        for lbl, fn in [("↺ Refresh",      self._load_data),
                        ("⊡ Fit",          self._view.fit_all),
                        ("⊞ Reset Layout", self._on_reset_layout)]:
            btn = QPushButton(lbl)
            btn.setFixedHeight(26)
            btn.setStyleSheet(_btn_ss)
            btn.clicked.connect(fn)
            hl.addWidget(btn)

        # ── Zoom controls ─────────────────────────────────────────────────────
        _icon_btn_ss = ("QPushButton{background:#313244;color:#CDD6F4;"
                        "border:1px solid #45475A;border-radius:4px;"
                        "padding:0;font-size:13px;min-height:26px;min-width:26px;"
                        "max-width:26px;}"
                        "QPushButton:hover{background:#45475A;}")

        zoom_out_btn = QPushButton("−")
        zoom_out_btn.setFixedSize(26, 26)
        zoom_out_btn.setStyleSheet(_icon_btn_ss)
        zoom_out_btn.setToolTip("Zoom out  (−)")
        zoom_out_btn.clicked.connect(self._view.zoom_out)
        hl.addWidget(zoom_out_btn)

        self._zoom_lbl = QLabel("100%")
        self._zoom_lbl.setFixedWidth(42)
        self._zoom_lbl.setAlignment(Qt.AlignCenter)
        self._zoom_lbl.setStyleSheet(
            "color:#6C7086; font-size:9px; background:transparent; cursor:pointer;")
        self._zoom_lbl.setToolTip("Click to reset zoom to 100%")
        self._zoom_lbl.mousePressEvent = lambda _ev: self._view.zoom_reset()
        hl.addWidget(self._zoom_lbl)

        _lock_ss_off = ("QPushButton{background:#313244;color:#6C7086;"
                        "border:1px solid #45475A;border-radius:4px;"
                        "padding:0;font-size:12px;min-height:26px;min-width:26px;"
                        "max-width:26px;}"
                        "QPushButton:hover{background:#45475A;color:#CDD6F4;}")
        _lock_ss_on  = ("QPushButton{background:#1A2E1A;color:#A6E3A1;"
                        "border:1px solid #A6E3A1;border-radius:4px;"
                        "padding:0;font-size:12px;min-height:26px;min-width:26px;"
                        "max-width:26px;}"
                        "QPushButton:hover{background:#2A3E2A;}")

        self._zoom_lock_btn = QPushButton("🔓")
        self._zoom_lock_btn.setFixedSize(26, 26)
        self._zoom_lock_btn.setStyleSheet(_lock_ss_off)
        self._zoom_lock_btn.setToolTip(
            "Lock zoom — wheel scrolls vertically\n"
            "Shift+wheel scrolls horizontally"
        )
        self._zoom_lock_btn._ss_off = _lock_ss_off
        self._zoom_lock_btn._ss_on  = _lock_ss_on

        def _toggle_zoom_lock():
            self._view._zoom_locked = not self._view._zoom_locked
            locked = self._view._zoom_locked
            self._zoom_lock_btn.setText("🔒" if locked else "🔓")
            self._zoom_lock_btn.setStyleSheet(
                self._zoom_lock_btn._ss_on if locked else self._zoom_lock_btn._ss_off
            )
            # Grey-out the +/− buttons while locked so their purpose is clear
            zoom_out_btn.setEnabled(not locked)
            zoom_in_btn.setEnabled(not locked)

        self._zoom_lock_btn.clicked.connect(_toggle_zoom_lock)
        hl.addWidget(self._zoom_lock_btn)

        zoom_in_btn = QPushButton("+")
        zoom_in_btn.setFixedSize(26, 26)
        zoom_in_btn.setStyleSheet(_icon_btn_ss)
        zoom_in_btn.setToolTip("Zoom in  (+)")
        zoom_in_btn.clicked.connect(self._view.zoom_in)
        hl.addWidget(zoom_in_btn)

        self._show_all_btn = QPushButton("⊗ Show All")
        self._show_all_btn.setFixedHeight(26)
        self._show_all_btn.setStyleSheet(_btn_ss)
        self._show_all_btn.setEnabled(False)
        self._show_all_btn.clicked.connect(self._scene.unfocus)
        hl.addWidget(self._show_all_btn)

        def _on_focus_changed(focused: bool):
            if focused:
                self._show_all_btn.setEnabled(True)
                self._show_all_btn.setStyleSheet(_focus_ss_active)
            else:
                self._show_all_btn.setEnabled(False)
                self._show_all_btn.setStyleSheet(_btn_ss)
        self._scene.focusChanged.connect(_on_focus_changed)

        return bar

    # ── Public API ────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        self._load_data()

    def on_scope_changed(self, config) -> None:
        """Slot connected to ScopeEditorWidget.scope_changed.

        Stores the new ScopeConfig and immediately reloads the graph so that
        only in-scope hosts are rendered.
        """
        self._scope = config
        self._load_data()

    # ── Slots ─────────────────────────────────────────────────────────────────

    def _load_data(self):
        if self._loader and self._loader.isRunning():
            return
        self._status.setText("⟳  Loading graph data…")
        self._loader = GraphDataLoader(
            self._project_dir, self._target, scope=self._scope, parent=self
        )
        self._loader.loaded.connect(self._on_loaded)
        self._loader.error.connect(lambda m: self._status.setText(f"Error: {m}"))
        self._loader.start()

    def _on_loaded(self, data: GraphData):
        first_load = self._data is None
        self._data = data
        if first_load:
            self._scene.build(data)
            if self._lane_mode:
                self._scene.lane_layout(data)
                QTimer.singleShot(150, self._fit_first_rows)
            else:
                QTimer.singleShot(150, self._view.fit_all)
        else:
            self._scene.merge(data)   # preserves all node positions
            if self._lane_mode:
                self._scene.lane_layout(data)

        n = data.nodes
        counts = {k: sum(1 for nd in n if nd.kind == k) for k in _NS}
        proxy_count = counts["cdn"] + counts["reverse_proxy"]
        cdn_s = f"  ·  {proxy_count} CDN/proxies" if proxy_count else ""
        self._status.setText(
            f"{counts['subdomain']} subdomains  ·  {counts['ip']} IPs  ·  "
            f"{counts['port']} ports  ·  {counts['tech']} technologies  ·  "
            f"{counts['vuln']} vulns  ·  {counts['osint']} OSINT{cdn_s}"
        )

    def _on_reset_layout(self):
        if self._data:
            self._scene.reset_layout(self._data)
            if self._lane_mode:
                self._scene.lane_layout(self._data)
            QTimer.singleShot(150, self._view.fit_all)

    def _on_zoom_changed(self, level: float) -> None:
        """Called by NetworkGraphView whenever the zoom factor changes."""
        if hasattr(self, "_zoom_lbl"):
            self._zoom_lbl.setText(f"{round(level * 100)}%")

    def _on_node_clicked(self, node: GraphNode):
        self._detail.show_node(node)

    def _on_open_browser(self, url: str):
        win = self.window()
        if hasattr(win, "openNewBrowserTab"):
            win.openNewBrowserTab(url)

    def _fit_first_rows(self, n_rows: int = 2) -> None:
        """Fit the view to show the first n_rows lane bands (plus the header)."""
        rects = getattr(self._scene, "_lane_row_rects", None)
        if not rects:
            self._view.fit_all()
            return
        n = min(n_rows, len(rects))
        col_w_total = sum(c[2] for c in _LANE_COLUMNS)
        header_y  = float(-(_LANE_HEADER_H + _LANE_PAD_TOP))
        top       = header_y - 10
        bot       = rects[n - 1][1] + rects[n - 1][3] + 20
        fit_rect  = QRectF(-20, top, col_w_total + 140, bot - top)
        self._view.fitInView(fit_rect, Qt.KeepAspectRatio)
        self._view._zoom_level = self._view.transform().m11()
        self._view._emit_zoom()

    def _toggle_lane_mode(self) -> None:
        self._lane_mode = not self._lane_mode
        btn = self._lane_btn
        if self._lane_mode:
            btn.setStyleSheet(btn._ss_on)
            btn.setText("⊟ Lane ✓")
            if self._data:
                self._scene.lane_layout(self._data)
                QTimer.singleShot(120, self._view.fit_all)
        else:
            btn.setStyleSheet(btn._ss_off)
            btn.setText("⊟ Lane")
            self._scene._clear_lane_decorations()
            if self._data:
                # Restore hierarchy layout (positions from cache win over
                # the lane positions we just applied)
                self._scene.build(self._data)
                QTimer.singleShot(120, self._view.fit_all)

    # ── Manual data entry ─────────────────────────────────────────────────────

    def _on_add_requested(self, action: str, parent_node):
        """Open the appropriate dialog, save to DB, and refresh the graph."""
        nd = parent_node  # GraphNode or None

        def _prefill_host() -> str:
            if nd is None:
                return ""
            return nd.data.get("ip") or nd.data.get("domain") or ""

        def _prefill_url(port: int | None = None) -> str:
            if nd is None:
                return ""
            h = nd.data.get("domain") or nd.data.get("ip") or ""
            p = port or nd.data.get("port")
            if not h:
                return ""
            scheme = "https" if p in (443, 8443) else "http"
            if p and p not in (80, 443):
                return f"{scheme}://{h}:{p}/"
            return f"{scheme}://{h}/"

        try:
            if action == "add_subdomain":
                prefill = nd.data.get("domain", "") if nd and nd.kind == "target" else ""
                dlg = _AddSubdomainDlg(self, prefill_domain="")
                if dlg.exec() != QDialog.Accepted:
                    return
                domain, ips = dlg.values()
                self._manual_repo.add_subdomain(domain, ips)

            elif action == "add_ip":
                host = _prefill_host()
                dlg = _AddSubdomainDlg(self, prefill_domain=host)
                dlg.setWindowTitle("Add IP Address to Subdomain")
                if dlg.exec() != QDialog.Accepted:
                    return
                domain, ips = dlg.values()
                self._manual_repo.add_subdomain(domain, ips)

            elif action == "add_port":
                host = _prefill_host()
                dlg = _AddPortDlg(self, prefill_host=host)
                if dlg.exec() != QDialog.Accepted:
                    return
                host, port, proto, svc, ver = dlg.values()
                self._manual_repo.add_port(host, port, proto, svc, ver)

            elif action == "add_tech":
                url = _prefill_url(nd.data.get("port") if nd else None)
                dlg = _AddTechDlg(self, prefill_url=url)
                if dlg.exec() != QDialog.Accepted:
                    return
                url, tech, status, title = dlg.values()
                self._manual_repo.add_tech(url, tech, status, title)

            elif action == "add_vuln":
                url = _prefill_url()
                dlg = _AddVulnDlg(self, prefill_url=url)
                if dlg.exec() != QDialog.Accepted:
                    return
                name, sev, url, desc, tid = dlg.values()
                self._manual_repo.add_vuln(name, sev, url, desc, tid)

            elif action == "add_endpoint":
                url = _prefill_url(nd.data.get("port") if nd else None)
                dlg = _AddEndpointDlg(self, prefill_url=url)
                if dlg.exec() != QDialog.Accepted:
                    return
                url, method, status = dlg.values()
                self._manual_repo.add_endpoint(url, method, status)

            elif action == "add_osint":
                dlg = _AddOSINTDlg(self)
                if dlg.exec() != QDialog.Accepted:
                    return
                rtype, value, extra, provider = dlg.values()
                self._manual_repo.add_osint(rtype, value, extra, provider)

            elif action == "add_cdn":
                host = _prefill_host()
                dlg  = _AddCdnDlg(self, prefill_subdomain=host)
                if dlg.exec() != QDialog.Accepted:
                    return
                subdomain, provider, proxy_type, origin_ips, bypass_hints = dlg.values()
                self._manual_repo.add_cdn(subdomain, provider, proxy_type,
                                          origin_ips, bypass_hints)

            elif action in ("add_info", "edit_info"):
                prefill = (self._manual_repo.get_info_note(nd.id)
                           if action == "edit_info" else "")
                dlg = _InfoNoteDlg(self,
                                   node_label=nd.label if nd else "",
                                   prefill=prefill)
                if dlg.exec() != QDialog.Accepted:
                    return
                self._manual_repo.save_info_note(nd.id, dlg.content())

            elif action == "add_custom":
                dlg = _AddCustomNodeDlg(self,
                                        parent_node_label=nd.label if nd else "")
                if dlg.exec() != QDialog.Accepted:
                    return
                label, desc = dlg.values()
                self._manual_repo.add_custom_node(nd.id, label, desc)

            elif action == "add_origin_server":
                dlg = _AddOriginServerDlg(
                    self,
                    provider=nd.label if nd else "",
                    subdomain=nd.data.get("proxied_host", "") if nd else "",
                )
                if dlg.exec() != QDialog.Accepted:
                    return
                origin_ip, subdomain, provider = dlg.values()
                self._manual_repo.add_origin_to_cdn(subdomain, provider, origin_ip)

            else:
                return

            # Refresh the graph so the new node appears immediately
            self._load_data()

        except Exception as exc:
            logger.exception("Manual data entry failed")
            QMessageBox.critical(
                self, "Save Failed",
                f"Could not save to database:\n{exc}",
            )
