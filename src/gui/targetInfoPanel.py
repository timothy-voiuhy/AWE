import json
import logging
import os
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Qt, QModelIndex, Slot, QThread, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QStandardItem, QStandardItemModel, QFont, QColor
from PySide6.QtWidgets import (
    QMessageBox, QDockWidget, QWidget, QVBoxLayout, QFormLayout, QCheckBox,
    QFrame, QLabel, QHBoxLayout, QLineEdit, QTreeView, QScrollArea,
    QTextBrowser, QSplitter, QTableWidget, QTableView, QTableWidgetItem,
    QPushButton, QSizePolicy,
)

from gui.guiUtilities import MessageBox, HoverButton
from gui.threadrunners import WhoisThreadRunner
from utilities import red, rm_same, yellow, runWhoisOnTarget


# ── Reusable UI helpers ───────────────────────────────────────────────────────

def _section(title: str, accent: str = "#89B4FA") -> tuple[QFrame, QVBoxLayout, "QPushButton"]:
    """Returns (outer_frame, content_vbox, toggle_btn).  Content starts visible."""
    outer = QFrame()
    outer.setObjectName("ldSection")
    outer.setStyleSheet(f"""
        QFrame#ldSection {{
            border: none;
            border-left: 2px solid {accent};
            background: transparent;
            margin: 0px;
        }}
    """)
    vbox = QVBoxLayout(outer)
    vbox.setContentsMargins(6, 0, 0, 4)
    vbox.setSpacing(4)

    hdr = QWidget()
    hdr.setStyleSheet("background: transparent;")
    hdr_row = QHBoxLayout(hdr)
    hdr_row.setContentsMargins(0, 2, 0, 2)
    hdr_row.setSpacing(4)

    toggle = QPushButton("▾")
    toggle.setFixedSize(18, 18)
    toggle.setFlat(True)
    toggle.setStyleSheet(f"color:{accent}; font-size:12px; background:transparent; border:none;")
    hdr_row.addWidget(toggle)

    lbl = QLabel(title.upper())
    lbl.setFont(QFont("Cascadia Code", 8))
    lbl.setStyleSheet(f"color:{accent}; letter-spacing:1px;")
    hdr_row.addWidget(lbl)
    hdr_row.addStretch()

    vbox.addWidget(hdr)

    body = QWidget()
    body.setStyleSheet("background: transparent;")
    body_vbox = QVBoxLayout(body)
    body_vbox.setContentsMargins(0, 0, 0, 0)
    body_vbox.setSpacing(4)
    vbox.addWidget(body)

    def _toggle():
        vis = not body.isVisible()
        body.setVisible(vis)
        toggle.setText("▾" if vis else "▸")

    body.show()   # explicit — isVisible() is False before parent is shown
    toggle.clicked.connect(_toggle)
    return outer, body_vbox, toggle


def _stat_card(label: str, value: str, accent: str) -> tuple[QFrame, QLabel]:
    """Returns (card_frame, value_label) so the caller can update the value."""
    card = QFrame()
    card.setStyleSheet(f"""
        QFrame {{
            background: #1E1E2E;
            border: 1px solid {accent};
            border-radius: 6px;
        }}
    """)
    card.setFixedHeight(52)
    vb = QVBoxLayout(card)
    vb.setContentsMargins(8, 4, 8, 4)
    vb.setSpacing(0)

    val_lbl = QLabel(value)
    val_lbl.setFont(QFont("Cascadia Code", 15, QFont.Bold))
    val_lbl.setStyleSheet(f"color:{accent}; background:transparent; border:none;")
    val_lbl.setAlignment(Qt.AlignCenter)

    key_lbl = QLabel(label)
    key_lbl.setFont(QFont("Cascadia Code", 7))
    key_lbl.setStyleSheet("color:#6C7086; background:transparent; border:none;")
    key_lbl.setAlignment(Qt.AlignCenter)

    vb.addWidget(val_lbl)
    vb.addWidget(key_lbl)
    return card, val_lbl


def _divider() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.HLine)
    f.setStyleSheet("color: #313244; background: #313244;")
    f.setFixedHeight(1)
    return f


class TargetInfoPanel(QObject):
    openLinkInBrw = Signal(str)

    def __init__(self, main_window,
                 project_dir_path,
                 parent=None,
                 top_parent=None,
                 embed=False,
                 ) -> None:
        super().__init__()
        self._embed = embed
        self.whois_text_results = None
        self.topParent = top_parent
        self.main_window = main_window
        self.projectDirPath = project_dir_path
        self.amass_data_json_file  = os.path.join(self.projectDirPath, "emcpData.json")
        self.SubdomainUrlDict = {}
        self.location_table_drawn = False
        self.SubdomainUrlDict_file = os.path.join(self.projectDirPath, "subdomainsUrlDict.json")
        self.parent = parent
        self.whois_displaying = False
        self.location_table_item_dicts = []
        self.topParent.socketIpc.processFinishedExecution.connect(self.updateModel)
        self.topParent.socketIpc.processFinishedExecution.connect(self.display_whois_results)

        # ── Dock shell ────────────────────────────────────────────────────────
        self._panel_widget = QWidget()
        self._panel_widget.setStyleSheet("background: #1E1E2E;")
        self._panel_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        if not self._embed:
            self._dock = QDockWidget()
            self._dock.setTitleBarWidget(QWidget())
            self._dock.setWidget(self._panel_widget)
            self._dockArea = Qt.DockWidgetArea()
            self.main_window.addDockWidget(self._dockArea.LeftDockWidgetArea, self._dock)

        root_vbox = QVBoxLayout(self._panel_widget)
        root_vbox.setContentsMargins(0, 0, 0, 0)
        root_vbox.setSpacing(0)

        # ── Target header card ────────────────────────────────────────────────
        header_card = QFrame()
        header_card.setObjectName("ldHeaderCard")
        header_card.setStyleSheet("""
            QFrame#ldHeaderCard {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #1E1E2E, stop:1 #181825);
                border-bottom: 2px solid #89B4FA;
            }
        """)
        header_card.setFixedHeight(64)
        hc_row = QHBoxLayout(header_card)
        hc_row.setContentsMargins(10, 6, 10, 6)
        hc_row.setSpacing(8)

        target_icon = QLabel("◎")
        target_icon.setFont(QFont("Cascadia Code", 18))
        target_icon.setStyleSheet("color:#89B4FA; background:transparent;")
        hc_row.addWidget(target_icon)

        hc_text = QWidget()
        hc_text.setStyleSheet("background:transparent;")
        hc_vbox = QVBoxLayout(hc_text)
        hc_vbox.setContentsMargins(0, 0, 0, 0)
        hc_vbox.setSpacing(0)

        domain_lbl = QLabel(self.main_window.main_server_name or "—")
        domain_lbl.setFont(QFont("Cascadia Code", 12, QFont.Bold))
        domain_lbl.setStyleSheet("color:#CDD6F4; background:transparent;")
        domain_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        hc_vbox.addWidget(domain_lbl)

        proj_path = Path(project_dir_path).name
        proj_lbl = QLabel(proj_path)
        proj_lbl.setFont(QFont("Cascadia Code", 8))
        proj_lbl.setStyleSheet("color:#6C7086; background:transparent;")
        hc_vbox.addWidget(proj_lbl)

        hc_row.addWidget(hc_text, stretch=1)
        root_vbox.addWidget(header_card)

        # ── Stat pills ────────────────────────────────────────────────────────
        pills_row = QWidget()
        pills_row.setStyleSheet("background:#181825;")
        pills_row.setFixedHeight(60)
        pills_layout = QHBoxLayout(pills_row)
        pills_layout.setContentsMargins(8, 4, 8, 4)
        pills_layout.setSpacing(6)

        card_subds, self.nSubd       = _stat_card("SUBDOMAINS", "0", "#CBA6F7")
        card_urls,  self.nUrls       = _stat_card("URLS",       "0", "#A6E3A1")
        card_whois, self._whoisPill  = _stat_card("WHOIS  ▶",   "○", "#FAB387")
        card_whois.setToolTip("Click to run Whois")
        card_whois.setCursor(Qt.PointingHandCursor)
        card_whois.mousePressEvent = lambda _e: self._run_whois_ui()
        pills_layout.addWidget(card_subds)
        pills_layout.addWidget(card_urls)
        pills_layout.addWidget(card_whois)
        root_vbox.addWidget(pills_row)
        root_vbox.addWidget(_divider())

        # ── Scrollable body ───────────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: #1E1E2E; border: none; }")
        scroll.viewport().setStyleSheet("background: #1E1E2E;")
        body_widget = QWidget()
        body_widget.setStyleSheet("background: #1E1E2E;")
        body_vbox = QVBoxLayout(body_widget)
        body_vbox.setContentsMargins(8, 8, 8, 8)
        body_vbox.setSpacing(10)
        scroll.setWidget(body_widget)

        # ── Whois section (first — immediately visible) ───────────────────────
        sec_whois, whois_body, _ = _section("Whois", "#FAB387")

        self.run_whois_button = QPushButton("▶  Run Whois")
        self.run_whois_button.setObjectName("primaryButton")
        self.run_whois_button.setFixedHeight(28)
        self.run_whois_button.clicked.connect(self._run_whois_ui)
        whois_body.addWidget(self.run_whois_button)

        self.whois_text_widget = QTextBrowser()
        self.whois_text_widget.setReadOnly(True)
        self.whois_text_widget.setMinimumHeight(130)
        self.whois_text_widget.setFont(QFont("Cascadia Code", 8))
        self.whois_text_widget.setStyleSheet("""
            QTextBrowser {
                background: #181825;
                color: #CDD6F4;
                border: 1px solid #313244;
                border-radius: 4px;
                padding: 4px;
            }
        """)
        self.whois_text_widget.setPlaceholderText("Click ▶ Run Whois or the WHOIS pill above…")
        whois_body.addWidget(self.whois_text_widget)
        body_vbox.addWidget(sec_whois)

        # ── Tool subdomain counts section ─────────────────────────────────────
        sec_counts, counts_body, _ = _section("Subdomain Counts", "#CBA6F7")

        tool_form = QWidget()
        tool_form.setStyleSheet("background:transparent;")
        tf_layout = QFormLayout(tool_form)
        tf_layout.setContentsMargins(4, 0, 0, 0)
        tf_layout.setSpacing(4)
        tf_layout.setLabelAlignment(Qt.AlignLeft)

        def _count_row(tool: str, color: str):
            key = QLabel(tool)
            key.setFont(QFont("Cascadia Code", 8))
            key.setStyleSheet("color:#9399B2; background:transparent;")
            val = QLabel("0")
            val.setFont(QFont("Cascadia Code", 9, QFont.Bold))
            val.setStyleSheet(f"color:{color}; background:transparent;")
            tf_layout.addRow(key, val)
            return val

        self.amassSdCountLabel         = _count_row("Amass",         "#89B4FA")
        self.sublist3rSdCountLabel     = _count_row("Sublist3r",     "#F38BA8")
        self.subdomainizerSdCountLabel = _count_row("Subdomainizer", "#FAB387")

        counts_body.addWidget(tool_form)
        body_vbox.addWidget(sec_counts)

        # ── Server Locations section ──────────────────────────────────────────
        sec_loc, loc_body, _ = _section("Server Locations", "#89DCEB")

        loc_ctrl = QWidget()
        loc_ctrl.setStyleSheet("background:transparent;")
        loc_ctrl_row = QHBoxLayout(loc_ctrl)
        loc_ctrl_row.setContentsMargins(0, 0, 0, 0)
        loc_ctrl_row.setSpacing(4)

        self.generate_table_button = QPushButton("Generate")
        self.generate_table_button.setFixedHeight(26)
        self.generate_table_button.clicked.connect(self.draw_location_table)
        loc_ctrl_row.addWidget(self.generate_table_button)

        self.search_line_edit = QLineEdit()
        self.search_line_edit.setPlaceholderText("Search domain…")
        self.search_line_edit.setFixedHeight(26)
        loc_ctrl_row.addWidget(self.search_line_edit, stretch=1)

        self.search_button = QPushButton("⌕")
        self.search_button.setFixedSize(26, 26)
        self.search_button.clicked.connect(self.search_location_table)
        loc_ctrl_row.addWidget(self.search_button)

        loc_body.addWidget(loc_ctrl)

        self.location_table = QTableWidget()
        self.location_table.setFont(QFont("Cascadia Code", 8))
        self.location_table.setAlternatingRowColors(True)
        self.location_table.setMinimumHeight(160)
        self.location_table.setStyleSheet("""
            QTableWidget {
                background: #181825;
                color: #CDD6F4;
                gridline-color: #313244;
                border: 1px solid #313244;
                border-radius: 4px;
            }
            QHeaderView::section {
                background: #1E1E2E;
                color: #89B4FA;
                border: none;
                padding: 3px;
                font-size: 8px;
            }
        """)
        loc_body.addWidget(self.location_table)
        body_vbox.addWidget(sec_loc)

        # ── Subdomain → URL Tree section ──────────────────────────────────────
        sec_tree, tree_body, _ = _section("Subdomain  →  URL Tree", "#A6E3A1")

        tree_ctrl = QWidget()
        tree_ctrl.setStyleSheet("background:transparent;")
        tree_ctrl_row = QHBoxLayout(tree_ctrl)
        tree_ctrl_row.setContentsMargins(0, 0, 0, 0)
        tree_ctrl_row.setSpacing(4)

        self.subdomainsButton = QPushButton("⊕  Load Tree")
        self.subdomainsButton.setFixedHeight(28)
        self.subdomainsButton.clicked.connect(self.UrlsScan)
        tree_ctrl_row.addWidget(self.subdomainsButton)

        self.urlsButton = QPushButton("⟳  Scan URLs")
        self.urlsButton.setFixedHeight(28)
        self.urlsButton.clicked.connect(self.UrlsScan)
        tree_ctrl_row.addWidget(self.urlsButton)

        tree_body.addWidget(tree_ctrl)

        self.subdomainsModel = QStandardItemModel()
        self.subdomainsModel.setHorizontalHeaderLabels(["Subdomain  /  URL"])
        self.subdomainsTreeView = QTreeView()
        self.subdomainsTreeView.setFont(QFont("Cascadia Code", 9))
        self.subdomainsTreeView.header().setFont(QFont("Cascadia Code", 8))
        self.subdomainsTreeView.setModel(self.subdomainsModel)
        self.subdomainsTreeView.doubleClicked.connect(self.openLinkInBrowser)
        self.subdomainsTreeView.setAlternatingRowColors(True)
        self.subdomainsTreeView.setAnimated(True)
        self.subdomainsTreeView.setUniformRowHeights(True)
        self.subdomainsTreeView.setEditTriggers(QTreeView.NoEditTriggers)
        self.subdomainsTreeView.setMinimumHeight(200)
        self.subdomainsTreeView.setStyleSheet("""
            QTreeView {
                background: #181825;
                color: #CDD6F4;
                border: 1px solid #313244;
                border-radius: 4px;
            }
            QTreeView::item:hover     { background: #313244; }
            QTreeView::item:selected  { background: #45475A; color: #CDD6F4; }
            QHeaderView::section {
                background: #1E1E2E;
                color: #A6E3A1;
                border: none;
                padding: 3px;
                font-size: 8px;
            }
        """)
        tree_body.addWidget(self.subdomainsTreeView)
        body_vbox.addWidget(sec_tree)

        body_vbox.addStretch()
        root_vbox.addWidget(scroll, stretch=1)

        # ── Legacy attribute stubs (keep external code working) ───────────────
        # hideGenInfo() is wired to nothing now; kept as no-op below
        self.general_information_frame = QFrame()   # invisible placeholder
        self.infoShowCheckBox = QCheckBox()         # invisible placeholder

    def search_location_table(self):
        if self.location_table_drawn:
            user_search_domain = self.search_line_edit.text()
            got_match = False
            for row_dict in self.location_table_item_dicts:
                subdomain = row_dict["subdomain"]
                if subdomain == user_search_domain:
                    item = row_dict["WidgetItems"][0]
                    row_index = row_dict["index"]
                    got_match = True
                    self.location_table.scrollToItem(item)
                    self.location_table.selectRow(row_index)
            if got_match is False:
                search_fail_mb = MessageBox("No results found", "No subdomain found that matches the item you searched", "Information")
                search_fail_mb.exec()
                
        else:
            mb=MessageBox("Information", "The location table has not been drawn. \nDo you want to generate the table ?", "Question", buttons=["Ok", "Cancel"])
            ret = mb.exec()
            if ret == QMessageBox.Ok:
                self.draw_location_table()

    def widget(self):
        if self._embed:
            return self._panel_widget
        return self._dock

    def draw_location_table(self):
        if not self.location_table_drawn:
            # get the amass data
            if Path(self.amass_data_json_file).exists():
                self.location_table.setColumnCount(6)
                self.location_table.setFixedHeight(800)
                with open(self.amass_data_json_file, "r") as data_file:
                    data_dict  = dict(json.loads(data_file.read()))
                domain_infodicts = list(data_dict.values())[0]
                data = []
                subdomains = []
                managers = []
                for domain_infodict in domain_infodicts:
                    domain_info_list = []

                    domain_name = domain_infodict["subdomain"]
                    subdomains.append(domain_name)

                    domain_info_list.append(domain_name)
                    name_record = domain_infodict["namerecord"]
                    domain_info_list.append(name_record)
                    ips_str = ""
                    if len(domain_infodict["ip"]) == 1:
                        ips_str = list(domain_infodict["ip"])[0]
                    else:
                        for index, ip in enumerate(domain_infodict["ip"]):
                            if index == len(domain_infodict["ip"]):
                                ips_str = ips_str + ip
                            else:
                                ips_str = ips_str + ip + "\n"
                    domain_info_list.append(ips_str)
                    netblock = domain_infodict["netblock"]
                    domain_info_list.append(netblock)
                    asn = domain_infodict["asn"]
                    domain_info_list.append(asn)

                    manager = domain_infodict["manager"]
                    managers.append(manager)

                    domain_info_list.append(manager)
                    data.append(domain_info_list)
                self.location_table.setRowCount(len(domain_infodicts))

                # set the column width for the subdomain name column
                longest_length = 0
                for domain_name in subdomains:
                    len_domain_name = len(domain_name)
                    if len_domain_name > longest_length:
                        longest_length = len_domain_name

                column_width = 200
                for column_index in range(6):
                    if column_index != 4 and column_index != 1:
                        self.location_table.setColumnWidth(column_index, column_width)
                self.location_table.setColumnWidth(4, 80) # asn column
                self.location_table.setColumnWidth(1, 120) #name_record column
                
                # self.location_table.setSizeAdjustPolicy()
                self.location_table.setHorizontalHeaderLabels(["Domain Name", "name record", "Ip(s)", "Netblock", "Asn", "Manager"])
                for row in range(len(data)):
                    row_widget_items_dict = {
                        "index": row,
                        "subdomain":data[row][0],
                        "WidgetItems":[]
                    }
                    row_table_widget_items = []
                    for col in range(len(data[row])):
                        item = QTableWidgetItem(data[row][col])
                        row_table_widget_items.append(item)
                        self.location_table.setItem(row, col, item)
                    row_widget_items_dict["WidgetItems"] = row_table_widget_items
                    self.location_table_item_dicts.append(row_widget_items_dict)
                self.location_table_drawn = True
                
            else:
                no_file_messagebox = MessageBox("File not found", "It seems Amass has not been yet. \n Do you want to run it?",buttons=["Ok", "Cancel"])
                ret_ = no_file_messagebox.exec()
                if ret_ == QMessageBox.Ok:
                    self.main_window.OpenTestTargetWindow()
                    self.main_window.testWindow.tabManager.setCurrentIndex(1)
            # self.location_table.selectRow(200) # highlight a given row
            # self.location_table.scrollToBottom() 
            # Todo: implement the search mechanism using the scroll to mechanism
            
        else:
            drawn_table_messagebox = MessageBox("Table Already Drawn", "Table has already drawn", "Ok")
            drawn_table_messagebox.exec()

    def _run_whois_ui(self):
        if self.whois_displaying or not self.run_whois_button.isEnabled():
            return
        self.run_whois_button.setText("⟳  Running…")
        self.run_whois_button.setEnabled(False)
        self._whoisPill.setText("⟳")
        self.run_whois()

    def run_whois(self):
        self.whois_runner = WhoisThreadRunner(
            top_parent=self.topParent,
            server_name=self.main_window.main_server_name,
            project_dir_path=self.projectDirPath,
        )
        self.whois_runner.start()

    def display_whois_results(self, parent, objectName):
        if self.whois_displaying is False:
            self.whois_results_filename = os.path.join(self.projectDirPath, "whois_results")
            if objectName == "whois runner":
                with open(self.whois_results_filename, "rb") as file:
                    self.whois_text_results = file.read()
                if not self.whois_text_results == b"":
                    self.whois_text_widget.setText(self.whois_text_results.decode("utf-8"))
                    self.whois_displaying = True
                    self._whoisPill.setText("✓")
                    self.run_whois_button.setText("✓  Done")
                else:
                    fail_message_box = MessageBox("Information", "whois returned no information.\ncheck the domain name or the internet connection", "Ok")
                    fail_message_box.exec()
        else:
            d_message_box = MessageBox("Information", "whois has already been run", "Ok")
            d_message_box.exec()


    def hideGenInfo(self):
        pass  # replaced by collapsible sections

    @Slot()
    def UrlsScan(self):
        if Path(self.SubdomainUrlDict_file).exists():
            with open(self.SubdomainUrlDict_file, "r") as f:
                self.SubdomainUrlDict = json.loads(f.read())
            self.subdomainsModel.dataChanged.emit(QModelIndex(), QModelIndex())
            self.updateModel()

    def updateModel(self, **args):
        self.subdomainsModel.clear()
        self.subdomainsModel.setHorizontalHeaderLabels(["Subdomain:UrlsMapping"])
        for subdomain, urls in self.SubdomainUrlDict.items():
            parentItem = QStandardItem(subdomain)
            self.subdomainsModel.appendRow(parentItem)
            for url in urls:
                url_item = QStandardItem(url)
                parentItem.appendRow(url_item)

    @Slot(int)
    def openLinkInBrowser(self, index: QModelIndex):
        clicked_link = self.subdomainsModel.itemFromIndex(index).text()
        self.openLinkInBrw.emit(clicked_link)
