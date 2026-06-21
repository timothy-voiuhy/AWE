"""
Pipeline editor — create or edit a pipeline template.

Custom pipelines are stored in MongoDB (project_settings collection,
key = "custom_pipeline:<name>").  They are loaded alongside built-in
templates in PipelineWindow.
"""
import json
from datetime import datetime, timezone

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QFrame,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from containers.tool_registry import TOOL_REGISTRY, TOOL_CATEGORIES
from pipeline.models import PipelineStep, PipelineTemplate


_CONDITIONS = ["always", "if:subdomain", "if:dns", "if:http",
               "if:crawl", "if:params", "if:fuzz", "if:vuln", "if:osint"]
_INPUT_CATS  = ["", "subdomain", "dns", "http", "crawl", "params",
                "fuzz", "vuln", "osint"]


class PipelineEditorDialog(QDialog):
    """
    Opens in create mode (template=None) or edit mode (template=PipelineTemplate).
    After accept(), call .result_template() to get the PipelineTemplate.
    """

    def __init__(self, template: PipelineTemplate | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Pipeline Editor" if template is None else f"Edit: {template.name}")
        self.resize(820, 560)
        self._result: PipelineTemplate | None = None

        vbox = QVBoxLayout(self)
        vbox.setSpacing(8)

        # ── Header form ───────────────────────────────────────────────────────
        header = QFormLayout()
        self._nameEdit = QLineEdit()
        self._nameEdit.setPlaceholderText("My Custom Pipeline")
        header.addRow("Name:", self._nameEdit)

        self._descEdit = QLineEdit()
        self._descEdit.setPlaceholderText("What this pipeline does")
        header.addRow("Description:", self._descEdit)

        self._catCombo = QComboBox()
        for c in ["general", "quick", "recon", "content", "vuln", "osint", "full"]:
            self._catCombo.addItem(c, c)
        header.addRow("Category:", self._catCombo)
        vbox.addLayout(header)

        vbox.addWidget(self._hline())

        # ── Steps table ───────────────────────────────────────────────────────
        label = QLabel("Steps  (each row = one tool execution)")
        label.setObjectName("certStepLabel")
        vbox.addWidget(label)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Tool", "Stage", "Condition", "Input From"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setFont(QFont("Cascadia Code", 9))
        self._table.setObjectName("siteMapTreeView")
        vbox.addWidget(self._table)

        # ── Row controls ──────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        addBtn = QPushButton("+ Add Step")
        addBtn.clicked.connect(self._add_row)
        btn_row.addWidget(addBtn)

        removeBtn = QPushButton("Remove Selected")
        removeBtn.clicked.connect(self._remove_selected)
        btn_row.addWidget(removeBtn)

        upBtn   = QPushButton("↑")
        downBtn = QPushButton("↓")
        upBtn.setFixedWidth(32)
        downBtn.setFixedWidth(32)
        upBtn.clicked.connect(lambda: self._move_row(-1))
        downBtn.clicked.connect(lambda: self._move_row(1))
        btn_row.addWidget(upBtn)
        btn_row.addWidget(downBtn)
        btn_row.addStretch()

        helpLabel = QLabel("Tip: give parallel tools the same Stage number")
        helpLabel.setObjectName("certDialogSubtitle")
        btn_row.addWidget(helpLabel)
        vbox.addLayout(btn_row)

        # ── Dialog buttons ────────────────────────────────────────────────────
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_save)
        buttons.rejected.connect(self.reject)
        vbox.addWidget(buttons)

        if template:
            self._populate(template)

    # ── Population ────────────────────────────────────────────────────────────

    def _populate(self, tmpl: PipelineTemplate):
        self._nameEdit.setText(tmpl.name)
        self._descEdit.setText(tmpl.description)
        idx = self._catCombo.findData(tmpl.category)
        if idx >= 0:
            self._catCombo.setCurrentIndex(idx)
        for step in tmpl.steps:
            self._add_row(step)

    def _add_row(self, step: PipelineStep | None = None):
        row = self._table.rowCount()
        self._table.insertRow(row)

        tool_combo = QComboBox()
        for key, tool in sorted(TOOL_REGISTRY.items(), key=lambda kv: kv[1].display_name):
            tool_combo.addItem(f"{tool.display_name}  [{tool.category}]", key)
        self._table.setCellWidget(row, 0, tool_combo)

        stage_edit = QLineEdit("0")
        stage_edit.setFixedWidth(48)
        self._table.setCellWidget(row, 1, stage_edit)

        cond_combo = QComboBox()
        for c in _CONDITIONS:
            cond_combo.addItem(c, c)
        self._table.setCellWidget(row, 2, cond_combo)

        input_combo = QComboBox()
        for c in _INPUT_CATS:
            input_combo.addItem(c or "(none)", c)
        self._table.setCellWidget(row, 3, input_combo)

        if step:
            idx = tool_combo.findData(step.tool_key)
            if idx >= 0:
                tool_combo.setCurrentIndex(idx)
            stage_edit.setText(str(step.stage))
            cidx = cond_combo.findData(step.condition)
            if cidx >= 0:
                cond_combo.setCurrentIndex(cidx)
            iidx = input_combo.findData(step.input_category or "")
            if iidx >= 0:
                input_combo.setCurrentIndex(iidx)

    def _remove_selected(self):
        rows = sorted({idx.row() for idx in self._table.selectedIndexes()}, reverse=True)
        for r in rows:
            self._table.removeRow(r)

    def _move_row(self, direction: int):
        row = self._table.currentRow()
        target = row + direction
        if target < 0 or target >= self._table.rowCount():
            return
        # swap widget states
        for col in range(self._table.columnCount()):
            w1 = self._table.cellWidget(row, col)
            w2 = self._table.cellWidget(target, col)
            self._swap_widget(row, target, col)
        self._table.setCurrentCell(target, 0)

    def _swap_widget(self, r1: int, r2: int, col: int):
        def _state(r):
            w = self._table.cellWidget(r, col)
            if isinstance(w, QComboBox):   return ("combo", w.currentIndex())
            if isinstance(w, QLineEdit):   return ("edit",  w.text())
            return None

        s1, s2 = _state(r1), _state(r2)
        def _apply(r, s):
            w = self._table.cellWidget(r, col)
            if s[0] == "combo": w.setCurrentIndex(s[1])
            elif s[0] == "edit": w.setText(s[1])

        if s1 and s2:
            _apply(r1, s2)
            _apply(r2, s1)

    # ── Save ──────────────────────────────────────────────────────────────────

    def _on_save(self):
        name = self._nameEdit.text().strip()
        if not name:
            QMessageBox.warning(self, "Missing name", "Enter a pipeline name.")
            return
        if self._table.rowCount() == 0:
            QMessageBox.warning(self, "No steps", "Add at least one step.")
            return

        steps = []
        for row in range(self._table.rowCount()):
            tool_key = self._table.cellWidget(row, 0).currentData()
            try:
                stage = int(self._table.cellWidget(row, 1).text())
            except ValueError:
                stage = 0
            condition    = self._table.cellWidget(row, 2).currentData()
            input_cat    = self._table.cellWidget(row, 3).currentData() or None
            steps.append(PipelineStep(tool_key=tool_key, stage=stage,
                                       condition=condition, input_category=input_cat))

        key = "custom_" + name.lower().replace(" ", "_")
        self._result = PipelineTemplate(
            key=key,
            name=name,
            description=self._descEdit.text().strip(),
            category=self._catCombo.currentData(),
            steps=steps,
        )
        self.accept()

    def result_template(self) -> PipelineTemplate | None:
        return self._result

    @staticmethod
    def _hline() -> QFrame:
        f = QFrame()
        f.setFrameShape(QFrame.HLine)
        f.setObjectName("certDivider")
        return f


def pipeline_to_dict(tmpl: PipelineTemplate) -> dict:
    return {
        "key":         tmpl.key,
        "name":        tmpl.name,
        "description": tmpl.description,
        "category":    tmpl.category,
        "steps": [
            {
                "tool_key":       s.tool_key,
                "stage":          s.stage,
                "condition":      s.condition,
                "input_category": s.input_category,
                "extra_params":   s.extra_params,
            }
            for s in tmpl.steps
        ],
    }


def pipeline_from_dict(d: dict) -> PipelineTemplate:
    steps = [
        PipelineStep(
            tool_key=s["tool_key"],
            stage=s.get("stage", 0),
            condition=s.get("condition", "always"),
            input_category=s.get("input_category"),
            extra_params=s.get("extra_params", {}),
        )
        for s in d.get("steps", [])
    ]
    return PipelineTemplate(
        key=d["key"],
        name=d["name"],
        description=d.get("description", ""),
        category=d.get("category", "general"),
        steps=steps,
    )
