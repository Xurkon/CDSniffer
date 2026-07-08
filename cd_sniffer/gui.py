from __future__ import annotations

import argparse
import html
import json
import importlib.resources as resources
import queue
import re
import shlex
import traceback
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .archive_index import (
    build_archive_index,
    correlate_capture_to_archive,
    export_cached_archive_match,
    render_archive_correlation_csv,
    render_archive_correlation_markdown,
    render_archive_index_csv,
    render_archive_index_markdown,
    select_archive_entries,
)
from .correlator import correlate_capture_to_files, render_correlation_csv, render_correlation_markdown
from .dmm import render_dmm_patch_draft
from .paths import project_logs_dir, project_root, resolve_project_path

try:
    from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal, Slot
    from PySide6.QtGui import QColor, QFont, QIcon, QPalette, QTextCharFormat, QTextCursor
    from PySide6.QtWidgets import (
        QApplication,
        QMenu,
        QCheckBox,
        QComboBox,
        QDialog,
        QDialogButtonBox,
        QFileDialog,
        QFormLayout,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QSpinBox,
        QDoubleSpinBox,
        QSplitter,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QLineEdit,
        QSystemTrayIcon,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover - import guard for optional GUI dependency
    _GUI_IMPORT_ERROR = exc
    class _MissingQtObject:
        pass

    class _MissingSignal:
        def connect(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    def _missing_signal(*_args: Any, **_kwargs: Any) -> _MissingSignal:
        return _MissingSignal()

    def _missing_slot(*_args: Any, **_kwargs: Any):
        def decorator(func):
            return func

        return decorator

    QApplication = _MissingQtObject  # type: ignore[assignment]
    QObject = _MissingQtObject  # type: ignore[assignment]
    Qt = _MissingQtObject  # type: ignore[assignment]
    QThread = _MissingQtObject  # type: ignore[assignment]
    Signal = _missing_signal  # type: ignore[assignment]
    Slot = _missing_slot  # type: ignore[assignment]
    QColor = _MissingQtObject  # type: ignore[assignment]
    QFont = _MissingQtObject  # type: ignore[assignment]
    QPalette = _MissingQtObject  # type: ignore[assignment]
    QTextCharFormat = _MissingQtObject  # type: ignore[assignment]
    QTextCursor = _MissingQtObject  # type: ignore[assignment]
    QCheckBox = _MissingQtObject  # type: ignore[assignment]
    QComboBox = _MissingQtObject  # type: ignore[assignment]
    QDialog = _MissingQtObject  # type: ignore[assignment]
    QDialogButtonBox = _MissingQtObject  # type: ignore[assignment]
    QFileDialog = _MissingQtObject  # type: ignore[assignment]
    QFormLayout = _MissingQtObject  # type: ignore[assignment]
    QGridLayout = _MissingQtObject  # type: ignore[assignment]
    QGroupBox = _MissingQtObject  # type: ignore[assignment]
    QHBoxLayout = _MissingQtObject  # type: ignore[assignment]
    QHeaderView = _MissingQtObject  # type: ignore[assignment]
    QLabel = _MissingQtObject  # type: ignore[assignment]
    QLineEdit = _MissingQtObject  # type: ignore[assignment]
    QListWidget = _MissingQtObject  # type: ignore[assignment]
    QListWidgetItem = _MissingQtObject  # type: ignore[assignment]
    QMainWindow = _MissingQtObject  # type: ignore[assignment]
    QMessageBox = _MissingQtObject  # type: ignore[assignment]
    QPlainTextEdit = _MissingQtObject  # type: ignore[assignment]
    QPushButton = _MissingQtObject  # type: ignore[assignment]
    QSpinBox = _MissingQtObject  # type: ignore[assignment]
    QDoubleSpinBox = _MissingQtObject  # type: ignore[assignment]
    QSplitter = _MissingQtObject  # type: ignore[assignment]
    QTabWidget = _MissingQtObject  # type: ignore[assignment]
    QTableWidget = _MissingQtObject  # type: ignore[assignment]
    QTableWidgetItem = _MissingQtObject  # type: ignore[assignment]
    QTextEdit = _MissingQtObject  # type: ignore[assignment]
    QVBoxLayout = _MissingQtObject  # type: ignore[assignment]
    QWidget = _MissingQtObject  # type: ignore[assignment]
else:
    _GUI_IMPORT_ERROR = None

from .core import (
    CAPTURE_GATE_MATCH_MODES,
    CAPTURE_GATE_MODES,
    build_keywords,
    build_comparison,
    build_manifest,
    capture_gate_matches,
    capture_once,
    collect_matching_windows,
    filter_payload_unique_hits,
    finalize_payload,
    load_signature_pack,
    merge_signature_packs,
    print_summary,
    render_csv_snapshot,
    render_markdown_snapshot,
    flatten_search_results,
    resolve_pid,
    render_search_results_csv,
    render_search_results_markdown,
    search_capture_directory,
    search_flattened_hits,
    search_payload_values,
    timestamped_output_path,
    validate_regex_patterns,
    write_manifest,
    write_rendered_snapshot,
    write_snapshot,
)
from .ipc import GuiCommand, GuiIpcServer
from .windows import close_handle, get_window_pid, is_key_triggered, is_process_running, open_process, vk_from_name


def apply_modern_theme(app: QApplication) -> None:
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#11161f"))
    palette.setColor(QPalette.WindowText, QColor("#eef2ff"))
    palette.setColor(QPalette.Base, QColor("#0b1020"))
    palette.setColor(QPalette.AlternateBase, QColor("#151b2d"))
    palette.setColor(QPalette.ToolTipBase, QColor("#eef2ff"))
    palette.setColor(QPalette.ToolTipText, QColor("#eef2ff"))
    palette.setColor(QPalette.Text, QColor("#eef2ff"))
    palette.setColor(QPalette.Button, QColor("#1d2740"))
    palette.setColor(QPalette.ButtonText, QColor("#eef2ff"))
    palette.setColor(QPalette.BrightText, QColor("#ff5d73"))
    palette.setColor(QPalette.Highlight, QColor("#58a6ff"))
    palette.setColor(QPalette.HighlightedText, QColor("#08111f"))
    app.setPalette(palette)
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(
        """
        QMainWindow, QWidget {
            background: #101620;
            color: #eef2ff;
        }
        QTabWidget::pane {
            border: 0;
            background: #101620;
            top: -1px;
        }
        QTabBar::tab {
            background: #172235;
            color: #cfd8ef;
            padding: 11px 18px;
            margin-right: 4px;
            border-radius: 8px;
        }
        QTabBar::tab:hover {
            background: #1d2a41;
        }
        QTabBar::tab:selected {
            background: #25405f;
            color: #ffffff;
        }
        QGroupBox {
            border: 0;
            border-radius: 8px;
            margin-top: 16px;
            padding-top: 16px;
            background: #141c2a;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 4px;
            color: #9fc7ff;
            font-weight: 600;
        }
        QLabel {
            color: #eef2ff;
        }
        QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {
            background: #0c1220;
            border: 1px solid #26344d;
            border-radius: 8px;
            padding: 8px;
            selection-background-color: #58a6ff;
        }
        QPlainTextEdit#settingsPreview {
            border: 0;
            border-radius: 8px;
            background: #0c1220;
        }
        QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {
            border: 1px solid #4f7db8;
        }
        QPlainTextEdit#settingsPreview:focus {
            border: 0;
        }
        QPushButton {
            background: #203451;
            border: 1px solid #345177;
            border-radius: 8px;
            padding: 8px 14px;
        }
        QPushButton:hover {
            background: #2a4568;
        }
        QPushButton:disabled {
            background: #172133;
            color: #6c7b98;
        }
        QTableWidget {
            background: #0c1220;
            alternate-background-color: #111927;
            gridline-color: #1d2a3f;
            border: 0;
            border-radius: 8px;
        }
        QHeaderView::section {
            background: #182233;
            color: #eef2ff;
            padding: 8px;
            border: none;
            border-bottom: 1px solid #25324a;
        }
        QCheckBox {
            spacing: 8px;
        }
        """
    )


def split_values(text: str) -> list[str]:
    values: list[str] = []
    for raw_line in text.splitlines():
        for part in raw_line.split(","):
            item = part.strip()
            if item:
                values.append(item)
    return values


def parse_int(text: str, default: int | None = None) -> int | None:
    value = text.strip()
    if not value:
        return default
    return int(value)


def verbosity_mode(quiet: bool, verbose: bool) -> str:
    if quiet:
        return "quiet"
    if verbose:
        return "verbose"
    return "normal"


def payload_to_text(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


def join_values(values: list[str] | None) -> str:
    return "\n".join(values or [])


def load_app_icon() -> QIcon:
    icon_file = resources.files("cd_sniffer").joinpath("assets/cdsniffer.svg")
    with resources.as_file(icon_file) as resolved:
        return QIcon(str(resolved))


def set_widget_tips(items: list[tuple[Any, str]]) -> None:
    for widget, tip in items:
        widget.setToolTip(tip)
        widget.setStatusTip(tip)


def normalize_hotkey_name(value: Any) -> str:
    hotkey = str(value if value is not None else "F8").strip().upper() or "F8"
    vk_from_name(hotkey)
    return hotkey


def validate_settings_dict(settings: dict[str, Any]) -> None:
    mode = str(settings.get("mode", "loop"))
    if mode not in {"once", "loop", "hotkey"}:
        raise ValueError(f"Unsupported capture mode: {mode}")

    def require_minimum(field: str, minimum: float, *, allow_zero: bool = True) -> None:
        if field not in settings or settings[field] is None:
            return
        value = settings[field]
        if isinstance(value, bool):
            raise ValueError(f"{field} must be numeric")
        if float(value) < minimum or (not allow_zero and float(value) == minimum):
            comparator = "greater than" if not allow_zero else "at least"
            raise ValueError(f"{field} must be {comparator} {minimum}")

    require_minimum("interval", 0.0, allow_zero=False)
    require_minimum("captures", 0.0)
    require_minimum("summary_limit", 1.0, allow_zero=False)
    require_minimum("compare_limit", 1.0, allow_zero=False)
    require_minimum("max_region_size", 1.0, allow_zero=False)
    require_minimum("context_bytes", 0.0)
    require_minimum("context_number_radius", 0.0)
    require_minimum("gate_max_regions", 0.0)
    require_minimum("gate_max_hits_per_region", 0.0)
    normalize_hotkey_name(settings.get("hotkey", "F8"))


def format_action_log(action: str, **fields: Any) -> str:
    payload = {"action": action, **fields}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def require_path(value: str, label: str, *, kind: str = "path") -> Path:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{label} is required.")
    path = Path(text)
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    if kind == "file" and not path.is_file():
        raise ValueError(f"{label} must be a file: {path}")
    if kind == "dir" and not path.is_dir():
        raise ValueError(f"{label} must be a folder: {path}")
    return path


class HotkeyLineEdit(QLineEdit):
    capture_prompt = "Click the field and press a key."

    hotkey_state_changed = Signal(str)

    def __init__(self, text: str = "") -> None:
        super().__init__(text)
        self.setReadOnly(True)
        self.setClearButtonEnabled(True)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setPlaceholderText(self.capture_prompt)

    def _set_capture_state(self, message: str) -> None:
        self.hotkey_state_changed.emit(message)

    def _begin_capture(self) -> None:
        self.setFocus(Qt.MouseFocusReason)
        self.selectAll()
        self._set_capture_state("Press a key to record the hotkey.")

    def mousePressEvent(self, event) -> None:  # noqa: ANN001 - Qt event type varies by binding
        self._begin_capture()
        event.accept()

    def focusInEvent(self, event) -> None:  # noqa: ANN001 - Qt event type varies by binding
        super().focusInEvent(event)
        self.selectAll()
        self._set_capture_state("Press a key to record the hotkey.")

    def focusOutEvent(self, event) -> None:  # noqa: ANN001 - Qt event type varies by binding
        super().focusOutEvent(event)
        self._set_capture_state(self.capture_prompt)

    def keyPressEvent(self, event) -> None:  # noqa: ANN001 - Qt event type varies by binding
        key = int(event.key())
        if key in {Qt.Key_Control, Qt.Key_Shift, Qt.Key_Alt, Qt.Key_Meta}:
            event.accept()
            return
        if key in {Qt.Key_Backspace, Qt.Key_Delete, Qt.Key_Escape}:
            self.clear()
            self._set_capture_state("Hotkey cleared. Click the field and press a key.")
            event.accept()
            return

        hotkey_name = self._key_name_from_event(event)
        if hotkey_name:
            self.setText(hotkey_name)
            self.selectAll()
            self._set_capture_state(f"Hotkey recorded: {hotkey_name}. Click the field to change it.")
            event.accept()
            return

        super().keyPressEvent(event)

    @staticmethod
    def _key_name_from_event(event) -> str | None:  # noqa: ANN001 - Qt event type varies by binding
        key = int(event.key())
        if Qt.Key_F1 <= key <= Qt.Key_F35:
            return f"F{key - Qt.Key_F1 + 1}"
        if Qt.Key_0 <= key <= Qt.Key_9:
            return chr(key)
        if Qt.Key_A <= key <= Qt.Key_Z:
            return chr(key).upper()

        specials = {
            Qt.Key_Space: "SPACE",
            Qt.Key_Tab: "TAB",
            Qt.Key_Return: "ENTER",
            Qt.Key_Enter: "ENTER",
            Qt.Key_Left: "LEFT",
            Qt.Key_Right: "RIGHT",
            Qt.Key_Up: "UP",
            Qt.Key_Down: "DOWN",
            Qt.Key_Home: "HOME",
            Qt.Key_End: "END",
            Qt.Key_PageUp: "PAGEUP",
            Qt.Key_PageDown: "PAGEDOWN",
            Qt.Key_Insert: "INSERT",
            Qt.Key_Delete: "DELETE",
            Qt.Key_Escape: "ESCAPE",
            Qt.Key_Pause: "PAUSE",
            Qt.Key_CapsLock: "CAPSLOCK",
            Qt.Key_Backspace: "BACKSPACE",
        }
        return specials.get(key)


class SettingsDialog(QDialog):
    def __init__(self, parent: QWidget | None, settings: dict[str, Any]) -> None:
        super().__init__(parent)
        self.setWindowTitle("CDSniffer Settings")
        self.setMinimumSize(980, 760)
        self._settings = dict(settings)

        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.capture_tab = QWidget()
        self.filters_tab = QWidget()
        self.advanced_tab = QWidget()
        self.behavior_tab = QWidget()
        self.tabs.addTab(self.capture_tab, "Capture")
        self.tabs.addTab(self.filters_tab, "Filters")
        self.tabs.addTab(self.advanced_tab, "Advanced")
        self.tabs.addTab(self.behavior_tab, "Behavior")

        self.build_capture_tab()
        self.build_filters_tab()
        self.build_advanced_tab()
        self.build_behavior_tab()
        self.apply_tooltips()

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def build_capture_tab(self) -> None:
        form = QFormLayout(self.capture_tab)
        self.mode = QComboBox()
        self.mode.addItems(["once", "loop", "hotkey"])
        self.mode.setCurrentText(str(self._settings.get("mode", "loop")))
        self.hotkey = HotkeyLineEdit(str(self._settings.get("hotkey", "F8")))
        self.hotkey_state_label = QLabel(HotkeyLineEdit.capture_prompt)
        self.hotkey_state_label.setWordWrap(True)
        self.hotkey_state_label.setStyleSheet("color: #93a4c3; font-size: 11px;")
        self.hotkey.hotkey_state_changed.connect(self.hotkey_state_label.setText)
        self.interval = QDoubleSpinBox()
        self.interval.setRange(0.05, 3600.0)
        self.interval.setDecimals(2)
        self.interval.setValue(float(self._settings.get("interval", 2.0)))
        self.captures = QSpinBox()
        self.captures.setRange(0, 1_000_000)
        self.captures.setSpecialValueText("Unlimited")
        capture_value = self._settings.get("captures")
        self.captures.setValue(int(capture_value) if capture_value else 0)
        self.output = QLineEdit(str(self._settings.get("output", "logs/cdsniffer.jsonl")))
        self.timestamp_output = QCheckBox("Timestamp output")
        self.timestamp_output.setChecked(bool(self._settings.get("timestamp_output", True)))
        self.session_name = QLineEdit(str(self._settings.get("session_name", "cdsniffer")))
        self.format = QComboBox()
        self.format.addItems(["jsonl", "json", "csv", "markdown"])
        self.format.setCurrentText(str(self._settings.get("format", "jsonl")))
        self.label = QLineEdit(str(self._settings.get("label", "capture")))
        self.game_version = QLineEdit(str(self._settings.get("game_version", "")))
        self.capture_gate = QComboBox()
        self.capture_gate.addItems(list(CAPTURE_GATE_MODES))
        self.capture_gate.setCurrentText(str(self._settings.get("capture_gate", "off")))
        self.capture_gate_match = QComboBox()
        self.capture_gate_match.addItems(list(CAPTURE_GATE_MATCH_MODES))
        self.capture_gate_match.setCurrentText(str(self._settings.get("capture_gate_match", "any")))
        self.unique_only = QCheckBox("Only capture new unique hit text")
        self.unique_only.setChecked(bool(self._settings.get("unique_only", False)))
        form.addRow("Mode", self.mode)
        form.addRow("Hotkey", self.hotkey)
        form.addRow("", self.hotkey_state_label)
        form.addRow("Interval", self.interval)
        form.addRow("Captures", self.captures)
        form.addRow("Output", self.output)
        form.addRow("", self.timestamp_output)
        form.addRow("Session Name", self.session_name)
        form.addRow("Format", self.format)
        form.addRow("Label", self.label)
        form.addRow("Game Version", self.game_version)
        form.addRow("Capture Gate", self.capture_gate)
        form.addRow("Gate Match", self.capture_gate_match)
        form.addRow("", self.unique_only)

    def build_filters_tab(self) -> None:
        form = QFormLayout(self.filters_tab)
        self.include_keywords = QPlainTextEdit(join_values(self._settings.get("include_keywords")))
        self.exclude_keywords = QPlainTextEdit(join_values(self._settings.get("exclude_keywords")))
        self.include_patterns = QPlainTextEdit(join_values(self._settings.get("include_patterns")))
        self.exclude_patterns = QPlainTextEdit(join_values(self._settings.get("exclude_patterns")))
        self.signature_packs = QPlainTextEdit(join_values(self._settings.get("signature_packs")))
        self.watch_patterns = QPlainTextEdit(join_values(self._settings.get("watch_patterns")))
        self.gate_keywords = QPlainTextEdit(join_values(self._settings.get("gate_keywords")))
        self.gate_patterns = QPlainTextEdit(join_values(self._settings.get("gate_patterns")))
        self.notes = QPlainTextEdit(join_values(self._settings.get("notes")))
        form.addRow("Include Keywords", self.include_keywords)
        form.addRow("Exclude Keywords", self.exclude_keywords)
        form.addRow("Include Regex", self.include_patterns)
        form.addRow("Exclude Regex", self.exclude_patterns)
        form.addRow("Signature Packs", self.signature_packs)
        form.addRow("Watch Patterns", self.watch_patterns)
        form.addRow("Gate Keywords", self.gate_keywords)
        form.addRow("Gate Regex", self.gate_patterns)
        form.addRow("Notes", self.notes)

    def build_advanced_tab(self) -> None:
        form = QFormLayout(self.advanced_tab)
        self.window_filter_patterns = QPlainTextEdit(join_values(self._settings.get("window_filter_patterns")))
        self.max_region_size = QSpinBox()
        self.max_region_size.setRange(1024, 1024 * 1024 * 1024)
        self.max_region_size.setSingleStep(1024 * 1024)
        self.max_region_size.setValue(int(self._settings.get("max_region_size", 16 * 1024 * 1024)))
        self.max_regions = QSpinBox()
        self.max_regions.setRange(0, 1_000_000)
        self.max_regions.setSpecialValueText("Unlimited")
        max_regions_value = self._settings.get("max_regions")
        self.max_regions.setValue(int(max_regions_value) if max_regions_value else 0)
        self.max_hits_per_region = QSpinBox()
        self.max_hits_per_region.setRange(0, 1_000_000)
        self.max_hits_per_region.setSpecialValueText("Unlimited")
        max_hits_value = self._settings.get("max_hits_per_region")
        self.max_hits_per_region.setValue(int(max_hits_value) if max_hits_value else 0)
        self.context_bytes = QSpinBox()
        self.context_bytes.setRange(0, 4096)
        self.context_bytes.setSingleStep(16)
        self.context_bytes.setValue(int(self._settings.get("context_bytes", 0)))
        self.decode_context_numbers = QCheckBox("Decode context numbers")
        self.decode_context_numbers.setChecked(bool(self._settings.get("decode_context_numbers", False)))
        self.context_number_radius = QSpinBox()
        self.context_number_radius.setRange(0, 512)
        self.context_number_radius.setSingleStep(4)
        self.context_number_radius.setValue(int(self._settings.get("context_number_radius", 16)))
        self.gate_max_regions = QSpinBox()
        self.gate_max_regions.setRange(0, 1_000_000)
        self.gate_max_regions.setSpecialValueText("Unlimited")
        self.gate_max_regions.setValue(int(self._settings.get("gate_max_regions", 6) or 0))
        self.gate_max_hits_per_region = QSpinBox()
        self.gate_max_hits_per_region.setRange(0, 1_000_000)
        self.gate_max_hits_per_region.setSpecialValueText("Unlimited")
        self.gate_max_hits_per_region.setValue(int(self._settings.get("gate_max_hits_per_region", 1) or 0))
        self.summary = QComboBox()
        self.summary.addItems(["none", "top-hits"])
        self.summary.setCurrentText(str(self._settings.get("summary", "none")))
        self.summary_limit = QSpinBox()
        self.summary_limit.setRange(1, 1000)
        self.summary_limit.setValue(int(self._settings.get("summary_limit", 10)))
        self.compare_last = QCheckBox("Compare last")
        self.compare_last.setChecked(bool(self._settings.get("compare_last", False)))
        self.compare_limit = QSpinBox()
        self.compare_limit.setRange(1, 1000)
        self.compare_limit.setValue(int(self._settings.get("compare_limit", 20)))
        self.export_manifest = QCheckBox("Export manifest")
        self.export_manifest.setChecked(bool(self._settings.get("export_manifest", False)))
        self.quiet = QCheckBox("Quiet")
        self.quiet.setChecked(bool(self._settings.get("quiet", False)))
        self.verbose = QCheckBox("Verbose")
        self.verbose.setChecked(bool(self._settings.get("verbose", False)))

        form.addRow("Window Filter Regex", self.window_filter_patterns)
        form.addRow("Max Region Size", self.max_region_size)
        form.addRow("Max Regions", self.max_regions)
        form.addRow("Max Hits/Region", self.max_hits_per_region)
        form.addRow("Context Bytes", self.context_bytes)
        form.addRow("", self.decode_context_numbers)
        form.addRow("Number Decode Radius", self.context_number_radius)
        form.addRow("Gate Max Regions", self.gate_max_regions)
        form.addRow("Gate Max Hits/Region", self.gate_max_hits_per_region)
        form.addRow("Summary", self.summary)
        form.addRow("Summary Limit", self.summary_limit)
        form.addRow("", self.compare_last)
        form.addRow("Compare Limit", self.compare_limit)
        form.addRow("", self.export_manifest)
        form.addRow("", self.quiet)
        form.addRow("", self.verbose)

    def build_behavior_tab(self) -> None:
        form = QFormLayout(self.behavior_tab)
        self.tray_enabled = QCheckBox("Enable tray icon")
        self.tray_enabled.setChecked(bool(self._settings.get("tray_enabled", True)))
        self.tray_start_hidden = QCheckBox("Start hidden to tray")
        self.tray_start_hidden.setChecked(bool(self._settings.get("tray_start_hidden", False)))
        self.tray_minimize_to_tray = QCheckBox("Close/minimize to tray")
        self.tray_minimize_to_tray.setChecked(bool(self._settings.get("tray_minimize_to_tray", True)))
        self.tray_notifications = QCheckBox("Show tray notifications")
        self.tray_notifications.setChecked(bool(self._settings.get("tray_notifications", True)))
        self.tray_click_behavior = QComboBox()
        self.tray_click_behavior.addItems(["toggle", "show", "menu"])
        self.tray_click_behavior.setCurrentText(str(self._settings.get("tray_click_behavior", "toggle")))
        notifications_box = QGroupBox("Tray Notification Events")
        notifications_form = QFormLayout(notifications_box)
        self.tray_notify_game_detected = QCheckBox("Game detected")
        self.tray_notify_game_detected.setChecked(bool(self._settings.get("tray_notify_game_detected", True)))
        self.tray_notify_game_lost = QCheckBox("Game lost")
        self.tray_notify_game_lost.setChecked(bool(self._settings.get("tray_notify_game_lost", True)))
        self.tray_notify_capture_started = QCheckBox("Capture started")
        self.tray_notify_capture_started.setChecked(bool(self._settings.get("tray_notify_capture_started", True)))
        self.tray_notify_capture_stopped = QCheckBox("Capture stopped")
        self.tray_notify_capture_stopped.setChecked(bool(self._settings.get("tray_notify_capture_stopped", True)))
        self.tray_notify_relinked = QCheckBox("PID relinked")
        self.tray_notify_relinked.setChecked(bool(self._settings.get("tray_notify_relinked", True)))
        self.tray_notify_errors = QCheckBox("Errors")
        self.tray_notify_errors.setChecked(bool(self._settings.get("tray_notify_errors", True)))
        self.tray_notify_capture_complete = QCheckBox("Capture complete")
        self.tray_notify_capture_complete.setChecked(bool(self._settings.get("tray_notify_capture_complete", False)))
        notifications_form.addRow("", self.tray_notify_game_detected)
        notifications_form.addRow("", self.tray_notify_game_lost)
        notifications_form.addRow("", self.tray_notify_capture_started)
        notifications_form.addRow("", self.tray_notify_capture_stopped)
        notifications_form.addRow("", self.tray_notify_relinked)
        notifications_form.addRow("", self.tray_notify_errors)
        notifications_form.addRow("", self.tray_notify_capture_complete)
        form.addRow("", self.tray_enabled)
        form.addRow("", self.tray_start_hidden)
        form.addRow("", self.tray_minimize_to_tray)
        form.addRow("", self.tray_notifications)
        form.addRow("Tray click action", self.tray_click_behavior)
        form.addRow(notifications_box)

    def apply_tooltips(self) -> None:
        set_widget_tips(
            [
                (self.mode, "Choose once for one snapshot, loop for repeated captures, or hotkey to capture only when the configured key is pressed."),
                (self.hotkey, "Click the field and press a key. F8 is the default because it is unlikely to conflict with the game UI."),
                (self.interval, "Seconds between loop captures and hotkey polling checks."),
                (self.captures, "Maximum snapshots before stopping. Leave at Unlimited for manual stop or long-running sessions."),
                (self.output, "Capture log path. JSONL is best for repeated captures because each snapshot is appended as one line."),
                (self.timestamp_output, "Create a fresh timestamped log file for each session so earlier evidence is not overwritten."),
                (self.session_name, "Filename prefix used when timestamped output is enabled."),
                (self.format, "Output format. Use JSONL for capture logs, CSV/Markdown for sharing, and JSON for structured automation."),
                (self.label, "Short label stored with each capture to describe what screen or test case produced it."),
                (self.game_version, "Optional game version note stored in capture metadata for patch-to-patch comparison."),
                (self.capture_gate, "Wait for target UI sentinel strings before recording. Camp mission mode reduces unrelated gameplay noise."),
                (self.capture_gate_match, "Choose whether any gate sentinel or every configured sentinel must be present before capture."),
                (self.unique_only, "Skip hit text already seen earlier in this session to reduce repeated log spam."),
                (self.include_keywords, "Literal text fragments to include in captures. Add one keyword per line."),
                (self.exclude_keywords, "Literal text fragments to suppress when they create noisy or unrelated hits."),
                (self.include_patterns, "Regex patterns for hits to include. Use when a family of values shares a predictable shape."),
                (self.exclude_patterns, "Regex patterns for hits to remove from results."),
                (self.signature_packs, "Paths to shared keyword or regex packs. Add one file path per line."),
                (self.watch_patterns, "Regex patterns that trigger watch alerts when they appear in a capture."),
                (self.gate_keywords, "Custom literal sentinel strings used by the custom capture gate."),
                (self.gate_patterns, "Custom regex sentinel patterns used by the custom capture gate."),
                (self.notes, "Freeform notes saved into session metadata so results can be understood later."),
                (self.window_filter_patterns, "Regex filters for target window titles when process lookup finds multiple candidates."),
                (self.max_region_size, "Skip readable memory regions larger than this many bytes to avoid expensive scans."),
                (self.max_regions, "Maximum matching memory regions to scan per capture. Unlimited is most complete but slower."),
                (self.max_hits_per_region, "Maximum string hits to keep from each region. Use this to limit very noisy pages."),
                (self.context_bytes, "Bytes before and after each hit to save for hex, offset, and nearby-ID analysis."),
                (self.decode_context_numbers, "Decode nearby unsigned integer candidates from captured byte context."),
                (self.context_number_radius, "How far from each hit CDSniffer searches for nearby numeric candidates."),
                (self.gate_max_regions, "Maximum regions scanned during the lightweight capture-gate pre-check."),
                (self.gate_max_hits_per_region, "Maximum gate hits kept per region during the pre-check."),
                (self.summary, "Optional console summary after each capture. Top hits is useful during live testing."),
                (self.summary_limit, "Number of rows included in the capture summary."),
                (self.compare_last, "Compare each snapshot to the previous snapshot in the same session."),
                (self.compare_limit, "Maximum added or removed strings to list in snapshot comparisons."),
                (self.export_manifest, "Write a sidecar JSON manifest containing the exact settings used for the session."),
                (self.quiet, "Reduce console and log chatter for automation or cleaner output."),
                (self.verbose, "Print extra diagnostics while troubleshooting targeting, capture, or archive workflows."),
                (self.tray_enabled, "Show a tray icon for quick show/hide and capture controls."),
                (self.tray_start_hidden, "Launch the GUI hidden in the tray instead of opening the main window."),
                (self.tray_minimize_to_tray, "Keep CDSniffer running in the tray when the window is minimized or closed."),
                (self.tray_notifications, "Enable tray popups for selected capture and game-detection events."),
                (self.tray_click_behavior, "Choose what happens when the tray icon is clicked: toggle window, show window, or open menu."),
                (self.tray_notify_game_detected, "Notify when Crimson Desert is detected and ready to capture."),
                (self.tray_notify_game_lost, "Notify when the target game process is no longer detected."),
                (self.tray_notify_capture_started, "Notify when a capture session starts."),
                (self.tray_notify_capture_stopped, "Notify when a capture session stops."),
                (self.tray_notify_relinked, "Notify when CDSniffer automatically attaches to a restarted game PID."),
                (self.tray_notify_errors, "Notify when capture or archive operations report errors."),
                (self.tray_notify_capture_complete, "Notify when a planned capture batch reaches its configured count."),
            ]
        )

    def settings_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.currentText(),
            "hotkey": normalize_hotkey_name(self.hotkey.text()),
            "interval": float(self.interval.value()),
            "captures": self.captures.value() or None,
            "output": self.output.text().strip() or "logs/cdsniffer.jsonl",
            "timestamp_output": self.timestamp_output.isChecked(),
            "session_name": self.session_name.text().strip() or "cdsniffer",
            "format": self.format.currentText(),
            "label": self.label.text().strip() or "capture",
            "game_version": self.game_version.text().strip(),
            "capture_gate": self.capture_gate.currentText(),
            "capture_gate_match": self.capture_gate_match.currentText(),
            "unique_only": self.unique_only.isChecked(),
            "include_keywords": split_values(self.include_keywords.toPlainText()),
            "exclude_keywords": split_values(self.exclude_keywords.toPlainText()),
            "include_patterns": split_values(self.include_patterns.toPlainText()),
            "exclude_patterns": split_values(self.exclude_patterns.toPlainText()),
            "signature_packs": split_values(self.signature_packs.toPlainText()),
            "watch_patterns": split_values(self.watch_patterns.toPlainText()),
            "gate_keywords": split_values(self.gate_keywords.toPlainText()),
            "gate_patterns": split_values(self.gate_patterns.toPlainText()),
            "notes": split_values(self.notes.toPlainText()),
            "window_filter_patterns": split_values(self.window_filter_patterns.toPlainText()),
            "max_region_size": int(self.max_region_size.value()),
            "max_regions": self.max_regions.value() or None,
            "max_hits_per_region": self.max_hits_per_region.value() or None,
            "context_bytes": int(self.context_bytes.value()),
            "decode_context_numbers": self.decode_context_numbers.isChecked(),
            "context_number_radius": int(self.context_number_radius.value()),
            "gate_max_regions": self.gate_max_regions.value() or None,
            "gate_max_hits_per_region": self.gate_max_hits_per_region.value() or None,
            "summary": self.summary.currentText(),
            "summary_limit": int(self.summary_limit.value()),
            "compare_last": self.compare_last.isChecked(),
            "compare_limit": int(self.compare_limit.value()),
            "export_manifest": self.export_manifest.isChecked(),
            "quiet": self.quiet.isChecked(),
            "verbose": self.verbose.isChecked(),
            "tray_enabled": self.tray_enabled.isChecked(),
            "tray_start_hidden": self.tray_start_hidden.isChecked(),
            "tray_minimize_to_tray": self.tray_minimize_to_tray.isChecked(),
            "tray_notifications": self.tray_notifications.isChecked(),
            "tray_click_behavior": self.tray_click_behavior.currentText(),
            "tray_notify_game_detected": self.tray_notify_game_detected.isChecked(),
            "tray_notify_game_lost": self.tray_notify_game_lost.isChecked(),
            "tray_notify_capture_started": self.tray_notify_capture_started.isChecked(),
            "tray_notify_capture_stopped": self.tray_notify_capture_stopped.isChecked(),
            "tray_notify_relinked": self.tray_notify_relinked.isChecked(),
            "tray_notify_errors": self.tray_notify_errors.isChecked(),
            "tray_notify_capture_complete": self.tray_notify_capture_complete.isChecked(),
        }


class TerminalPanel(QWidget):
    def __init__(self, executor: Callable[[str], str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._executor = executor
        layout = QVBoxLayout(self)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Cascadia Mono", 10))
        self.input = QLineEdit()
        self.input.setPlaceholderText("Type `help` or a CDSniffer terminal command...")
        self.input.returnPressed.connect(self.run_command)
        layout.addWidget(self.output)
        layout.addWidget(self.input)

    def append(self, text: str) -> None:
        self.output.appendPlainText(text)

    def run_command(self) -> None:
        line = self.input.text().strip()
        if not line:
            return
        self.append(f"> {line}")
        self.input.clear()
        result = self._executor(line)
        if result:
            self.append(result)


class WindowPickerDialog(QDialog):
    def __init__(self, parent: QWidget | None, matches: list[tuple[int, int | None, str]]) -> None:
        super().__init__(parent)
        self.setWindowTitle("Pick Window")
        self.setMinimumSize(820, 420)
        self._matches = matches
        layout = QVBoxLayout(self)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter windows...")
        self.list_widget = QListWidget()
        self.list_widget.itemDoubleClicked.connect(self.accept)
        self.search.textChanged.connect(self.filter_items)
        layout.addWidget(self.search)
        layout.addWidget(self.list_widget)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.populate()

    def populate(self) -> None:
        self.list_widget.clear()
        for hwnd, pid, title in self._matches:
            pid_text = f"PID {pid}" if pid else "PID unknown"
            item = QListWidgetItem(f"0x{hwnd:08X}  {pid_text}  {title}")
            item.setData(Qt.UserRole, pid or get_window_pid(hwnd))
            self.list_widget.addItem(item)

    def filter_items(self, text: str) -> None:
        needle = text.lower().strip()
        for index in range(self.list_widget.count()):
            item = self.list_widget.item(index)
            item.setHidden(bool(needle) and needle not in item.text().lower())

    def selected_pid(self) -> int | None:
        item = self.list_widget.currentItem()
        if not item:
            return None
        pid = item.data(Qt.UserRole)
        return int(pid) if pid else None


class CaptureWorker(QObject):
    captured = Signal(dict)
    status = Signal(str)
    error = Signal(str)
    finished = Signal()

    def __init__(self, settings: dict[str, Any]) -> None:
        super().__init__()
        self.settings = settings
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def _open_target(self, args: argparse.Namespace) -> tuple[int | None, int | None]:
        pid = resolve_pid(args)
        if pid is None:
            return None, None
        return open_process(pid), pid

    def _ensure_target_handle(
        self,
        args: argparse.Namespace,
        handle: int | None,
        active_pid: int | None,
    ) -> tuple[int | None, int | None]:
        if handle is not None and is_process_running(handle):
            return handle, active_pid
        if handle is not None:
            close_handle(handle)
        reopened_handle, pid = self._open_target(args)
        if reopened_handle is not None and pid is not None:
            if pid != active_pid:
                self.status.emit(f"Re-linked to PID {pid}.")
            return reopened_handle, pid
        return None, None

    def _capture_payload(
        self,
        handle: int,
        pid: int,
        args: argparse.Namespace,
        include_keywords: list[str],
        exclude_keywords: list[str],
        output_path: Path,
        previous_payload: dict[str, Any] | None,
        seen_texts: set[str],
    ) -> tuple[dict[str, Any] | None, str | None]:
        gate_matched, gate_detail = capture_gate_matches(handle, args)
        if not gate_matched:
            reason = gate_detail.get("reason") or "target UI sentinel was not found"
            return None, f"Capture gate not matched; {reason}."

        payload = capture_once(handle, pid, args, include_keywords, exclude_keywords)
        if gate_detail.get("mode") != "off":
            payload["capture_gate"] = gate_detail
        if getattr(args, "unique_only", False):
            payload = filter_payload_unique_hits(payload, seen_texts)
            if payload.get("hit_count", 0) <= 0:
                return None, "No new unique hits; snapshot skipped."
        return finalize_payload(payload, args, output_path, previous_payload), None

    def _write_payload(self, args: argparse.Namespace, output_path: Path, payload: dict[str, Any]) -> None:
        if args.format in {"csv", "markdown"}:
            write_rendered_snapshot(output_path, payload, args.format)
        else:
            write_snapshot(output_path, payload, args.format)

    @Slot()
    def run(self) -> None:
        handle: int | None = None
        try:
            args = argparse.Namespace(**self.settings)
            merge_signature_packs(args)
            if args.context_bytes < 0:
                raise ValueError("context_bytes cannot be negative")
            if args.context_number_radius < 0:
                raise ValueError("context_number_radius cannot be negative")
            validate_regex_patterns(args.include_patterns, "--include-regex or signature pack include_patterns")
            validate_regex_patterns(args.exclude_patterns, "--exclude-regex or signature pack exclude_patterns")
            validate_regex_patterns(args.window_filter_patterns, "--window-filter-regex")
            validate_regex_patterns(args.watch_patterns, "--watch-pattern")
            validate_regex_patterns(args.gate_patterns, "--gate-regex")
            include_keywords, exclude_keywords = build_keywords(args)
            handle, pid = self._open_target(args)
            if not handle or not pid:
                self.error.emit("No PID selected.")
                return
            output_path = timestamped_output_path(args.output, args.session_name) if args.timestamp_output else Path(args.output)
            if args.export_manifest:
                manifest = build_manifest(args, pid, output_path)
                manifest_path = write_manifest(output_path, manifest)
                self.status.emit(f"Wrote manifest: {manifest_path}")
            hotkey_vk = vk_from_name(args.hotkey)
            previous_payload: dict[str, Any] | None = None
            seen_texts: set[str] = set()
            captures = 0
            if args.mode == "once":
                handle, pid = self._ensure_target_handle(args, handle, pid)
                if not handle or not pid:
                    self.status.emit("Game not running; waiting for relink.")
                    return
                args.pid = pid
                started = time.perf_counter()
                payload, skip_message = self._capture_payload(
                    handle,
                    pid,
                    args,
                    include_keywords,
                    exclude_keywords,
                    output_path,
                    previous_payload,
                    seen_texts,
                )
                if payload is None:
                    self.status.emit(skip_message or "Capture skipped.")
                    return
                payload["capture_duration_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
                self._write_payload(args, output_path, payload)
                self.captured.emit(payload)
                self.status.emit("Capture complete.")
                return

            if args.mode == "loop":
                while not self._stop_event.is_set():
                    handle, pid = self._ensure_target_handle(args, handle, pid)
                    if not handle or not pid:
                        self.status.emit("Game not running; waiting for relink.")
                        if self._stop_event.wait(1.0):
                            break
                        continue
                    args.pid = pid
                    started = time.perf_counter()
                    payload, skip_message = self._capture_payload(
                        handle,
                        pid,
                        args,
                        include_keywords,
                        exclude_keywords,
                        output_path,
                        previous_payload,
                        seen_texts,
                    )
                    if payload is None:
                        self.status.emit(skip_message or "Capture skipped.")
                        if self._stop_event.wait(max(0.01, args.interval)):
                            break
                        continue
                    payload["capture_duration_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
                    self._write_payload(args, output_path, payload)
                    self.captured.emit(payload)
                    self.status.emit(f"Captured {captures + 1} snapshot(s)")
                    previous_payload = payload
                    captures += 1
                    if args.captures is not None and captures >= args.captures:
                        self.status.emit("Capture limit reached.")
                        break
                    if self._stop_event.wait(max(0.01, args.interval)):
                        break
            else:
                last_state = False
                while not self._stop_event.is_set():
                    handle, pid = self._ensure_target_handle(args, handle, pid)
                    if not handle or not pid:
                        self.status.emit("Game not running; waiting for relink.")
                        if self._stop_event.wait(1.0):
                            break
                        last_state = False
                        continue
                    args.pid = pid
                    current_state = is_key_triggered(hotkey_vk)
                    if current_state and not last_state:
                        started = time.perf_counter()
                        payload, skip_message = self._capture_payload(
                            handle,
                            pid,
                            args,
                            include_keywords,
                            exclude_keywords,
                            output_path,
                            previous_payload,
                            seen_texts,
                        )
                        if payload is None:
                            self.status.emit(skip_message or "Capture skipped.")
                            last_state = current_state
                            if self._stop_event.wait(max(0.05, min(args.interval, 0.25))):
                                break
                            continue
                        payload["capture_duration_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
                        self._write_payload(args, output_path, payload)
                        self.captured.emit(payload)
                        self.status.emit(f"Captured {captures + 1} snapshot(s)")
                        previous_payload = payload
                        captures += 1
                        if args.captures is not None and captures >= args.captures:
                            self.status.emit("Capture limit reached.")
                            break
                    last_state = current_state
                    if self._stop_event.wait(max(0.05, min(args.interval, 0.25))):
                        break
            self.status.emit("Capture session stopped.")
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            if handle:
                close_handle(handle)
            self.finished.emit()


class ArchiveTaskWorker(QObject):
    result = Signal(str, dict)
    status = Signal(str)
    error = Signal(str)
    finished = Signal()

    def __init__(self, task: str, params: dict[str, Any]) -> None:
        super().__init__()
        self.task = task
        self.params = params

    @Slot()
    def run(self) -> None:
        try:
            if self.task == "build-index":
                roots = [Path(item) for item in self.params.get("roots", [])]
                self.status.emit(f"Building archive index from {len(roots)} root(s)...")

                def report_progress(current: int, total: int, entry_path: str | None) -> None:
                    if total <= 0:
                        self.status.emit("Indexing archive entries...")
                        return
                    percent = int(round((current / total) * 100)) if current > 0 else 0
                    if current <= 0:
                        self.status.emit(f"Indexing archive entries: 0/{total} (0%)")
                        return
                    detail = f" - {entry_path}" if entry_path else ""
                    self.status.emit(f"Indexing archive entries: {current}/{total} ({percent}%) {detail}".rstrip())

                result = build_archive_index(
                    Path(self.params["db_path"]),
                    roots,
                    paz_dir=Path(self.params["paz_dir"]) if self.params.get("paz_dir") else None,
                    patterns=self.params.get("patterns") or None,
                    limit=self.params.get("limit"),
                    progress_callback=report_progress,
                )
                self.result.emit(self.task, result)
                return
            if self.task == "search-index":
                self.status.emit("Searching archive index...")
                entries = select_archive_entries(
                    Path(self.params["db_path"]),
                    patterns=self.params.get("patterns") or None,
                    path_terms=self.params.get("path_terms") or None,
                    limit=self.params.get("limit"),
                )
                result = {
                    "db_path": self.params["db_path"],
                    "patterns": self.params.get("patterns") or ["*"],
                    "path_terms": self.params.get("path_terms") or [],
                    "entry_count": len(entries),
                    "entries": [entry.to_dict() for entry in entries],
                }
                self.result.emit(self.task, result)
                return
            if self.task == "correlate-archive":
                self.status.emit("Correlating capture against archive index...")
                result = correlate_capture_to_archive(
                    Path(self.params["capture_path"]),
                    Path(self.params["db_path"]),
                    Path(self.params["cache_dir"]),
                    patterns=self.params.get("patterns") or None,
                    path_terms=self.params.get("path_terms") or None,
                    max_entries=int(self.params["max_entries"]),
                    max_matches_per_evidence=int(self.params["max_matches_per_evidence"]),
                    max_total_matches=int(self.params["max_matches"]),
                    include_numeric=bool(self.params["include_numeric"]),
                    context_bytes=int(self.params["context_bytes"]),
                    include_format_hints=bool(self.params["include_format_hints"]),
                    decrypt_xml=bool(self.params["decrypt_xml"]),
                )
                self.result.emit(self.task, result)
                return
            if self.task == "correlate-file":
                selected_file = Path(self.params["selected_file"])
                self.status.emit(f"Correlating capture against {selected_file.name}...")
                result = correlate_capture_to_files(
                    Path(self.params["capture_path"]),
                    selected_file.parent,
                    selected_files=[selected_file],
                    max_matches_per_evidence=int(self.params["max_matches_per_evidence"]),
                    max_total_matches=int(self.params["max_matches"]),
                    include_numeric=bool(self.params["include_numeric"]),
                    context_bytes=int(self.params["context_bytes"]),
                    include_format_hints=bool(self.params["include_format_hints"]),
                )
                self.result.emit(self.task, result)
                return
            if self.task == "correlate-root":
                root = Path(self.params["root_path"])
                baseline_text = str(self.params.get("baseline_path") or "").strip()
                self.status.emit(f"Correlating capture against decoded folder {root}...")
                result = correlate_capture_to_files(
                    Path(self.params["capture_path"]),
                    root,
                    baseline_capture_path=Path(baseline_text) if baseline_text else None,
                    patterns=self.params.get("patterns") or None,
                    max_matches_per_evidence=int(self.params["max_matches_per_evidence"]),
                    max_total_matches=int(self.params["max_matches"]),
                    include_numeric=bool(self.params["include_numeric"]),
                    context_bytes=int(self.params["context_bytes"]),
                    include_format_hints=bool(self.params["include_format_hints"]),
                )
                self.result.emit(self.task, result)
                return
            raise ValueError(f"Unknown archive task: {self.task}")
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self.finished.emit()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("CDSniffer")
        self.setWindowIcon(load_app_icon())
        self.resize(1480, 920)
        self.worker_thread: QThread | None = None
        self.worker: CaptureWorker | None = None
        self.archive_task_thread: QThread | None = None
        self.archive_task_worker: ArchiveTaskWorker | None = None
        self.last_payload: dict[str, Any] | None = None
        self.last_capture_at: datetime | None = None
        self.last_capture_duration_ms: float | None = None
        self._last_target_detected: bool | None = None
        self.ipc_command_queue: queue.Queue[GuiCommand] = queue.Queue()
        self.ipc_server = GuiIpcServer(state_provider=self.ipc_state_snapshot, command_queue=self.ipc_command_queue)
        self.ipc_server.start()
        self._force_close = False
        self.tray_status_action = None
        self.last_error_summary = ""

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs)
        self.status_bar = QWidget()
        status_layout = QHBoxLayout(self.status_bar)
        self.status_icon_label = QLabel()
        self.status_icon_label.setPixmap(load_app_icon().pixmap(18, 18))
        self.status_pid_label = QLabel("PID: -")
        self.status_age_label = QLabel("Age: -")
        self.status_label = QLabel("Idle")
        self.status_label.setWordWrap(False)
        status_layout.addWidget(self.status_icon_label)
        status_layout.addWidget(self.status_pid_label)
        status_layout.addWidget(self.status_age_label)
        status_layout.addWidget(self.status_label, 1)
        outer.addWidget(self.status_bar)

        self.capture_tab = QWidget()
        self.live_tab = QWidget()
        self.search_tab = QWidget()
        self.archives_tab = QWidget()
        self.terminal_tab = QWidget()
        self.log_tab = QWidget()
        self.presets_tab = QWidget()
        self.tabs.addTab(self.capture_tab, "Capture")
        self.tabs.addTab(self.live_tab, "Real-Time")
        self.tabs.addTab(self.search_tab, "Search")
        self.tabs.addTab(self.archives_tab, "Archives")
        self.tabs.addTab(self.terminal_tab, "Terminal")
        self.tabs.addTab(self.log_tab, "Logs")
        self.tabs.addTab(self.presets_tab, "Presets")

        self.build_capture_tab()
        self.build_live_tab()
        self.build_search_tab()
        self.build_archives_tab()
        self.load_search_state()
        self.build_terminal_tab()
        self.build_log_tab()
        self.build_presets_tab()
        self.tray_icon: QSystemTrayIcon | None = None
        self.refresh_tray_configuration()

        self.ipc_timer = QTimer(self)
        self.ipc_timer.timeout.connect(self.process_ipc_commands)
        self.ipc_timer.start(100)
        self.detection_timer = QTimer(self)
        self.detection_timer.timeout.connect(self.refresh_target_indicator)
        self.detection_timer.start(1000)
        self.freshness_timer = QTimer(self)
        self.freshness_timer.timeout.connect(self.update_freshness_view)
        self.freshness_timer.start(1000)
        self.apply_main_tooltips()

    def build_capture_tab(self) -> None:
        layout = QVBoxLayout(self.capture_tab)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)
        self._init_hidden_settings()

        hero = QGroupBox("Session")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(14, 12, 14, 12)
        hero_layout.setSpacing(8)
        self.session_summary = QLabel("")
        self.session_summary.setWordWrap(True)
        self.session_summary.setVisible(False)
        self.window_status = QLabel("No window selected yet.")
        self.window_status.setWordWrap(True)
        self.target_status = QLabel("Game not detected")
        self.target_status.setWordWrap(True)
        self.target_status.setStyleSheet("color: #ff7a90; font-weight: 700;")
        hero_layout.addWidget(self.session_summary)
        hero_layout.addWidget(self.window_status)
        hero_layout.addWidget(self.target_status)
        layout.addWidget(hero)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_capture)
        self.refresh_button = QPushButton("Refresh Window List")
        self.refresh_button.clicked.connect(self.refresh_windows)
        self.settings_button = QPushButton("Settings")
        self.settings_button.clicked.connect(self.open_settings_dialog)
        self.import_profile_button = QPushButton("Import Profile")
        self.import_profile_button.clicked.connect(self.import_settings_profile)
        self.export_profile_button = QPushButton("Export Profile")
        self.export_profile_button.clicked.connect(self.export_settings_profile)
        self.pick_window_button = QPushButton("Pick Window")
        self.pick_window_button.clicked.connect(self.pick_window)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        controls.addWidget(self.refresh_button)
        controls.addWidget(self.pick_window_button)
        controls.addWidget(self.settings_button)
        controls.addWidget(self.import_profile_button)
        controls.addWidget(self.export_profile_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        summary_box = QGroupBox("Current Settings")
        summary_layout = QVBoxLayout(summary_box)
        summary_layout.setContentsMargins(12, 12, 12, 12)
        self.settings_preview = QPlainTextEdit()
        self.settings_preview.setObjectName("settingsPreview")
        self.settings_preview.setReadOnly(True)
        self.settings_preview.setFont(QFont("Cascadia Mono", 10))
        summary_layout.addWidget(self.settings_preview)
        layout.addWidget(summary_box, 1)
        self.refresh_capture_summary()
        self.refresh_target_indicator()

    def _init_hidden_settings(self) -> None:
        self.pid_edit = QLineEdit()
        self.pid_edit.setPlaceholderText("Optional PID")
        self.process_edit = QLineEdit("Crimson Desert")
        self.window_title_edit = QLineEdit()
        self.window_title_edit.setPlaceholderText("Window title fragment")
        self.window_filter_edit = QLineEdit()
        self.window_filter_edit.setPlaceholderText("Regex filter for windows")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["once", "loop", "hotkey"])
        self.mode_combo.setCurrentText("loop")
        self.hotkey_edit = HotkeyLineEdit("F8")
        self.interval_spin = QDoubleSpinBox()
        self.interval_spin.setRange(0.05, 3600.0)
        self.interval_spin.setDecimals(2)
        self.interval_spin.setValue(2.0)
        self.captures_spin = QSpinBox()
        self.captures_spin.setRange(0, 1_000_000)
        self.captures_spin.setSpecialValueText("Unlimited")
        self.output_edit = QLineEdit("logs/cdsniffer.jsonl")
        self.output_browse = QPushButton("Browse")
        self.output_browse.clicked.connect(self.browse_output)
        self.timestamp_check = QCheckBox("Timestamp output")
        self.timestamp_check.setChecked(False)
        self.session_name_edit = QLineEdit("cdsniffer")
        self.format_combo = QComboBox()
        self.format_combo.addItems(["jsonl", "json", "csv", "markdown"])
        self.label_edit = QLineEdit("capture")
        self.game_version_edit = QLineEdit()
        self.capture_gate_combo = QComboBox()
        self.capture_gate_combo.addItems(list(CAPTURE_GATE_MODES))
        self.capture_gate_combo.setCurrentText("off")
        self.capture_gate_match_combo = QComboBox()
        self.capture_gate_match_combo.addItems(list(CAPTURE_GATE_MATCH_MODES))
        self.capture_gate_match_combo.setCurrentText("any")
        self.unique_only_check = QCheckBox("Only capture new unique hit text")
        self.unique_only_check.setChecked(False)
        self.summary_combo = QComboBox()
        self.summary_combo.addItems(["none", "top-hits"])
        self.summary_limit_spin = QSpinBox()
        self.summary_limit_spin.setRange(1, 1000)
        self.summary_limit_spin.setValue(10)
        self.compare_check = QCheckBox("Compare last")
        self.compare_check.setChecked(False)
        self.compare_limit_spin = QSpinBox()
        self.compare_limit_spin.setRange(1, 1000)
        self.compare_limit_spin.setValue(20)
        self.export_manifest_check = QCheckBox("Export manifest")
        self.export_manifest_check.setChecked(False)
        self.quiet_check = QCheckBox("Quiet")
        self.verbose_check = QCheckBox("Verbose")
        self.tray_enabled_check = QCheckBox("Enable tray icon")
        self.tray_enabled_check.setChecked(True)
        self.tray_start_hidden_check = QCheckBox("Start hidden to tray")
        self.tray_start_hidden_check.setChecked(False)
        self.tray_minimize_to_tray_check = QCheckBox("Close/minimize to tray")
        self.tray_minimize_to_tray_check.setChecked(True)
        self.tray_notifications_check = QCheckBox("Show tray notifications")
        self.tray_notifications_check.setChecked(True)
        self.tray_click_behavior_combo = QComboBox()
        self.tray_click_behavior_combo.addItems(["toggle", "show", "menu"])
        self.tray_click_behavior_combo.setCurrentText("toggle")
        self.tray_notify_game_detected_check = QCheckBox("Game detected")
        self.tray_notify_game_detected_check.setChecked(True)
        self.tray_notify_game_lost_check = QCheckBox("Game lost")
        self.tray_notify_game_lost_check.setChecked(True)
        self.tray_notify_capture_started_check = QCheckBox("Capture started")
        self.tray_notify_capture_started_check.setChecked(True)
        self.tray_notify_capture_stopped_check = QCheckBox("Capture stopped")
        self.tray_notify_capture_stopped_check.setChecked(True)
        self.tray_notify_relinked_check = QCheckBox("PID relinked")
        self.tray_notify_relinked_check.setChecked(True)
        self.tray_notify_errors_check = QCheckBox("Errors")
        self.tray_notify_errors_check.setChecked(True)
        self.tray_notify_capture_complete_check = QCheckBox("Capture complete")
        self.tray_notify_capture_complete_check.setChecked(False)
        self.max_region_size = QSpinBox()
        self.max_region_size.setRange(1024, 1024 * 1024 * 1024)
        self.max_region_size.setSingleStep(1024 * 1024)
        self.max_region_size.setValue(16 * 1024 * 1024)
        self.max_regions = QSpinBox()
        self.max_regions.setRange(0, 1_000_000)
        self.max_regions.setSpecialValueText("Unlimited")
        self.max_regions.setValue(0)
        self.max_hits_per_region = QSpinBox()
        self.max_hits_per_region.setRange(0, 1_000_000)
        self.max_hits_per_region.setSpecialValueText("Unlimited")
        self.max_hits_per_region.setValue(0)
        self.context_bytes_spin = QSpinBox()
        self.context_bytes_spin.setRange(0, 4096)
        self.context_bytes_spin.setSingleStep(16)
        self.context_bytes_spin.setValue(0)
        self.decode_context_numbers_check = QCheckBox("Decode context numbers")
        self.decode_context_numbers_check.setChecked(False)
        self.context_number_radius_spin = QSpinBox()
        self.context_number_radius_spin.setRange(0, 512)
        self.context_number_radius_spin.setSingleStep(4)
        self.context_number_radius_spin.setValue(16)
        self.gate_max_regions_spin = QSpinBox()
        self.gate_max_regions_spin.setRange(0, 1_000_000)
        self.gate_max_regions_spin.setSpecialValueText("Unlimited")
        self.gate_max_regions_spin.setValue(6)
        self.gate_max_hits_per_region_spin = QSpinBox()
        self.gate_max_hits_per_region_spin.setRange(0, 1_000_000)
        self.gate_max_hits_per_region_spin.setSpecialValueText("Unlimited")
        self.gate_max_hits_per_region_spin.setValue(1)
        self.watch_edit = QPlainTextEdit()
        self.watch_edit.setPlaceholderText("One regex per line for watch alerts")
        self.gate_keywords_edit = QPlainTextEdit()
        self.gate_keywords_edit.setPlaceholderText("Extra capture-gate keywords, one per line")
        self.gate_regex_edit = QPlainTextEdit()
        self.gate_regex_edit.setPlaceholderText("Capture-gate regex patterns, one per line")
        self.signature_pack_edit = QPlainTextEdit()
        self.signature_pack_edit.setPlaceholderText("One signature pack path per line")
        self.include_keywords_edit = QPlainTextEdit()
        self.include_keywords_edit.setPlaceholderText("One keyword per line or comma-separated")
        self.exclude_keywords_edit = QPlainTextEdit()
        self.exclude_keywords_edit.setPlaceholderText("One keyword per line or comma-separated")
        self.include_regex_edit = QPlainTextEdit()
        self.include_regex_edit.setPlaceholderText("One regex per line")
        self.exclude_regex_edit = QPlainTextEdit()
        self.exclude_regex_edit.setPlaceholderText("One regex per line")
        self.notes_edit = QPlainTextEdit()
        self.notes_edit.setPlaceholderText("Optional session notes")
        self.connect_capture_summary_signals()
        self._apply_default_settings()

    def connect_capture_summary_signals(self) -> None:
        widgets: list[tuple[Any, str]] = [
            (self.pid_edit, "textChanged"),
            (self.process_edit, "textChanged"),
            (self.window_title_edit, "textChanged"),
            (self.window_filter_edit, "textChanged"),
            (self.mode_combo, "currentTextChanged"),
            (self.hotkey_edit, "textChanged"),
            (self.interval_spin, "valueChanged"),
            (self.captures_spin, "valueChanged"),
            (self.output_edit, "textChanged"),
            (self.timestamp_check, "toggled"),
            (self.session_name_edit, "textChanged"),
            (self.format_combo, "currentTextChanged"),
            (self.label_edit, "textChanged"),
            (self.game_version_edit, "textChanged"),
            (self.capture_gate_combo, "currentTextChanged"),
            (self.capture_gate_match_combo, "currentTextChanged"),
            (self.unique_only_check, "toggled"),
            (self.context_bytes_spin, "valueChanged"),
            (self.decode_context_numbers_check, "toggled"),
            (self.context_number_radius_spin, "valueChanged"),
            (self.max_region_size, "valueChanged"),
            (self.max_regions, "valueChanged"),
            (self.max_hits_per_region, "valueChanged"),
            (self.include_keywords_edit, "textChanged"),
            (self.exclude_keywords_edit, "textChanged"),
            (self.include_regex_edit, "textChanged"),
            (self.exclude_regex_edit, "textChanged"),
            (self.signature_pack_edit, "textChanged"),
            (self.watch_edit, "textChanged"),
            (self.gate_keywords_edit, "textChanged"),
            (self.gate_regex_edit, "textChanged"),
            (self.gate_max_regions_spin, "valueChanged"),
            (self.gate_max_hits_per_region_spin, "valueChanged"),
            (self.summary_combo, "currentTextChanged"),
            (self.summary_limit_spin, "valueChanged"),
            (self.compare_check, "toggled"),
            (self.compare_limit_spin, "valueChanged"),
            (self.export_manifest_check, "toggled"),
            (self.quiet_check, "toggled"),
            (self.verbose_check, "toggled"),
            (self.notes_edit, "textChanged"),
            (self.tray_enabled_check, "toggled"),
            (self.tray_start_hidden_check, "toggled"),
            (self.tray_minimize_to_tray_check, "toggled"),
            (self.tray_notifications_check, "toggled"),
            (self.tray_click_behavior_combo, "currentTextChanged"),
            (self.tray_notify_game_detected_check, "toggled"),
            (self.tray_notify_game_lost_check, "toggled"),
            (self.tray_notify_capture_started_check, "toggled"),
            (self.tray_notify_capture_stopped_check, "toggled"),
            (self.tray_notify_relinked_check, "toggled"),
            (self.tray_notify_errors_check, "toggled"),
            (self.tray_notify_capture_complete_check, "toggled"),
        ]
        for widget, signal_name in widgets:
            signal = getattr(widget, signal_name, None)
            if signal is not None:
                signal.connect(self.refresh_capture_summary)

    def apply_main_tooltips(self) -> None:
        tips = {
            "start_button": "Start capturing with the current settings shown in the dashboard.",
            "stop_button": "Stop the active capture session.",
            "refresh_button": "Refresh Crimson Desert detection and update the game status indicator.",
            "pick_window_button": "Manually choose a target window when auto-detection is ambiguous.",
            "settings_button": "Open the full settings dialog for capture, filters, advanced scan limits, and tray behavior.",
            "import_profile_button": "Load a saved settings profile JSON into the current GUI session.",
            "export_profile_button": "Save the current GUI settings as a reusable profile JSON.",
            "settings_preview": "Read-only summary of the current capture configuration. Use Settings to edit values.",
            "target_status": "Shows whether Crimson Desert is currently detected and ready for capture.",
            "process_edit": "Process name fragment used for auto-detection. The default targets Crimson Desert.",
            "window_title_edit": "Optional window title fragment used if process lookup needs help.",
            "window_filter_edit": "Regex window-title filter used to narrow ambiguous target windows.",
            "pid_edit": "Optional exact process ID. Leave blank to auto-detect Crimson Desert.",
            "hotkey_edit": "Click the field and press a single supported key like F8, G, or PageDown.",
            "live_search_edit": "Search within the current real-time capture without changing the saved capture payload.",
            "live_search_history_combo": "Recent live searches for quick reuse.",
            "live_search_regex_check": "Treat the live search query as a regular expression.",
            "live_search_case_check": "Require exact casing when searching the current capture.",
            "live_search_filter_table_check": "Show only matching rows in the top-hits table while searching.",
            "live_search_name_edit": "Name used when saving the current live search as a preset.",
            "saved_search_combo": "Saved live-search presets stored in your local CDSniffer profile.",
            "save_search_button": "Save the current live search query and options.",
            "apply_saved_search_button": "Apply the selected saved live-search preset.",
            "delete_saved_search_button": "Delete the selected saved live-search preset.",
            "export_search_state_button": "Export live-search history and saved searches for sharing or backup.",
            "import_search_state_button": "Import live-search history and saved searches from a JSON file.",
            "clear_search_button": "Clear the live search and show the full current capture.",
            "folder_search_path_edit": "Folder containing CDSniffer JSON or JSONL capture logs to search.",
            "folder_search_query_edit": "Text or regex to find in stored capture logs.",
            "folder_search_recursive_check": "Search subfolders under the selected capture-log folder.",
            "folder_search_regex_check": "Treat the folder search query as a regular expression.",
            "folder_search_case_check": "Require exact casing for folder search matches.",
            "folder_search_format_combo": "Format used when exporting folder-search results.",
            "folder_search_limit_spin": "Maximum number of folder-search matches to collect.",
            "folder_search_button": "Search saved capture logs using the selected query and filters.",
            "folder_search_export_button": "Export the latest folder-search results.",
            "folder_search_filter_edit": "Filter visible folder-search result rows without rerunning the search.",
            "correlation_guide_mode_combo": "Pick the archive/correlation workflow step you want the guided button to run.",
            "correlation_guide_run_button": "Run the selected guided archive or correlation step.",
            "archive_root_edit": "Crimson Desert install folder, archive folder, or standalone .pamt file to index.",
            "archive_index_db_edit": "SQLite archive index file to create or reuse.",
            "archive_paz_dir_edit": "Optional PAZ folder used when the archive root is a standalone .pamt file.",
            "archive_patterns_edit": "Archive entry globs to index, one per line. Keep this focused for faster searches.",
            "archive_index_limit_spin": "Maximum archive entries to index. No limit is most complete but slower.",
            "archive_browse_root_button": "Choose the game install folder, archive folder, or .pamt file.",
            "archive_browse_index_button": "Choose where the SQLite archive index is stored.",
            "archive_build_index_button": "Build or refresh the archive index after a game update or filter change.",
            "archive_export_index_button": "Export the latest archive index summary report.",
            "archive_search_terms_edit": "Comma-separated path terms used to search indexed archive entries.",
            "archive_search_globs_edit": "Comma-separated archive path globs used to limit index search results.",
            "archive_search_limit_spin": "Maximum archive index search rows to return.",
            "archive_search_filter_edit": "Filter visible archive index rows without rerunning the search.",
            "archive_search_button": "Search the SQLite archive index before decoding or correlating.",
            "archive_capture_edit": "CDSniffer capture log to compare against archive, folder, or selected-file data.",
            "archive_baseline_capture_edit": "Optional before-state capture used to rank target-only matches higher.",
            "archive_cache_dir_edit": "Folder where archive correlation stores lazily decoded game files.",
            "archive_correlation_root_edit": "Decoded or unpacked folder used by folder correlation.",
            "archive_selected_file_edit": "One decoded or unpacked file to compare directly against the selected capture.",
            "archive_correlation_globs_edit": "Globs that limit archive or folder correlation candidates.",
            "archive_correlation_terms_edit": "Archive path terms that narrow archive correlation before decoding.",
            "archive_correlation_max_entries_spin": "Maximum archive entries to decode and scan in one correlation run.",
            "archive_correlation_max_matches_spin": "Maximum total correlation matches to return.",
            "archive_correlation_max_per_evidence_spin": "Maximum offsets returned for one captured evidence value.",
            "archive_correlation_context_spin": "Bytes around each file match to include in correlation output.",
            "archive_correlation_numeric_check": "Include decoded numeric candidates from captured byte context in correlation.",
            "archive_correlation_hints_check": "Add format-specific hints for JSON, text, PASEQ, hashes, and nearby values.",
            "archive_correlation_decrypt_check": "Decrypt supported XML archive entries during archive correlation.",
            "archive_correlation_format_combo": "Report format for exported archive, file, or folder correlation results.",
            "archive_browse_capture_button": "Choose the capture log used for correlation.",
            "archive_browse_baseline_button": "Choose an optional baseline capture for before/after comparison.",
            "archive_browse_cache_button": "Choose the decoded archive cache folder.",
            "archive_browse_correlation_root_button": "Choose a decoded or unpacked folder for folder correlation.",
            "archive_browse_selected_file_button": "Choose a single decoded or unpacked file for focused comparison.",
            "archive_correlate_button": "Compare the capture against indexed archive entries and decoded cache files.",
            "archive_correlate_file_button": "Compare the capture against only the selected decoded/unpacked file.",
            "archive_correlate_root_button": "Compare the capture against a decoded/unpacked folder tree.",
            "archive_export_correlation_button": "Export the latest archive, file, or folder correlation report.",
            "archive_extract_match_button": "Copy the decoded cache file behind the selected archive match into a chosen folder.",
            "archive_export_dmm_button": "Create a review-required DMM patch draft from the latest correlation result.",
            "archive_correlation_filter_edit": "Filter visible correlation rows without rerunning correlation.",
            "archive_index_table": "Indexed archive entries found in the current SQLite archive index.",
            "archive_correlation_table": "Correlation matches ranked by confidence and evidence trail.",
            "archive_report_view": "Text report from the latest archive/index/correlation operation.",
            "match_preview_view": "Decoded bytes, printable context, evidence metadata, and patch skeleton for the selected match.",
            "preset_name_edit": "Name to use when saving the current settings as a preset.",
            "preset_list": "Saved local settings presets.",
            "preset_refresh_button": "Reload the local preset list.",
            "preset_save_button": "Save the current settings under the entered preset name.",
            "preset_load_button": "Apply the selected preset to the current GUI settings.",
            "preset_delete_button": "Delete the selected local preset.",
            "preset_import_button": "Import a preset JSON file into the local preset folder.",
            "preset_export_button": "Export the selected preset JSON file.",
        }
        set_widget_tips(
            [
                (widget, tip)
                for name, tip in tips.items()
                if (widget := getattr(self, name, None)) is not None
            ]
        )

    def _apply_default_settings(self) -> None:
        if hasattr(self, "settings_preview"):
            self.refresh_capture_summary()
        if hasattr(self, "target_status"):
            self.refresh_target_indicator()

    def refresh_target_indicator(self) -> None:
        try:
            pid = resolve_pid(self.build_settings_namespace())
        except Exception:
            pid = None
        detected = pid is not None or self.worker is not None
        if self.worker is not None:
            self.target_status.setText(f"Game Detected - attached to PID {pid or 'unknown'}")
            self.target_status.setStyleSheet("color: #67e8a5; font-weight: 700;")
        elif pid is not None:
            self.target_status.setText(f"Game Detected - PID {pid}")
            self.target_status.setStyleSheet("color: #67e8a5; font-weight: 700;")
        else:
            self.target_status.setText("Game not detected")
            self.target_status.setStyleSheet("color: #ff7a90; font-weight: 700;")
        if self._last_target_detected is not None and detected != self._last_target_detected:
            if detected:
                self.notify_tray("game_detected", "CDSniffer", "Game detected and ready.")
            else:
                self.notify_tray("game_lost", "CDSniffer", "Game no longer detected.")
        self._last_target_detected = detected
        self.refresh_status_bar()

    def update_freshness_view(self) -> None:
        if self.last_capture_at is None:
            self.freshness_state_label.setText("No capture yet.")
            self.freshness_age_label.setText("-")
            self.freshness_duration_label.setText("-")
            self.freshness_pid_label.setText(str(self.build_settings_namespace().pid or "-"))
            self.refresh_status_bar()
            return
        now = datetime.now(timezone.utc)
        age_seconds = max(0.0, (now - self.last_capture_at).total_seconds())
        if age_seconds < 2:
            freshness = "Fresh"
            color = "#67e8a5"
        elif age_seconds < 10:
            freshness = "Warm"
            color = "#f0c674"
        else:
            freshness = "Stale"
            color = "#ff7a90"
        self.freshness_state_label.setText(f"{freshness} capture")
        self.freshness_state_label.setStyleSheet(f"color: {color}; font-weight: 700;")
        self.freshness_age_label.setText(f"{age_seconds:.1f}s ago")
        self.freshness_duration_label.setText(f"{self.last_capture_duration_ms or 0.0:.2f} ms")
        self.freshness_pid_label.setText(str(self.last_payload.get("pid") if self.last_payload else self.build_settings_namespace().pid or "-"))
        self.refresh_status_bar()

    def refresh_status_bar(self) -> None:
        pid = None
        if self.last_payload and self.last_payload.get("pid") is not None:
            pid = self.last_payload.get("pid")
        else:
            try:
                pid = self.build_settings_namespace().pid
            except Exception:
                pid = None
        self.status_pid_label.setText(f"PID: {pid if pid is not None else '-'}")
        if self.last_capture_at is None:
            self.status_age_label.setText("Age: -")
        else:
            age_seconds = max(0.0, (datetime.now(timezone.utc) - self.last_capture_at).total_seconds())
            self.status_age_label.setText(f"Age: {age_seconds:.1f}s")

    def render_hit_rows(self, rows: list[dict[str, Any]]) -> None:
        self.top_hits_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            self.top_hits_table.setItem(row_index, 0, QTableWidgetItem(str(row.get("count", ""))))
            self.top_hits_table.setItem(row_index, 1, QTableWidgetItem(str(row.get("encoding", ""))))
            self.top_hits_table.setItem(row_index, 2, QTableWidgetItem(f"0x{int(row.get('first_address', 0)):X}"))
            self.top_hits_table.setItem(row_index, 3, QTableWidgetItem(str(row.get("text", ""))))

    def search_state_root(self) -> Path:
        return Path.home() / ".cdsniffer"

    def search_state_path(self) -> Path:
        return self.search_state_root() / "searches.json"

    def default_search_state(self) -> dict[str, Any]:
        return {"history": [], "saved": []}

    def load_search_state(self) -> None:
        path = self.search_state_path()
        self.search_history: list[str] = []
        self.saved_searches: list[dict[str, Any]] = []
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    history = data.get("history", [])
                    saved = data.get("saved", [])
                    if isinstance(history, list):
                        self.search_history = [str(item).strip() for item in history if str(item).strip()]
                    if isinstance(saved, list):
                        normalized: list[dict[str, Any]] = []
                        for item in saved:
                            if isinstance(item, dict) and str(item.get("name", "")).strip():
                                normalized.append(dict(item))
                        self.saved_searches = normalized
            except Exception:
                self.search_history = []
                self.saved_searches = []
        self.refresh_search_history()
        self.refresh_saved_searches()

    def save_search_state(self) -> None:
        path = self.search_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "history": self.search_history[:25],
            "saved": self.saved_searches,
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def current_folder_search_spec(self) -> dict[str, Any]:
        return {
            "path": self.folder_search_path_edit.text().strip() or str(Path("logs")),
            "query": self.folder_search_query_edit.text().strip(),
            "regex": self.folder_search_regex_check.isChecked(),
            "case_sensitive": self.folder_search_case_check.isChecked(),
            "recursive": self.folder_search_recursive_check.isChecked(),
            "format": self.folder_search_format_combo.currentText(),
            "limit": int(self.folder_search_limit_spin.value()),
        }

    def render_folder_search_results(self, result: dict[str, Any]) -> None:
        self.last_folder_search = result
        rows = flatten_search_results(result)
        self.folder_search_summary_label.setText(
            f"Search '{result.get('query', '')}' found {result.get('match_count', 0)} matches across {result.get('file_count', 0)} file(s)."
        )
        self.folder_search_results_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            self.folder_search_results_table.setItem(row_index, 0, QTableWidgetItem(str(row.get("file", ""))))
            self.folder_search_results_table.setItem(row_index, 1, QTableWidgetItem(str(row.get("snapshot_index", ""))))
            self.folder_search_results_table.setItem(row_index, 2, QTableWidgetItem(str(row.get("match_path", ""))))
            self.folder_search_results_table.setItem(row_index, 3, QTableWidgetItem(str(row.get("value", ""))))
            self.folder_search_results_table.setItem(row_index, 4, QTableWidgetItem(str(row.get("payload_index", ""))))
        self.filter_folder_search_results(self.folder_search_filter_edit.text())

    def filter_folder_search_results(self, text: str) -> None:
        needle = text.strip().lower()
        if not hasattr(self, "folder_search_results_table"):
            return
        for row in range(self.folder_search_results_table.rowCount()):
            visible = True
            if needle:
                visible = any(
                    needle in self.folder_search_results_table.item(row, column).text().lower()
                    for column in range(self.folder_search_results_table.columnCount())
                    if self.folder_search_results_table.item(row, column) is not None
                )
            self.folder_search_results_table.setRowHidden(row, not visible)

    def run_folder_search(self) -> None:
        spec = self.current_folder_search_spec()
        query = spec["query"]
        if not query:
            QMessageBox.information(self, "Missing Query", "Enter a search query first.")
            return
        root = Path(spec["path"])
        if not root.exists():
            QMessageBox.warning(self, "Missing Path", f"Folder not found: {root}")
            return
        try:
            result = search_capture_directory(
                root,
                query,
                regex=spec["regex"],
                case_sensitive=spec["case_sensitive"],
                limit=spec["limit"],
                recursive=spec["recursive"],
            )
        except Exception as exc:
            QMessageBox.warning(self, "Search Failed", str(exc))
            return
        self.render_folder_search_results(result)
        self.add_search_history_entry(query)
        self.append_log(f"Folder search complete: {result.get('match_count', 0)} match(es) in {result.get('file_count', 0)} file(s).")

    def export_folder_search_results(self) -> None:
        result = getattr(self, "last_folder_search", None)
        if not result:
            QMessageBox.information(self, "No Results", "Run a folder search first.")
            return
        fmt = self.folder_search_format_combo.currentText()
        default_name = f"search-results.{ 'md' if fmt == 'markdown' else 'csv' if fmt == 'csv' else 'json' }"
        save_path, _ = QFileDialog.getSaveFileName(self, "Export Search Results", default_name, "All Files (*.*)")
        if not save_path:
            return
        try:
            if fmt == "csv":
                rendered = render_search_results_csv(result)
            elif fmt == "markdown":
                rendered = render_search_results_markdown(result)
            else:
                rendered = json.dumps(result, ensure_ascii=False, indent=2)
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            Path(save_path).write_text(rendered, encoding="utf-8")
            self.append_log(f"Exported folder search results to {save_path}.")
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", str(exc))

    def refresh_search_history(self) -> None:
        if not hasattr(self, "live_search_history_combo"):
            return
        current = self.live_search_history_combo.currentText()
        self.live_search_history_combo.blockSignals(True)
        self.live_search_history_combo.clear()
        for query in self.search_history:
            self.live_search_history_combo.addItem(query, query)
        if current:
            index = self.live_search_history_combo.findText(current)
            if index >= 0:
                self.live_search_history_combo.setCurrentIndex(index)
        self.live_search_history_combo.blockSignals(False)

    def refresh_saved_searches(self) -> None:
        if not hasattr(self, "saved_search_combo"):
            return
        current = self.saved_search_combo.currentText()
        self.saved_search_combo.blockSignals(True)
        self.saved_search_combo.clear()
        self.saved_search_combo.addItem("Choose saved search...", None)
        for item in self.saved_searches:
            self.saved_search_combo.addItem(str(item.get("name", "Unnamed")), item)
        if current:
            index = self.saved_search_combo.findText(current)
            if index >= 0:
                self.saved_search_combo.setCurrentIndex(index)
        self.saved_search_combo.blockSignals(False)

    def export_search_state(self) -> None:
        default_path = self.search_state_path()
        save_path, _ = QFileDialog.getSaveFileName(self, "Export Search State", str(default_path), "JSON Files (*.json)")
        if not save_path:
            return
        try:
            payload = {
                "history": self.search_history[:25],
                "saved": self.saved_searches,
            }
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            Path(save_path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            self.append_log(f"Exported search state to {save_path}.")
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", str(exc))

    def import_search_state(self) -> None:
        path_text, _ = QFileDialog.getOpenFileName(self, "Import Search State", "", "JSON Files (*.json)")
        if not path_text:
            return
        try:
            data = json.loads(Path(path_text).read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Search state JSON must be an object.")
            history = data.get("history", [])
            saved = data.get("saved", [])
            self.search_history = [str(item).strip() for item in history if str(item).strip()] if isinstance(history, list) else []
            self.saved_searches = [dict(item) for item in saved if isinstance(item, dict) and str(item.get("name", "")).strip()] if isinstance(saved, list) else []
            self.save_search_state()
            self.refresh_search_history()
            self.refresh_saved_searches()
            self.append_log(f"Imported search state from {path_text}.")
        except Exception as exc:
            QMessageBox.warning(self, "Import Failed", str(exc))

    def add_search_history_entry(self, query: str) -> None:
        normalized = query.strip()
        if not normalized:
            return
        self.search_history = [item for item in self.search_history if item != normalized]
        self.search_history.insert(0, normalized)
        self.search_history = self.search_history[:25]
        self.refresh_search_history()
        self.save_search_state()

    def commit_live_search(self) -> None:
        self.add_search_history_entry(self.live_search_edit.text())

    def clear_live_search(self) -> None:
        self.live_search_edit.clear()
        self.apply_live_search_filter()

    def on_recent_search_selected(self, query: str) -> None:
        if query and query != self.live_search_edit.text():
            self.live_search_edit.setText(query)
            self.apply_live_search_filter()

    def on_saved_search_selected(self, index: int) -> None:
        if index <= 0:
            return
        item = self.saved_search_combo.itemData(index)
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            if name:
                self.live_search_name_edit.setText(name)

    def current_search_spec(self) -> dict[str, Any]:
        return {
            "query": self.live_search_edit.text().strip(),
            "regex": self.live_search_regex_check.isChecked(),
            "case_sensitive": self.live_search_case_check.isChecked(),
            "filter_top_hits": self.live_search_filter_table_check.isChecked(),
        }

    def save_current_search(self) -> None:
        spec = self.current_search_spec()
        if not spec["query"]:
            QMessageBox.information(self, "Missing Query", "Enter a search query first.")
            return
        name = self.live_search_name_edit.text().strip() or spec["query"]
        entry = {"name": name, **spec}
        self.saved_searches = [item for item in self.saved_searches if str(item.get("name", "")) != name]
        self.saved_searches.insert(0, entry)
        self.saved_searches = self.saved_searches[:25]
        self.save_search_state()
        self.refresh_saved_searches()
        self.append_log(f"Saved search: {name}")

    def format_search_status(self, query: str, match_groups: int, field_matches: int) -> str:
        if not query:
            return '<span style="color:#cbd5e1;">Showing the full live capture.</span>'
        safe_query = html.escape(query)
        return (
            f"<span style='color:#fde68a; font-weight:700;'>Search</span> "
            f"<span style='color:#f8fafc;'>{safe_query}</span> "
            f"<span style='color:#67e8a5;'>matched {match_groups} hit group(s)</span> "
            f"<span style='color:#93c5fd;'>and {field_matches} field value(s).</span>"
        )

    def apply_selected_saved_search(self) -> None:
        index = self.saved_search_combo.currentIndex()
        if index <= 0:
            QMessageBox.information(self, "No Saved Search", "Choose a saved search first.")
            return
        item = self.saved_search_combo.itemData(index)
        if not isinstance(item, dict):
            QMessageBox.information(self, "No Saved Search", "Choose a saved search first.")
            return
        self.live_search_name_edit.setText(str(item.get("name", "")))
        self.live_search_edit.setText(str(item.get("query", "")))
        self.live_search_regex_check.setChecked(bool(item.get("regex", False)))
        self.live_search_case_check.setChecked(bool(item.get("case_sensitive", False)))
        self.live_search_filter_table_check.setChecked(bool(item.get("filter_top_hits", True)))
        self.apply_live_search_filter()
        self.commit_live_search()
        self.append_log(f"Applied saved search: {item.get('name', '')}")

    def delete_selected_saved_search(self) -> None:
        index = self.saved_search_combo.currentIndex()
        if index <= 0:
            QMessageBox.information(self, "No Saved Search", "Choose a saved search first.")
            return
        item = self.saved_search_combo.itemData(index)
        if not isinstance(item, dict):
            QMessageBox.information(self, "No Saved Search", "Choose a saved search first.")
            return
        name = str(item.get("name", "")).strip()
        self.saved_searches = [entry for entry in self.saved_searches if str(entry.get("name", "")).strip() != name]
        self.save_search_state()
        self.refresh_saved_searches()
        self.append_log(f"Deleted saved search: {name}")

    def highlight_raw_view(self, query: str, *, regex: bool, case_sensitive: bool) -> None:
        if not query:
            self.raw_view.setExtraSelections([])
            return
        try:
            pattern = re.compile(query if regex else re.escape(query), 0 if case_sensitive else re.IGNORECASE)
        except re.error:
            self.raw_view.setExtraSelections([])
            return

        text = self.raw_view.toPlainText()
        if not text:
            self.raw_view.setExtraSelections([])
            return

        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor("#fbbf24"))
        highlight_format.setForeground(QColor("#111827"))

        selections = []
        for match in pattern.finditer(text):
            selection = QTextEdit.ExtraSelection()
            cursor = self.raw_view.textCursor()
            cursor.setPosition(match.start())
            cursor.setPosition(match.end(), QTextCursor.KeepAnchor)
            selection.cursor = cursor
            selection.format = highlight_format
            selections.append(selection)
        self.raw_view.setExtraSelections(selections)

    def apply_live_search_filter(self) -> None:
        payload = self.last_payload
        if payload is None:
            self.live_search_result_label.setText("<span style='color:#cbd5e1;'>No capture available yet.</span>")
            self.top_hits_table.setRowCount(0)
            self.raw_view.setPlainText("No capture yet.")
            self.raw_view.setExtraSelections([])
            return

        query = self.live_search_edit.text().strip()
        filter_top_hits = self.live_search_filter_table_check.isChecked()
        if not query:
            self.live_search_result_label.setText(self.format_search_status("", 0, 0))
            self.render_hit_rows(payload.get("top_hits", []))
            self.raw_view.setPlainText(payload_to_text(payload))
            self.raw_view.setExtraSelections([])
            return

        try:
            regex = self.live_search_regex_check.isChecked()
            case_sensitive = self.live_search_case_check.isChecked()
            flattened_hits = search_flattened_hits(
                payload,
                query,
                regex=regex,
                case_sensitive=case_sensitive,
                limit=250,
            )
            field_matches = search_payload_values(
                payload,
                query,
                regex=regex,
                case_sensitive=case_sensitive,
                limit=250,
            )
        except (ValueError, re.error) as exc:
            self.live_search_result_label.setText(f"<span style='color:#ff7a90;'>{str(exc)}</span>")
            self.render_hit_rows(payload.get("top_hits", []))
            self.raw_view.setPlainText(payload_to_text(payload))
            self.raw_view.setExtraSelections([])
            return

        counts: dict[tuple[str, str], int] = {}
        first_addresses: dict[tuple[str, str], int] = {}
        for hit in flattened_hits:
            key = (str(hit.get("encoding", "")), str(hit.get("text", "")))
            counts[key] = counts.get(key, 0) + 1
            first_addresses.setdefault(key, int(hit.get("address", 0) or 0))

        search_rows = [
            {
                "count": count,
                "encoding": encoding,
                "first_address": first_addresses[(encoding, text)],
                "text": text,
            }
            for (encoding, text), count in sorted(counts.items(), key=lambda item: (-item[1], item[0][1].lower()))
        ]

        self.live_search_result_label.setText(self.format_search_status(query, len(search_rows), len(field_matches)))
        self.render_hit_rows(search_rows if filter_top_hits else payload.get("top_hits", []))
        self.raw_view.setPlainText(
            payload_to_text(
                {
                    "query": query,
                    "regex": regex,
                    "case_sensitive": case_sensitive,
                    "filter_top_hits": filter_top_hits,
                    "snapshot_timestamp": payload.get("timestamp"),
                    "match_count": len(search_rows),
                    "field_match_count": len(field_matches),
                    "matched_hits": search_rows,
                    "field_matches": field_matches,
                }
            )
        )
        self.highlight_raw_view(query, regex=regex, case_sensitive=case_sensitive)

    def refresh_capture_summary(self) -> None:
        if not hasattr(self, "settings_preview"):
            return
        self.settings_preview.setPlainText(
            "\n".join(
                [
                    f"PID: {self.pid_edit.text().strip() or 'not set'}",
                    f"Process: {self.process_edit.text().strip() or 'Crimson Desert'}",
                    f"Mode: {self.mode_combo.currentText()}",
                    f"Hotkey: {normalize_hotkey_name(self.hotkey_edit.text())}",
                    f"Output: {self.output_edit.text().strip() or 'logs/cdsniffer.jsonl'}",
                    f"Format: {self.format_combo.currentText()}",
                    f"Context bytes: {self.context_bytes_spin.value()}",
                    f"Decode numbers: {'yes' if self.decode_context_numbers_check.isChecked() else 'no'}",
                    f"Capture gate: {self.capture_gate_combo.currentText()} / {self.capture_gate_match_combo.currentText()}",
                    f"Unique only: {'yes' if self.unique_only_check.isChecked() else 'no'}",
                    f"Summary: {self.summary_combo.currentText()}",
                    f"Timestamp output: {'yes' if self.timestamp_check.isChecked() else 'no'}",
                    f"Manifest: {'yes' if self.export_manifest_check.isChecked() else 'no'}",
                    f"Tray: {'yes' if self.tray_enabled_check.isChecked() else 'no'} / {self.tray_click_behavior_combo.currentText()}",
                    f"Tray notifications: {'yes' if self.tray_notifications_check.isChecked() else 'no'}",
                    f"Quiet: {'yes' if self.quiet_check.isChecked() else 'no'}",
                    f"Verbose: {'yes' if self.verbose_check.isChecked() else 'no'}",
                ]
            )
        )

    def build_live_tab(self) -> None:
        layout = QVBoxLayout(self.live_tab)
        search_box = QGroupBox("Live Search")
        search_layout = QGridLayout(search_box)
        self.live_search_history_combo = QComboBox()
        self.live_search_history_combo.setEditable(False)
        self.live_search_history_combo.currentTextChanged.connect(self.on_recent_search_selected)
        self.live_search_edit = QLineEdit()
        self.live_search_edit.setPlaceholderText("Search the current real-time capture...")
        self.live_search_regex_check = QCheckBox("Regex")
        self.live_search_case_check = QCheckBox("Case sensitive")
        self.live_search_filter_table_check = QCheckBox("Filter top-hits table")
        self.live_search_filter_table_check.setChecked(True)
        self.live_search_result_label = QLabel("Showing the full live capture.")
        self.live_search_result_label.setTextFormat(Qt.RichText)
        self.live_search_result_label.setWordWrap(True)
        self.live_search_name_edit = QLineEdit()
        self.live_search_name_edit.setPlaceholderText("Saved search name")
        self.saved_search_combo = QComboBox()
        self.saved_search_combo.setEditable(False)
        self.saved_search_combo.currentIndexChanged.connect(self.on_saved_search_selected)
        self.live_search_edit.textChanged.connect(self.apply_live_search_filter)
        self.live_search_edit.returnPressed.connect(self.commit_live_search)
        self.live_search_edit.editingFinished.connect(self.commit_live_search)
        self.live_search_regex_check.toggled.connect(self.apply_live_search_filter)
        self.live_search_case_check.toggled.connect(self.apply_live_search_filter)
        self.live_search_filter_table_check.toggled.connect(self.apply_live_search_filter)
        search_layout.addWidget(QLabel("Query"), 0, 0)
        search_layout.addWidget(self.live_search_edit, 0, 1, 1, 3)
        search_layout.addWidget(QLabel("Recent"), 1, 0)
        search_layout.addWidget(self.live_search_history_combo, 1, 1, 1, 3)
        search_layout.addWidget(self.live_search_regex_check, 2, 1)
        search_layout.addWidget(self.live_search_case_check, 2, 2)
        search_layout.addWidget(self.live_search_filter_table_check, 2, 3)
        search_layout.addWidget(QLabel("Save As"), 3, 0)
        search_layout.addWidget(self.live_search_name_edit, 3, 1)
        search_layout.addWidget(self.saved_search_combo, 3, 2)
        self.save_search_button = QPushButton("Save Search")
        self.apply_saved_search_button = QPushButton("Apply Saved")
        self.delete_saved_search_button = QPushButton("Delete Saved")
        self.export_search_state_button = QPushButton("Export State")
        self.import_search_state_button = QPushButton("Import State")
        self.clear_search_button = QPushButton("Clear")
        self.save_search_button.clicked.connect(self.save_current_search)
        self.apply_saved_search_button.clicked.connect(self.apply_selected_saved_search)
        self.delete_saved_search_button.clicked.connect(self.delete_selected_saved_search)
        self.export_search_state_button.clicked.connect(self.export_search_state)
        self.import_search_state_button.clicked.connect(self.import_search_state)
        self.clear_search_button.clicked.connect(self.clear_live_search)
        search_layout.addWidget(self.save_search_button, 4, 0)
        search_layout.addWidget(self.apply_saved_search_button, 4, 1)
        search_layout.addWidget(self.delete_saved_search_button, 4, 2)
        search_layout.addWidget(self.export_search_state_button, 4, 3)
        search_layout.addWidget(self.import_search_state_button, 5, 0)
        search_layout.addWidget(self.clear_search_button, 5, 1)
        search_layout.addWidget(self.live_search_result_label, 6, 0, 1, 4)
        layout.addWidget(search_box)

        freshness_box = QGroupBox("Capture Freshness")
        freshness_layout = QGridLayout(freshness_box)
        self.freshness_state_label = QLabel("No capture yet.")
        self.freshness_age_label = QLabel("-")
        self.freshness_duration_label = QLabel("-")
        self.freshness_pid_label = QLabel("-")
        freshness_layout.addWidget(QLabel("State"), 0, 0)
        freshness_layout.addWidget(self.freshness_state_label, 0, 1)
        freshness_layout.addWidget(QLabel("Age"), 1, 0)
        freshness_layout.addWidget(self.freshness_age_label, 1, 1)
        freshness_layout.addWidget(QLabel("Duration"), 2, 0)
        freshness_layout.addWidget(self.freshness_duration_label, 2, 1)
        freshness_layout.addWidget(QLabel("PID"), 3, 0)
        freshness_layout.addWidget(self.freshness_pid_label, 3, 1)
        layout.addWidget(freshness_box)

        stats_box = QGroupBox("Latest Snapshot")
        stats_layout = QGridLayout(stats_box)
        self.stats_label = QLabel("No capture yet.")
        self.watch_label = QLabel("")
        self.comparison_label = QLabel("")
        stats_layout.addWidget(QLabel("Stats"), 0, 0)
        stats_layout.addWidget(self.stats_label, 0, 1)
        stats_layout.addWidget(QLabel("Watch"), 1, 0)
        stats_layout.addWidget(self.watch_label, 1, 1)
        stats_layout.addWidget(QLabel("Diff"), 2, 0)
        stats_layout.addWidget(self.comparison_label, 2, 1)
        layout.addWidget(stats_box)

        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        self.top_hits_table = QTableWidget(0, 4)
        self.top_hits_table.setHorizontalHeaderLabels(["Count", "Encoding", "Address", "Text"])
        self.top_hits_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.top_hits_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.top_hits_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.top_hits_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.top_hits_table.setAlternatingRowColors(True)
        left_layout.addWidget(QLabel("Top Hits"))
        left_layout.addWidget(self.top_hits_table)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        self.raw_view = QTextEdit()
        self.raw_view.setReadOnly(True)
        self.raw_view.setFont(QFont("Cascadia Mono", 10))
        right_layout.addWidget(QLabel("Raw Snapshot"))
        right_layout.addWidget(self.raw_view)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)

    def build_search_tab(self) -> None:
        layout = QVBoxLayout(self.search_tab)
        controls = QGroupBox("Folder Search")
        controls_layout = QGridLayout(controls)
        self.folder_search_path_edit = QLineEdit(str(Path("logs")))
        self.folder_search_query_edit = QLineEdit()
        self.folder_search_query_edit.setPlaceholderText("Search query")
        self.folder_search_recursive_check = QCheckBox("Recursive")
        self.folder_search_recursive_check.setChecked(True)
        self.folder_search_regex_check = QCheckBox("Regex")
        self.folder_search_case_check = QCheckBox("Case sensitive")
        self.folder_search_format_combo = QComboBox()
        self.folder_search_format_combo.addItems(["json", "csv", "markdown"])
        self.folder_search_limit_spin = QSpinBox()
        self.folder_search_limit_spin.setRange(1, 100000)
        self.folder_search_limit_spin.setValue(500)
        self.folder_search_button = QPushButton("Search Folder")
        self.folder_search_export_button = QPushButton("Export Results")
        self.folder_search_filter_edit = QLineEdit()
        self.folder_search_filter_edit.setPlaceholderText("Filter result rows...")
        self.folder_search_filter_edit.textChanged.connect(self.filter_folder_search_results)
        self.folder_search_button.clicked.connect(self.run_folder_search)
        self.folder_search_export_button.clicked.connect(self.export_folder_search_results)
        controls_layout.addWidget(QLabel("Path"), 0, 0)
        controls_layout.addWidget(self.folder_search_path_edit, 0, 1, 1, 3)
        controls_layout.addWidget(QLabel("Query"), 1, 0)
        controls_layout.addWidget(self.folder_search_query_edit, 1, 1, 1, 3)
        controls_layout.addWidget(self.folder_search_recursive_check, 2, 1)
        controls_layout.addWidget(self.folder_search_regex_check, 2, 2)
        controls_layout.addWidget(self.folder_search_case_check, 2, 3)
        controls_layout.addWidget(QLabel("Format"), 3, 0)
        controls_layout.addWidget(self.folder_search_format_combo, 3, 1)
        controls_layout.addWidget(QLabel("Limit"), 3, 2)
        controls_layout.addWidget(self.folder_search_limit_spin, 3, 3)
        controls_layout.addWidget(self.folder_search_button, 4, 0)
        controls_layout.addWidget(self.folder_search_export_button, 4, 1)
        controls_layout.addWidget(QLabel("Results filter"), 5, 0)
        controls_layout.addWidget(self.folder_search_filter_edit, 5, 1, 1, 3)
        layout.addWidget(controls)

        self.folder_search_summary_label = QLabel("No folder search run yet.")
        self.folder_search_summary_label.setWordWrap(True)
        layout.addWidget(self.folder_search_summary_label)

        self.folder_search_results_table = QTableWidget(0, 5)
        self.folder_search_results_table.setHorizontalHeaderLabels(["File", "Snapshot", "Match Path", "Value", "Payload Index"])
        self.folder_search_results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.folder_search_results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.folder_search_results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.folder_search_results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.folder_search_results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.folder_search_results_table.setAlternatingRowColors(True)
        layout.addWidget(self.folder_search_results_table, 1)

    def build_archives_tab(self) -> None:
        layout = QVBoxLayout(self.archives_tab)
        guide_box = QGroupBox("Guided Correlation Workspace")
        guide_layout = QGridLayout(guide_box)
        self.correlation_guide_mode_combo = QComboBox()
        self.correlation_guide_mode_combo.addItems(
            [
                "1. Build archive index",
                "2. Search archive index",
                "3. Correlate archive index",
                "4. Correlate selected decoded file",
                "5. Correlate decoded folder",
                "6. Export DMM draft",
            ]
        )
        self.correlation_guide_mode_combo.currentIndexChanged.connect(self.update_correlation_guide)
        self.correlation_guide_label = QLabel()
        self.correlation_guide_label.setWordWrap(True)
        self.correlation_guide_run_button = QPushButton("Run Guided Step")
        self.correlation_guide_run_button.clicked.connect(self.run_correlation_guide_action)
        guide_layout.addWidget(QLabel("Step"), 0, 0)
        guide_layout.addWidget(self.correlation_guide_mode_combo, 0, 1)
        guide_layout.addWidget(self.correlation_guide_run_button, 0, 2)
        guide_layout.addWidget(self.correlation_guide_label, 1, 0, 1, 3)
        layout.addWidget(guide_box)

        controls = QGroupBox("Archive Index")
        controls_layout = QGridLayout(controls)
        self.archive_root_edit = QLineEdit(r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert")
        self.archive_index_db_edit = QLineEdit(str(project_logs_dir() / "cdsniffer-archive-index.sqlite"))
        self.archive_paz_dir_edit = QLineEdit()
        self.archive_paz_dir_edit.setPlaceholderText("Optional PAZ directory for standalone .pamt")
        self.archive_patterns_edit = QPlainTextEdit("*.paseq\n*.json\n*.xml")
        self.archive_patterns_edit.setMaximumHeight(92)
        self.archive_index_limit_spin = QSpinBox()
        self.archive_index_limit_spin.setRange(0, 10_000_000)
        self.archive_index_limit_spin.setSpecialValueText("No limit")
        self.archive_index_limit_spin.setValue(0)
        self.archive_browse_root_button = QPushButton("Browse Root")
        self.archive_browse_root_button.clicked.connect(self.browse_archive_root)
        self.archive_browse_index_button = QPushButton("Browse Index DB")
        self.archive_browse_index_button.clicked.connect(self.browse_archive_index_db)
        self.archive_build_index_button = QPushButton("Build / Rebuild Index")
        self.archive_build_index_button.clicked.connect(self.run_archive_index_build)
        self.archive_export_index_button = QPushButton("Export Index Summary")
        self.archive_export_index_button.clicked.connect(self.export_archive_index_report)
        controls_layout.addWidget(QLabel("Archive root"), 0, 0)
        controls_layout.addWidget(self.archive_root_edit, 0, 1, 1, 4)
        controls_layout.addWidget(self.archive_browse_root_button, 0, 5)
        controls_layout.addWidget(QLabel("Index DB"), 1, 0)
        controls_layout.addWidget(self.archive_index_db_edit, 1, 1, 1, 4)
        controls_layout.addWidget(self.archive_browse_index_button, 1, 5)
        controls_layout.addWidget(QLabel("PAZ dir"), 2, 0)
        controls_layout.addWidget(self.archive_paz_dir_edit, 2, 1, 1, 5)
        controls_layout.addWidget(QLabel("Index globs"), 3, 0)
        controls_layout.addWidget(self.archive_patterns_edit, 3, 1, 1, 3)
        controls_layout.addWidget(QLabel("Limit"), 3, 4)
        controls_layout.addWidget(self.archive_index_limit_spin, 3, 5)
        controls_layout.addWidget(self.archive_build_index_button, 4, 0, 1, 2)
        controls_layout.addWidget(self.archive_export_index_button, 4, 2, 1, 2)
        layout.addWidget(controls)

        search_box = QGroupBox("Search Indexed Archive Entries")
        search_layout = QGridLayout(search_box)
        self.archive_search_terms_edit = QLineEdit()
        self.archive_search_terms_edit.setPlaceholderText("Path terms, comma separated, e.g. mission, camp, quest")
        self.archive_search_globs_edit = QLineEdit("*.paseq")
        self.archive_search_globs_edit.setPlaceholderText("Entry globs, comma separated")
        self.archive_search_limit_spin = QSpinBox()
        self.archive_search_limit_spin.setRange(1, 100_000)
        self.archive_search_limit_spin.setValue(500)
        self.archive_search_filter_edit = QLineEdit()
        self.archive_search_filter_edit.setPlaceholderText("Filter index result rows...")
        self.archive_search_filter_edit.textChanged.connect(self.filter_archive_index_rows)
        self.archive_search_button = QPushButton("Search Index")
        self.archive_search_button.clicked.connect(self.run_archive_index_search)
        search_layout.addWidget(QLabel("Path terms"), 0, 0)
        search_layout.addWidget(self.archive_search_terms_edit, 0, 1, 1, 3)
        search_layout.addWidget(QLabel("Globs"), 1, 0)
        search_layout.addWidget(self.archive_search_globs_edit, 1, 1)
        search_layout.addWidget(QLabel("Limit"), 1, 2)
        search_layout.addWidget(self.archive_search_limit_spin, 1, 3)
        search_layout.addWidget(self.archive_search_button, 2, 0)
        search_layout.addWidget(QLabel("Table filter"), 2, 1)
        search_layout.addWidget(self.archive_search_filter_edit, 2, 2, 1, 2)
        layout.addWidget(search_box)

        correlate_box = QGroupBox("Correlate Capture Against Archive Index")
        correlate_layout = QGridLayout(correlate_box)
        self.archive_capture_edit = QLineEdit(str(project_logs_dir() / "camp-mission.jsonl"))
        self.archive_baseline_capture_edit = QLineEdit()
        self.archive_baseline_capture_edit.setPlaceholderText("Optional before-state capture for target-only diff")
        self.archive_cache_dir_edit = QLineEdit(str(project_logs_dir() / "archive-cache"))
        self.archive_correlation_root_edit = QLineEdit()
        self.archive_correlation_root_edit.setPlaceholderText("Optional decoded/unpacked folder for folder correlation")
        self.archive_correlation_globs_edit = QLineEdit("*.paseq, *.json, *.xml")
        self.archive_correlation_terms_edit = QLineEdit()
        self.archive_correlation_terms_edit.setPlaceholderText("Optional archive path terms")
        self.archive_correlation_max_entries_spin = QSpinBox()
        self.archive_correlation_max_entries_spin.setRange(1, 100_000)
        self.archive_correlation_max_entries_spin.setValue(2000)
        self.archive_correlation_max_matches_spin = QSpinBox()
        self.archive_correlation_max_matches_spin.setRange(1, 100_000)
        self.archive_correlation_max_matches_spin.setValue(500)
        self.archive_correlation_max_per_evidence_spin = QSpinBox()
        self.archive_correlation_max_per_evidence_spin.setRange(1, 10_000)
        self.archive_correlation_max_per_evidence_spin.setValue(20)
        self.archive_correlation_context_spin = QSpinBox()
        self.archive_correlation_context_spin.setRange(0, 4096)
        self.archive_correlation_context_spin.setValue(16)
        self.archive_correlation_numeric_check = QCheckBox("Numeric evidence")
        self.archive_correlation_numeric_check.setChecked(True)
        self.archive_correlation_hints_check = QCheckBox("Format hints")
        self.archive_correlation_hints_check.setChecked(True)
        self.archive_correlation_decrypt_check = QCheckBox("Decrypt XML")
        self.archive_correlation_decrypt_check.setChecked(True)
        self.archive_correlation_format_combo = QComboBox()
        self.archive_correlation_format_combo.addItems(["markdown", "json", "csv"])
        self.archive_browse_capture_button = QPushButton("Browse Capture")
        self.archive_browse_capture_button.clicked.connect(self.browse_archive_capture)
        self.archive_browse_baseline_button = QPushButton("Browse Baseline")
        self.archive_browse_baseline_button.clicked.connect(self.browse_archive_baseline)
        self.archive_browse_cache_button = QPushButton("Browse Cache")
        self.archive_browse_cache_button.clicked.connect(self.browse_archive_cache)
        self.archive_browse_correlation_root_button = QPushButton("Browse Decoded Root")
        self.archive_browse_correlation_root_button.clicked.connect(self.browse_archive_correlation_root)
        self.archive_selected_file_edit = QLineEdit()
        self.archive_selected_file_edit.setPlaceholderText("Optional decoded/unpacked file for focused comparison")
        self.archive_browse_selected_file_button = QPushButton("Browse Decoded File")
        self.archive_browse_selected_file_button.clicked.connect(self.browse_archive_selected_file)
        self.archive_correlate_file_button = QPushButton("Run File Correlation")
        self.archive_correlate_file_button.clicked.connect(self.run_selected_file_correlation)
        self.archive_correlate_root_button = QPushButton("Run Folder Correlation")
        self.archive_correlate_root_button.clicked.connect(self.run_root_correlation)
        self.archive_correlate_button = QPushButton("Run Archive Correlation")
        self.archive_correlate_button.clicked.connect(self.run_archive_correlation)
        self.archive_export_correlation_button = QPushButton("Export Correlation")
        self.archive_export_correlation_button.clicked.connect(self.export_archive_correlation)
        self.archive_extract_match_button = QPushButton("Extract Selected Entry")
        self.archive_extract_match_button.clicked.connect(self.extract_selected_archive_match)
        self.archive_export_dmm_button = QPushButton("Export DMM Draft")
        self.archive_export_dmm_button.clicked.connect(self.export_dmm_draft)
        self.archive_correlation_filter_edit = QLineEdit()
        self.archive_correlation_filter_edit.setPlaceholderText("Filter correlation result rows...")
        self.archive_correlation_filter_edit.textChanged.connect(self.filter_archive_correlation_rows)
        correlate_layout.addWidget(QLabel("Capture"), 0, 0)
        correlate_layout.addWidget(self.archive_capture_edit, 0, 1, 1, 4)
        correlate_layout.addWidget(self.archive_browse_capture_button, 0, 5)
        correlate_layout.addWidget(QLabel("Baseline"), 1, 0)
        correlate_layout.addWidget(self.archive_baseline_capture_edit, 1, 1, 1, 4)
        correlate_layout.addWidget(self.archive_browse_baseline_button, 1, 5)
        correlate_layout.addWidget(QLabel("Cache dir"), 2, 0)
        correlate_layout.addWidget(self.archive_cache_dir_edit, 2, 1, 1, 4)
        correlate_layout.addWidget(self.archive_browse_cache_button, 2, 5)
        correlate_layout.addWidget(QLabel("Decoded root"), 3, 0)
        correlate_layout.addWidget(self.archive_correlation_root_edit, 3, 1, 1, 4)
        correlate_layout.addWidget(self.archive_browse_correlation_root_button, 3, 5)
        correlate_layout.addWidget(QLabel("Decoded file"), 4, 0)
        correlate_layout.addWidget(self.archive_selected_file_edit, 4, 1, 1, 4)
        correlate_layout.addWidget(self.archive_browse_selected_file_button, 4, 5)
        correlate_layout.addWidget(QLabel("Globs"), 5, 0)
        correlate_layout.addWidget(self.archive_correlation_globs_edit, 5, 1, 1, 2)
        correlate_layout.addWidget(QLabel("Path terms"), 5, 3)
        correlate_layout.addWidget(self.archive_correlation_terms_edit, 5, 4, 1, 2)
        correlate_layout.addWidget(QLabel("Max entries"), 6, 0)
        correlate_layout.addWidget(self.archive_correlation_max_entries_spin, 6, 1)
        correlate_layout.addWidget(QLabel("Max matches"), 6, 2)
        correlate_layout.addWidget(self.archive_correlation_max_matches_spin, 6, 3)
        correlate_layout.addWidget(QLabel("Per evidence"), 6, 4)
        correlate_layout.addWidget(self.archive_correlation_max_per_evidence_spin, 6, 5)
        correlate_layout.addWidget(QLabel("Context bytes"), 7, 0)
        correlate_layout.addWidget(self.archive_correlation_context_spin, 7, 1)
        correlate_layout.addWidget(self.archive_correlation_numeric_check, 7, 2)
        correlate_layout.addWidget(self.archive_correlation_hints_check, 7, 3)
        correlate_layout.addWidget(self.archive_correlation_decrypt_check, 7, 4)
        correlate_layout.addWidget(self.archive_correlation_format_combo, 7, 5)
        correlate_layout.addWidget(self.archive_correlate_button, 8, 0)
        correlate_layout.addWidget(self.archive_correlate_file_button, 8, 1)
        correlate_layout.addWidget(self.archive_correlate_root_button, 8, 2)
        correlate_layout.addWidget(self.archive_export_correlation_button, 8, 3)
        correlate_layout.addWidget(self.archive_extract_match_button, 8, 4)
        correlate_layout.addWidget(self.archive_export_dmm_button, 8, 5)
        correlate_layout.addWidget(QLabel("Table filter"), 9, 0)
        correlate_layout.addWidget(self.archive_correlation_filter_edit, 9, 1, 1, 5)
        layout.addWidget(correlate_box)
        self.update_correlation_guide()

        self.archive_summary_label = QLabel("No archive operation run yet.")
        self.archive_summary_label.setWordWrap(True)
        layout.addWidget(self.archive_summary_label)

        splitter = QSplitter(Qt.Vertical)
        tables_splitter = QSplitter(Qt.Horizontal)
        index_panel = QWidget()
        index_layout = QVBoxLayout(index_panel)
        self.archive_index_table = QTableWidget(0, 8)
        self.archive_index_table.setHorizontalHeaderLabels(["Path", "Ext", "Compression", "PAZ", "Offset", "Stored", "Original", "Flags"])
        self.archive_index_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.archive_index_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.archive_index_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.archive_index_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.archive_index_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.archive_index_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.archive_index_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.archive_index_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self.archive_index_table.setAlternatingRowColors(True)
        index_layout.addWidget(QLabel("Indexed Entries"))
        index_layout.addWidget(self.archive_index_table)
        tables_splitter.addWidget(index_panel)

        correlation_panel = QWidget()
        correlation_layout = QVBoxLayout(correlation_panel)
        self.archive_correlation_table = QTableWidget(0, 10)
        self.archive_correlation_table.setHorizontalHeaderLabels(
            ["Confidence", "Archive Path", "Offset", "Type", "Evidence", "Count", "Decoder", "Original Bytes", "Cache", "Reasons"]
        )
        self.archive_correlation_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.archive_correlation_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.archive_correlation_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.archive_correlation_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.archive_correlation_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.archive_correlation_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.archive_correlation_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.archive_correlation_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        self.archive_correlation_table.horizontalHeader().setSectionResizeMode(8, QHeaderView.Stretch)
        self.archive_correlation_table.horizontalHeader().setSectionResizeMode(9, QHeaderView.Stretch)
        self.archive_correlation_table.setAlternatingRowColors(True)
        self.archive_correlation_table.itemSelectionChanged.connect(self.update_match_preview_from_selection)
        correlation_layout.addWidget(QLabel("Correlation Matches"))
        correlation_layout.addWidget(self.archive_correlation_table)
        tables_splitter.addWidget(correlation_panel)
        tables_splitter.setStretchFactor(0, 2)
        tables_splitter.setStretchFactor(1, 3)
        splitter.addWidget(tables_splitter)

        self.archive_report_view = QPlainTextEdit()
        self.archive_report_view.setReadOnly(True)
        self.archive_report_view.setFont(QFont("Cascadia Mono", 10))
        splitter.addWidget(self.archive_report_view)
        self.match_preview_view = QPlainTextEdit()
        self.match_preview_view.setReadOnly(True)
        self.match_preview_view.setFont(QFont("Cascadia Mono", 10))
        self.match_preview_view.setPlainText("Select a correlation match to preview decoded bytes and patch context.")
        splitter.addWidget(self.match_preview_view)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 1)
        layout.addWidget(splitter, 1)

        self.last_archive_index_report: dict[str, Any] | None = None
        self.last_archive_index_search: dict[str, Any] | None = None
        self.last_archive_correlation: dict[str, Any] | None = None
        self.last_file_correlation: dict[str, Any] | None = None
        self.current_correlation_matches: list[dict[str, Any]] = []

    def archive_patterns(self, text: str) -> list[str]:
        return split_values(text)

    def archive_terms(self, text: str) -> list[str]:
        return split_values(text)

    def update_correlation_guide(self) -> None:
        if not hasattr(self, "correlation_guide_label"):
            return
        guidance = [
            "Build or refresh the SQLite archive index after a game update or when changing indexed file families.",
            "Search the index to find likely archive paths before decoding or correlating.",
            "Compare a capture against indexed archive entries. This lazily decodes candidates into the cache directory.",
            "Compare a capture against one decoded/cache file when you already know the likely target file.",
            "Compare a capture against a decoded folder. Add a baseline capture to highlight target-only candidates.",
            "Export the latest archive/file/folder correlation result as a review-required DMM byte-patch draft.",
        ]
        index = max(0, min(self.correlation_guide_mode_combo.currentIndex(), len(guidance) - 1))
        self.correlation_guide_label.setText(guidance[index])

    def run_correlation_guide_action(self) -> None:
        index = self.correlation_guide_mode_combo.currentIndex()
        actions = [
            self.run_archive_index_build,
            self.run_archive_index_search,
            self.run_archive_correlation,
            self.run_selected_file_correlation,
            self.run_root_correlation,
            self.export_dmm_draft,
        ]
        actions[max(0, min(index, len(actions) - 1))]()

    def browse_archive_root(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Archive Root", self.archive_root_edit.text())
        if path:
            self.archive_root_edit.setText(path)

    def browse_archive_index_db(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Select Archive Index DB", self.archive_index_db_edit.text(), "SQLite DB (*.sqlite *.db);;All Files (*.*)")
        if path:
            self.archive_index_db_edit.setText(path)

    def browse_archive_capture(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Capture File", self.archive_capture_edit.text(), "Capture Files (*.jsonl *.json);;All Files (*.*)")
        if path:
            self.archive_capture_edit.setText(path)

    def browse_archive_baseline(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Baseline Capture File", self.archive_baseline_capture_edit.text() or self.archive_capture_edit.text(), "Capture Files (*.jsonl *.json);;All Files (*.*)")
        if path:
            self.archive_baseline_capture_edit.setText(path)

    def browse_archive_cache(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Archive Cache Directory", self.archive_cache_dir_edit.text())
        if path:
            self.archive_cache_dir_edit.setText(path)

    def browse_archive_correlation_root(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Decoded or Unpacked Root", self.archive_correlation_root_edit.text() or str(Path.cwd()))
        if path:
            self.archive_correlation_root_edit.setText(path)

    def browse_archive_selected_file(self) -> None:
        start = self.archive_selected_file_edit.text().strip() or self.archive_cache_dir_edit.text().strip() or str(Path.cwd())
        path, _ = QFileDialog.getOpenFileName(self, "Select Decoded or Unpacked File", start, "Decoded Files (*.paseq *.json *.xml *.bin);;All Files (*.*)")
        if path:
            self.archive_selected_file_edit.setText(path)

    def set_archive_busy(self, busy: bool) -> None:
        for button_name in [
            "archive_build_index_button",
            "archive_search_button",
            "archive_correlate_button",
            "archive_correlate_file_button",
            "archive_correlate_root_button",
            "correlation_guide_run_button",
            "archive_export_index_button",
            "archive_export_correlation_button",
            "archive_extract_match_button",
            "archive_export_dmm_button",
        ]:
            button = getattr(self, button_name, None)
            if button is not None:
                button.setEnabled(not busy)
        if busy:
            self.archive_summary_label.setText("Archive task running...")

    def start_archive_task(self, task: str, params: dict[str, Any]) -> None:
        if self.archive_task_worker is not None:
            QMessageBox.information(self, "Archive Task Running", "Wait for the current archive task to finish first.")
            return
        self.set_archive_busy(True)
        self.log_action("archive.task.start", task=task, params=params)
        self.archive_task_thread = QThread(self)
        self.archive_task_worker = ArchiveTaskWorker(task, params)
        self.archive_task_worker.moveToThread(self.archive_task_thread)
        self.archive_task_thread.started.connect(self.archive_task_worker.run)
        self.archive_task_worker.result.connect(self.on_archive_task_result)
        self.archive_task_worker.status.connect(self.on_archive_task_status)
        self.archive_task_worker.error.connect(self.on_archive_task_error)
        self.archive_task_worker.finished.connect(self.on_archive_task_finished)
        self.archive_task_worker.finished.connect(self.archive_task_thread.quit)
        self.archive_task_worker.finished.connect(self.archive_task_worker.deleteLater)
        self.archive_task_thread.finished.connect(self.archive_task_thread.deleteLater)
        self.archive_task_thread.start()

    def run_archive_index_build(self) -> None:
        try:
            root = require_path(self.archive_root_edit.text(), "Archive root", kind="dir")
            db_text = self.archive_index_db_edit.text().strip()
            if not db_text:
                raise ValueError("Index DB is required.")
            db_path = resolve_project_path(db_text, base_dir=project_root())
            paz_dir_text = self.archive_paz_dir_edit.text().strip()
            if paz_dir_text:
                require_path(paz_dir_text, "PAZ directory", kind="dir")
        except (ValueError, FileNotFoundError) as exc:
            QMessageBox.warning(self, "Archive Preflight Failed", str(exc))
            return
        limit = int(self.archive_index_limit_spin.value()) or None
        self.start_archive_task(
            "build-index",
            {
                "roots": [str(root)],
                "db_path": str(db_path),
                "paz_dir": paz_dir_text,
                "patterns": self.archive_patterns(self.archive_patterns_edit.toPlainText()),
                "limit": limit,
            },
        )

    def run_archive_index_search(self) -> None:
        try:
            db_path = require_path(resolve_project_path(self.archive_index_db_edit.text(), base_dir=project_root()), "Archive index DB", kind="file")
        except (ValueError, FileNotFoundError) as exc:
            QMessageBox.warning(self, "Archive Preflight Failed", str(exc))
            return
        self.start_archive_task(
            "search-index",
            {
                "db_path": str(db_path),
                "patterns": self.archive_patterns(self.archive_search_globs_edit.text()),
                "path_terms": self.archive_terms(self.archive_search_terms_edit.text()),
                "limit": int(self.archive_search_limit_spin.value()),
            },
        )

    def run_archive_correlation(self) -> None:
        try:
            capture_path = require_path(
                resolve_project_path(self.archive_capture_edit.text(), base_dir=project_root()),
                "Capture file",
                kind="file",
            )
            db_path = require_path(resolve_project_path(self.archive_index_db_edit.text(), base_dir=project_root()), "Archive index DB", kind="file")
            cache_dir = resolve_project_path(self.archive_cache_dir_edit.text(), base_dir=project_root())
            if not str(cache_dir).strip():
                raise ValueError("Cache dir is required.")
            if cache_dir.exists() and not cache_dir.is_dir():
                raise ValueError(f"Cache dir must be a folder: {cache_dir}")
            if not cache_dir.exists():
                cache_dir.mkdir(parents=True, exist_ok=True)
            if self.archive_baseline_capture_edit.text().strip():
                require_path(
                    resolve_project_path(self.archive_baseline_capture_edit.text(), base_dir=project_root()),
                    "Baseline capture file",
                    kind="file",
                )
        except (ValueError, FileNotFoundError, OSError) as exc:
            QMessageBox.warning(self, "Archive Preflight Failed", str(exc))
            return
        self.start_archive_task(
            "correlate-archive",
            {
                "capture_path": str(capture_path),
                "db_path": str(db_path),
                "cache_dir": str(cache_dir),
                "patterns": self.archive_patterns(self.archive_correlation_globs_edit.text()),
                "path_terms": self.archive_terms(self.archive_correlation_terms_edit.text()),
                "max_entries": int(self.archive_correlation_max_entries_spin.value()),
                "max_matches": int(self.archive_correlation_max_matches_spin.value()),
                "max_matches_per_evidence": int(self.archive_correlation_max_per_evidence_spin.value()),
                "context_bytes": int(self.archive_correlation_context_spin.value()),
                "include_numeric": self.archive_correlation_numeric_check.isChecked(),
                "include_format_hints": self.archive_correlation_hints_check.isChecked(),
                "decrypt_xml": self.archive_correlation_decrypt_check.isChecked(),
            },
        )

    def run_selected_file_correlation(self) -> None:
        try:
            capture_path = require_path(self.archive_capture_edit.text(), "Capture file", kind="file")
            selected_file = require_path(self.archive_selected_file_edit.text(), "Decoded/unpacked file", kind="file")
        except (ValueError, FileNotFoundError) as exc:
            QMessageBox.warning(self, "Archive Preflight Failed", str(exc))
            return
        self.start_archive_task(
            "correlate-file",
            {
                "capture_path": str(capture_path),
                "selected_file": str(selected_file),
                "max_matches": int(self.archive_correlation_max_matches_spin.value()),
                "max_matches_per_evidence": int(self.archive_correlation_max_per_evidence_spin.value()),
                "context_bytes": int(self.archive_correlation_context_spin.value()),
                "include_numeric": self.archive_correlation_numeric_check.isChecked(),
                "include_format_hints": self.archive_correlation_hints_check.isChecked(),
            },
        )

    def run_root_correlation(self) -> None:
        try:
            capture_path = require_path(self.archive_capture_edit.text(), "Capture file", kind="file")
            root_path = require_path(self.archive_correlation_root_edit.text(), "Decoded/unpacked folder", kind="dir")
            baseline_text = self.archive_baseline_capture_edit.text().strip()
            if baseline_text:
                require_path(baseline_text, "Baseline capture file", kind="file")
        except (ValueError, FileNotFoundError) as exc:
            QMessageBox.warning(self, "Archive Preflight Failed", str(exc))
            return
        self.start_archive_task(
            "correlate-root",
            {
                "capture_path": str(capture_path),
                "baseline_path": baseline_text,
                "root_path": str(root_path),
                "patterns": self.archive_patterns(self.archive_correlation_globs_edit.text()),
                "max_matches": int(self.archive_correlation_max_matches_spin.value()),
                "max_matches_per_evidence": int(self.archive_correlation_max_per_evidence_spin.value()),
                "context_bytes": int(self.archive_correlation_context_spin.value()),
                "include_numeric": self.archive_correlation_numeric_check.isChecked(),
                "include_format_hints": self.archive_correlation_hints_check.isChecked(),
            },
        )

    @Slot(str, dict)
    def on_archive_task_result(self, task: str, result: dict[str, Any]) -> None:
        if task == "build-index":
            self.render_archive_index_report(result)
            self.append_log(f"Archive index built with {result.get('indexed_count', 0)} entries.")
            self.log_action("archive.task.result", task=task, indexed_count=result.get("indexed_count", 0))
            return
        if task == "search-index":
            self.render_archive_index_search(result)
            self.append_log(f"Archive index search returned {result.get('entry_count', 0)} entries.")
            self.log_action("archive.task.result", task=task, entry_count=result.get("entry_count", 0))
            return
        if task == "correlate-archive":
            self.render_archive_correlation(result)
            self.append_log(f"Archive correlation returned {result.get('match_count', 0)} match(es).")
            self.log_action("archive.task.result", task=task, match_count=result.get("match_count", 0))
            return
        if task == "correlate-file":
            self.render_file_correlation(result)
            self.append_log(f"File correlation returned {result.get('match_count', 0)} match(es).")
            self.log_action("archive.task.result", task=task, match_count=result.get("match_count", 0))
            return
        if task == "correlate-root":
            self.render_file_correlation(result)
            self.append_log(f"Folder correlation returned {result.get('match_count', 0)} match(es).")
            self.log_action("archive.task.result", task=task, match_count=result.get("match_count", 0))

    @Slot(str)
    def on_archive_task_status(self, message: str) -> None:
        self.archive_summary_label.setText(message)
        self.status_label.setText(message)
        self.append_log(message)
        self.log_action("archive.task.status", message=message)

    @Slot(str)
    def on_archive_task_error(self, message: str) -> None:
        self.archive_summary_label.setText(f"Archive task failed: {message}")
        self.append_log(f"Archive task failed: {message}")
        self.show_error_summary("Archive Task Failed", message)
        QMessageBox.warning(self, "Archive Task Failed", message)

    @Slot()
    def on_archive_task_finished(self) -> None:
        self.archive_task_worker = None
        self.archive_task_thread = None
        self.set_archive_busy(False)

    def render_archive_index_report(self, report: dict[str, Any]) -> None:
        self.last_archive_index_report = report
        self.archive_summary_label.setText(
            f"Indexed {report.get('indexed_count', 0)} entries into {report.get('db_path', self.archive_index_db_edit.text())}."
        )
        self.archive_report_view.setPlainText(render_archive_index_markdown(report))

    def render_archive_index_search(self, result: dict[str, Any]) -> None:
        self.last_archive_index_search = result
        entries = list(result.get("entries", []))
        self.archive_summary_label.setText(
            f"Index search found {result.get('entry_count', len(entries))} entries for {', '.join(result.get('patterns', []))}."
        )
        self.render_archive_index_entries(entries)
        self.archive_report_view.setPlainText(json.dumps(result, ensure_ascii=False, indent=2))

    def render_archive_index_entries(self, entries: list[dict[str, Any]]) -> None:
        self.archive_index_table.setRowCount(len(entries))
        for row_index, entry in enumerate(entries):
            values = [
                entry.get("path", ""),
                entry.get("extension", ""),
                entry.get("compression_name", ""),
                Path(str(entry.get("paz_file", ""))).name,
                entry.get("offset_hex", ""),
                entry.get("comp_size", ""),
                entry.get("orig_size", ""),
                entry.get("flags_hex", ""),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.archive_index_table.setItem(row_index, column, item)
        self.filter_archive_index_rows(self.archive_search_filter_edit.text())

    def render_archive_correlation(self, result: dict[str, Any]) -> None:
        self.last_archive_correlation = result
        self.last_file_correlation = None
        matches = list(result.get("matches", []))
        self.current_correlation_matches = matches
        self.archive_summary_label.setText(
            f"Archive correlation found {result.get('match_count', 0)} matches from {result.get('candidate_entry_count', 0)} candidate entries. "
            f"Decoded {result.get('decoded_entry_count', 0)} entries with {result.get('cache_hit_count', 0)} cache hits."
        )
        self.archive_correlation_table.setRowCount(len(matches))
        for row_index, match in enumerate(matches):
            values = [
                match.get("confidence", ""),
                match.get("archive_path", ""),
                match.get("decoded_offset_hex", ""),
                match.get("match_type", ""),
                match.get("evidence_value", ""),
                match.get("evidence_count", ""),
                match.get("compression_decoder", ""),
                match.get("original_bytes", ""),
                match.get("cache_path", ""),
                ", ".join(str(item) for item in match.get("confidence_reasons", [])),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.archive_correlation_table.setItem(row_index, column, item)
        self.archive_report_view.setPlainText(render_archive_correlation_markdown(result))
        self.match_preview_view.setPlainText("Select an archive correlation match to preview decoded bytes and patch context.")
        self.filter_archive_correlation_rows(self.archive_correlation_filter_edit.text())

    def render_file_correlation(self, result: dict[str, Any]) -> None:
        self.last_file_correlation = result
        self.last_archive_correlation = None
        matches = list(result.get("matches", []))
        self.current_correlation_matches = matches
        selected = ", ".join(result.get("selected_files", [])) or result.get("root", "")
        scope = "selected file(s)" if result.get("selected_files") else "decoded folder file(s)"
        self.archive_summary_label.setText(
            f"File correlation found {result.get('match_count', 0)} matches in {result.get('file_count', 0)} {scope}."
        )
        self.archive_correlation_table.setRowCount(len(matches))
        for row_index, match in enumerate(matches):
            values = [
                match.get("confidence", ""),
                match.get("relative_file") or match.get("file", ""),
                match.get("offset_hex", ""),
                match.get("match_type", ""),
                match.get("evidence_value", ""),
                match.get("evidence_count", ""),
                "selected-file",
                match.get("original_bytes", ""),
                selected,
                ", ".join(str(item) for item in match.get("confidence_reasons", [])),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.archive_correlation_table.setItem(row_index, column, item)
        self.archive_report_view.setPlainText(render_correlation_markdown(result))
        self.match_preview_view.setPlainText("Select a file correlation match to preview decoded bytes and patch context.")
        self.filter_archive_correlation_rows(self.archive_correlation_filter_edit.text())

    def update_match_preview_from_selection(self) -> None:
        if not hasattr(self, "match_preview_view"):
            return
        row = self.archive_correlation_table.currentRow()
        if row < 0 or row >= len(self.current_correlation_matches):
            self.match_preview_view.setPlainText("Select a correlation match to preview decoded bytes and patch context.")
            return
        self.match_preview_view.setPlainText(self.build_match_preview(self.current_correlation_matches[row]))

    def build_match_preview(self, match: dict[str, Any], *, radius: int = 96) -> str:
        source_text = str(match.get("cache_path") or match.get("file") or "").strip()
        source_file = Path(source_text) if source_text else Path()
        offset = self.match_offset(match)
        original = str(match.get("original_bytes", ""))
        lines = [
            "# Match Preview",
            "",
            f"Source: {source_text or '<unknown>'}",
            f"Archive path: {match.get('archive_path', '<not archive-backed>')}",
            f"Offset: {match.get('decoded_offset_hex') or match.get('offset_hex') or offset}",
            f"Type: {match.get('match_type', '')}",
            f"Evidence: {match.get('evidence_value', '')}",
            f"Confidence: {match.get('confidence', '')}",
            f"Reasons: {', '.join(str(item) for item in match.get('confidence_reasons', []))}",
            "",
            "Patch skeleton:",
            json.dumps(match.get("patch_skeleton", {}), ensure_ascii=False, indent=2),
            "",
            f"Original bytes: {original}",
        ]
        preview = self.read_match_preview_bytes(source_file, offset, radius=radius)
        if preview is None:
            context_hex = str(match.get("context_hex", "")).strip()
            if context_hex:
                lines.extend(["", "Context hex from report:", context_hex])
            else:
                lines.extend(["", "No readable decoded/cache file or context bytes were available for this match."])
            return "\n".join(lines)

        start, blob = preview
        lines.extend(
            [
                "",
                f"Preview window: 0x{start:X} - 0x{start + len(blob):X}",
                "",
                "Hex:",
                self.hex_dump(blob, base_offset=start),
                "",
                "Printable text:",
                self.printable_preview(blob),
            ]
        )
        return "\n".join(lines)

    def match_offset(self, match: dict[str, Any]) -> int:
        value = match.get("decoded_offset", match.get("offset", 0))
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    def read_match_preview_bytes(self, source_file: Path, offset: int, *, radius: int) -> tuple[int, bytes] | None:
        if not str(source_file) or not source_file.exists() or not source_file.is_file():
            return None
        try:
            size = source_file.stat().st_size
            start = max(0, offset - radius)
            end = min(size, offset + radius)
            with source_file.open("rb") as handle:
                handle.seek(start)
                return start, handle.read(max(0, end - start))
        except OSError:
            return None

    def hex_dump(self, blob: bytes, *, base_offset: int = 0, width: int = 16) -> str:
        rows: list[str] = []
        for row_start in range(0, len(blob), width):
            chunk = blob[row_start : row_start + width]
            hex_part = " ".join(f"{byte:02X}" for byte in chunk)
            ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            rows.append(f"{base_offset + row_start:08X}  {hex_part:<{width * 3}}  {ascii_part}")
        return "\n".join(rows) if rows else "<empty>"

    def printable_preview(self, blob: bytes) -> str:
        text = "".join(chr(byte) if byte in {9, 10, 13} or 32 <= byte <= 126 else "." for byte in blob)
        return text.strip() or "<no printable text>"

    def filter_archive_index_rows(self, text: str) -> None:
        self.filter_table_rows(self.archive_index_table, text)

    def filter_archive_correlation_rows(self, text: str) -> None:
        self.filter_table_rows(self.archive_correlation_table, text)

    def filter_table_rows(self, table: QTableWidget, text: str) -> None:
        needle = text.strip().lower()
        for row in range(table.rowCount()):
            visible = True
            if needle:
                visible = any(
                    needle in table.item(row, column).text().lower()
                    for column in range(table.columnCount())
                    if table.item(row, column) is not None
                )
            table.setRowHidden(row, not visible)

    def export_archive_index_report(self) -> None:
        report = self.last_archive_index_report
        if not report:
            QMessageBox.information(self, "No Index Report", "Build an archive index first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Archive Index Report", "archive-index.md", "Markdown (*.md);;JSON (*.json);;CSV (*.csv);;All Files (*.*)")
        if not path:
            return
        try:
            suffix = Path(path).suffix.lower()
            if suffix == ".json":
                rendered = json.dumps(report, ensure_ascii=False, indent=2)
            elif suffix == ".csv":
                rendered = render_archive_index_csv(report)
            else:
                rendered = render_archive_index_markdown(report)
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(rendered, encoding="utf-8")
            self.append_log(f"Exported archive index report to {path}.")
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", str(exc))

    def export_archive_correlation(self) -> None:
        result = self.last_archive_correlation or self.last_file_correlation
        if not result:
            QMessageBox.information(self, "No Correlation Results", "Run archive or file correlation first.")
            return
        fmt = self.archive_correlation_format_combo.currentText()
        is_file_correlation = self.last_file_correlation is not None
        default_prefix = "file-correlation" if is_file_correlation else "archive-correlation"
        default_name = f"{default_prefix}.{ 'md' if fmt == 'markdown' else fmt }"
        path, _ = QFileDialog.getSaveFileName(self, "Export Correlation", default_name, "All Files (*.*)")
        if not path:
            return
        try:
            if fmt == "json":
                rendered = json.dumps(result, ensure_ascii=False, indent=2)
            elif fmt == "csv":
                rendered = render_correlation_csv(result) if is_file_correlation else render_archive_correlation_csv(result)
            else:
                rendered = render_correlation_markdown(result) if is_file_correlation else render_archive_correlation_markdown(result)
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(rendered, encoding="utf-8")
            self.append_log(f"Exported archive correlation results to {path}.")
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", str(exc))

    def selected_correlation_match(self) -> dict[str, Any] | None:
        row = self.archive_correlation_table.currentRow()
        if row < 0 or row >= len(self.current_correlation_matches):
            return None
        return self.current_correlation_matches[row]

    def extract_selected_archive_match(self) -> None:
        if not self.last_archive_correlation:
            QMessageBox.information(self, "No Archive Match", "Run archive correlation and select an archive-backed match first.")
            return
        match = self.selected_correlation_match()
        if not match:
            QMessageBox.information(self, "No Selection", "Select an archive correlation match to extract.")
            return
        if not match.get("cache_path") or not match.get("archive_path"):
            QMessageBox.information(self, "Not Archive Backed", "The selected row does not include archive cache metadata.")
            return
        default_dir = str(Path(match.get("cache_path", "")).parent)
        output_dir = QFileDialog.getExistingDirectory(self, "Extract Selected Archive Entry To", default_dir)
        if not output_dir:
            return
        try:
            result = export_cached_archive_match(match, Path(output_dir))
        except Exception as exc:
            QMessageBox.warning(self, "Extraction Failed", str(exc))
            return
        self.append_log(f"Extracted {result['archive_path']} to {result['output_path']}.")
        QMessageBox.information(
            self,
            "Extraction Complete",
            f"Decoded entry written to:\n{result['output_path']}\n\nMetadata written to:\n{result['metadata_path']}",
        )

    def export_dmm_draft(self) -> None:
        result = self.last_archive_correlation or self.last_file_correlation
        if not result:
            QMessageBox.information(self, "No Correlation Results", "Run archive or file correlation first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export DMM Draft", "cdsniffer-dmm-draft.json", "DMM JSON (*.json);;All Files (*.*)")
        if not path:
            return
        try:
            rendered = render_dmm_patch_draft(result)
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(rendered, encoding="utf-8")
            self.append_log(f"Exported DMM draft to {path}. Review patched values before using it in DMM.")
        except Exception as exc:
            QMessageBox.warning(self, "DMM Export Failed", str(exc))

    def build_log_tab(self) -> None:
        layout = QVBoxLayout(self.log_tab)
        toolbar = QHBoxLayout()
        self.copy_error_button = QPushButton("Copy Last Error")
        self.restore_last_good_button = QPushButton("Restore Last Good Settings")
        self.copy_error_button.clicked.connect(self.copy_last_error_summary)
        self.restore_last_good_button.clicked.connect(self.restore_last_good_settings_snapshot)
        toolbar.addWidget(self.copy_error_button)
        toolbar.addWidget(self.restore_last_good_button)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Cascadia Mono", 10))
        layout.addWidget(self.log_view)

    def settings_snapshot_root(self) -> Path:
        return Path.home() / ".cdsniffer"

    def last_good_settings_path(self) -> Path:
        return self.settings_snapshot_root() / "last-good-settings.json"

    def write_last_good_settings_snapshot(self, settings: dict[str, Any] | None = None) -> None:
        snapshot = dict(settings or self.collect_settings_dict())
        path = self.last_good_settings_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")

    def restore_last_good_settings_snapshot(self) -> None:
        path = self.last_good_settings_path()
        if not path.exists():
            QMessageBox.information(self, "No Last-Good Snapshot", "No saved last-good settings snapshot exists yet.")
            return
        try:
            self.load_settings_profile_from_path(path)
            self.log_action("settings.restore", path=str(path))
            self.append_log(f"Restored last-good settings snapshot from {path}.")
        except Exception as exc:
            QMessageBox.warning(self, "Restore Failed", str(exc))

    def copy_last_error_summary(self) -> None:
        if not self.last_error_summary:
            QMessageBox.information(self, "No Error Summary", "No recent error summary is available yet.")
            return
        QApplication.clipboard().setText(self.last_error_summary)
        self.log_action("error.copy_summary")
        self.append_log("Copied last error summary to clipboard.")

    def show_error_summary(self, title: str, message: str, *, details: str | None = None) -> None:
        summary = {
            "title": title,
            "message": message,
            "details": details or "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.last_error_summary = json.dumps(summary, ensure_ascii=False, indent=2)
        self.log_action("error", title=title, message=message, details=details or "")
        QApplication.clipboard().setText(self.last_error_summary)

    def log_action(self, action: str, **fields: Any) -> None:
        self.append_log(format_action_log(action, **fields))

    def build_terminal_tab(self) -> None:
        layout = QVBoxLayout(self.terminal_tab)
        self.terminal_panel = TerminalPanel(self.execute_terminal_command, self.terminal_tab)
        self.terminal_panel.append("CDSniffer terminal ready. Type `help` for commands.")
        layout.addWidget(self.terminal_panel)

    def preset_root(self) -> Path:
        return Path.home() / ".cdsniffer" / "presets"

    def preset_path_from_name(self, name: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-")
        if not safe:
            safe = "default"
        return self.preset_root() / f"{safe}.json"

    def preset_files(self) -> list[Path]:
        root = self.preset_root()
        if not root.exists():
            return []
        return sorted(path for path in root.glob("*.json") if path.is_file())

    def build_presets_tab(self) -> None:
        layout = QVBoxLayout(self.presets_tab)
        header = QGroupBox("Preset Manager")
        header_layout = QVBoxLayout(header)
        self.preset_name_edit = QLineEdit()
        self.preset_name_edit.setPlaceholderText("Preset name")
        self.preset_list = QListWidget()
        self.preset_list.itemSelectionChanged.connect(self.sync_preset_name_from_selection)
        header_layout.addWidget(self.preset_name_edit)
        header_layout.addWidget(self.preset_list)
        layout.addWidget(header)

        buttons = QHBoxLayout()
        self.preset_refresh_button = QPushButton("Refresh")
        self.preset_save_button = QPushButton("Save")
        self.preset_load_button = QPushButton("Load")
        self.preset_delete_button = QPushButton("Delete")
        self.preset_import_button = QPushButton("Import")
        self.preset_export_button = QPushButton("Export")
        self.preset_refresh_button.clicked.connect(self.refresh_preset_list)
        self.preset_save_button.clicked.connect(self.save_named_preset)
        self.preset_load_button.clicked.connect(self.load_selected_preset)
        self.preset_delete_button.clicked.connect(self.delete_selected_preset)
        self.preset_import_button.clicked.connect(self.import_preset_file)
        self.preset_export_button.clicked.connect(self.export_selected_preset)
        buttons.addWidget(self.preset_refresh_button)
        buttons.addWidget(self.preset_save_button)
        buttons.addWidget(self.preset_load_button)
        buttons.addWidget(self.preset_delete_button)
        buttons.addWidget(self.preset_import_button)
        buttons.addWidget(self.preset_export_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.preset_info = QLabel("Presets are stored as JSON in your local CDSniffer profile folder.")
        self.preset_info.setWordWrap(True)
        layout.addWidget(self.preset_info)
        self.refresh_preset_list()

    def refresh_preset_list(self) -> None:
        self.preset_list.clear()
        for path in self.preset_files():
            self.preset_list.addItem(path.stem)

    def selected_preset_path(self) -> Path | None:
        item = self.preset_list.currentItem()
        if item is None:
            return None
        return self.preset_path_from_name(item.text())

    def sync_preset_name_from_selection(self) -> None:
        item = self.preset_list.currentItem()
        if item is not None:
            self.preset_name_edit.setText(item.text())

    def save_named_preset(self) -> None:
        name = self.preset_name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Missing Name", "Enter a preset name first.")
            return
        try:
            path = self.preset_path_from_name(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(self.collect_settings_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
            self.refresh_preset_list()
            self.log_action("preset.save", path=str(path))
        except Exception as exc:
            QMessageBox.warning(self, "Save Failed", str(exc))

    def load_selected_preset(self) -> None:
        path = self.selected_preset_path()
        if path is None or not path.exists():
            QMessageBox.information(self, "No Preset", "Select a preset first.")
            return
        try:
            settings = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(settings, dict):
                raise ValueError("Preset JSON must be an object.")
            self.apply_settings_dict(settings)
            self.log_action("preset.load", path=str(path))
        except Exception as exc:
            QMessageBox.warning(self, "Load Failed", str(exc))

    def delete_selected_preset(self) -> None:
        path = self.selected_preset_path()
        if path is None or not path.exists():
            QMessageBox.information(self, "No Preset", "Select a preset first.")
            return
        try:
            path.unlink()
            self.refresh_preset_list()
            self.append_log(f"Deleted preset: {path.stem}")
        except Exception as exc:
            QMessageBox.warning(self, "Delete Failed", str(exc))

    def import_preset_file(self) -> None:
        path_text, _ = QFileDialog.getOpenFileName(self, "Import Preset", "", "JSON Files (*.json)")
        if not path_text:
            return
        src = Path(path_text)
        try:
            data = json.loads(src.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Preset JSON must be an object.")
            name = src.stem
            dest = self.preset_path_from_name(name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            self.refresh_preset_list()
            self.log_action("preset.import", path=str(dest))
        except Exception as exc:
            QMessageBox.warning(self, "Import Failed", str(exc))

    def export_selected_preset(self) -> None:
        path = self.selected_preset_path()
        if path is None or not path.exists():
            QMessageBox.information(self, "No Preset", "Select a preset first.")
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "Export Preset", path.name, "JSON Files (*.json)")
        if not save_path:
            return
        try:
            Path(save_path).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            self.log_action("preset.export", path=str(save_path))
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", str(exc))

    def setup_tray_icon(self) -> None:
        if self.tray_icon is not None:
            self.tray_icon.hide()
            self.tray_icon.deleteLater()
            self.tray_icon = None
        self.tray_status_action = None
        if not self.tray_enabled_check.isChecked() or not QSystemTrayIcon.isSystemTrayAvailable():
            return
        icon = load_app_icon()
        self.tray_icon = QSystemTrayIcon(icon, self)
        self.tray_icon.setToolTip("CDSniffer")
        menu = QMenu()
        self.tray_status_action = menu.addAction("Status: Idle")
        self.tray_status_action.setEnabled(False)
        menu.addSeparator()
        show_action = menu.addAction("Show Window")
        hide_action = menu.addAction("Hide Window")
        menu.addSeparator()
        start_action = menu.addAction("Start Capture")
        stop_action = menu.addAction("Stop Capture")
        settings_action = menu.addAction("Open Settings")
        menu.addSeparator()
        exit_action = menu.addAction("Exit")

        show_action.triggered.connect(self.show_from_tray)
        hide_action.triggered.connect(self.hide)
        start_action.triggered.connect(self.start_capture)
        stop_action.triggered.connect(self.stop_capture)
        settings_action.triggered.connect(self.open_settings_dialog)
        exit_action.triggered.connect(self.exit_application)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()

    def refresh_tray_configuration(self) -> None:
        self.setup_tray_icon()
        self.update_tray_status("CDSniffer: idle" if self.worker is None else "CDSniffer: capturing")
        if self.tray_icon and self.tray_start_hidden_check.isChecked() and self.isVisible():
            self.hide()

    def tray_event_enabled(self, event_name: str) -> bool:
        event_map = {
            "game_detected": "tray_notify_game_detected_check",
            "game_lost": "tray_notify_game_lost_check",
            "capture_started": "tray_notify_capture_started_check",
            "capture_stopped": "tray_notify_capture_stopped_check",
            "relinked": "tray_notify_relinked_check",
            "errors": "tray_notify_errors_check",
            "capture_complete": "tray_notify_capture_complete_check",
        }
        attr = event_map.get(event_name)
        if attr is None:
            return False
        widget = getattr(self, attr, None)
        return bool(widget and widget.isChecked())

    def update_tray_status(self, text: str) -> None:
        if self.tray_status_action is not None:
            self.tray_status_action.setText(text)
        if self.tray_icon is not None:
            self.tray_icon.setToolTip(text)

    def notify_tray(self, event_name: str, title: str, message: str) -> None:
        if self.tray_icon and self.tray_notifications_check.isChecked() and self.tray_event_enabled(event_name):
            self.tray_icon.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, 2500)

    def on_tray_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            behavior = self.tray_click_behavior_combo.currentText()
            if behavior == "menu":
                return
            if behavior == "show":
                self.show_from_tray()
                return
            if self.isVisible():
                self.hide()
                self.update_tray_status("CDSniffer: hidden to tray")
            else:
                self.show_from_tray()

    def show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def exit_application(self) -> None:
        self._force_close = True
        self.close()

    def browse_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Select Output File", self.output_edit.text(), "All Files (*.*)")
        if path:
            self.output_edit.setText(path)

    def export_settings_profile(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Settings Profile", "cdsniffer-profile.json", "JSON Files (*.json)")
        if not path:
            return
        try:
            self.save_settings_profile_to_path(path)
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", str(exc))

    def import_settings_profile(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Settings Profile", "", "JSON Files (*.json)")
        if not path:
            return
        try:
            self.load_settings_profile_from_path(path)
        except Exception as exc:
            QMessageBox.warning(self, "Import Failed", str(exc))

    def save_settings_profile_to_path(self, path: str | Path) -> None:
        profile = self.collect_settings_dict()
        target = Path(path)
        target.write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")
        self.write_last_good_settings_snapshot(profile)
        self.log_action("settings.export", path=str(target))

    def load_settings_profile_from_path(self, path: str | Path) -> None:
        source = Path(path)
        settings = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(settings, dict):
            raise ValueError("Profile JSON must be an object.")
        validate_settings_dict(settings)
        self.apply_settings_dict(settings)
        self.log_action("settings.import", path=str(source))

    def collect_settings_dict(self) -> dict[str, Any]:
        pid_text = self.pid_edit.text().strip()
        pid = int(pid_text) if pid_text else None
        return {
            "pid": pid,
            "process": self.process_edit.text().strip() or "Crimson Desert",
            "window_titles": split_values(self.window_title_edit.text()),
            "window_filter_patterns": split_values(self.window_filter_edit.text()),
            "pick_window": False,
            "list_windows": False,
            "mode": self.mode_combo.currentText(),
            "hotkey": normalize_hotkey_name(self.hotkey_edit.text()),
            "interval": float(self.interval_spin.value()),
            "captures": self.captures_spin.value() or None,
            "output": self.output_edit.text().strip() or "logs/cdsniffer.jsonl",
            "timestamp_output": self.timestamp_check.isChecked(),
            "session_name": self.session_name_edit.text().strip() or "cdsniffer",
            "format": self.format_combo.currentText(),
            "label": self.label_edit.text().strip() or "capture",
            "game_version": self.game_version_edit.text().strip(),
            "capture_gate": self.capture_gate_combo.currentText(),
            "capture_gate_match": self.capture_gate_match_combo.currentText(),
            "unique_only": self.unique_only_check.isChecked(),
            "include_keywords": split_values(self.include_keywords_edit.toPlainText()),
            "exclude_keywords": split_values(self.exclude_keywords_edit.toPlainText()),
            "include_patterns": split_values(self.include_regex_edit.toPlainText()),
            "exclude_patterns": split_values(self.exclude_regex_edit.toPlainText()),
            "signature_packs": split_values(self.signature_pack_edit.toPlainText()),
            "watch_patterns": split_values(self.watch_edit.toPlainText()),
            "gate_keywords": split_values(self.gate_keywords_edit.toPlainText()),
            "gate_patterns": split_values(self.gate_regex_edit.toPlainText()),
            "notes": split_values(self.notes_edit.toPlainText()),
            "max_region_size": 16 * 1024 * 1024 if not hasattr(self, "max_region_size") else int(self.max_region_size.value()),
            "max_regions": None if not hasattr(self, "max_regions") else (self.max_regions.value() or None),
            "max_hits_per_region": None if not hasattr(self, "max_hits_per_region") else (self.max_hits_per_region.value() or None),
            "context_bytes": 0 if not hasattr(self, "context_bytes_spin") else int(self.context_bytes_spin.value()),
            "decode_context_numbers": bool(
                hasattr(self, "decode_context_numbers_check") and self.decode_context_numbers_check.isChecked()
            ),
            "context_number_radius": 16
            if not hasattr(self, "context_number_radius_spin")
            else int(self.context_number_radius_spin.value()),
            "gate_max_regions": None if not hasattr(self, "gate_max_regions_spin") else (self.gate_max_regions_spin.value() or None),
            "gate_max_hits_per_region": None
            if not hasattr(self, "gate_max_hits_per_region_spin")
            else (self.gate_max_hits_per_region_spin.value() or None),
            "summary": self.summary_combo.currentText(),
            "summary_limit": self.summary_limit_spin.value(),
            "compare_last": self.compare_check.isChecked(),
            "compare_limit": self.compare_limit_spin.value(),
            "export_manifest": self.export_manifest_check.isChecked(),
            "quiet": self.quiet_check.isChecked(),
            "verbose": self.verbose_check.isChecked(),
            "tray_enabled": self.tray_enabled_check.isChecked(),
            "tray_start_hidden": self.tray_start_hidden_check.isChecked(),
            "tray_minimize_to_tray": self.tray_minimize_to_tray_check.isChecked(),
            "tray_notifications": self.tray_notifications_check.isChecked(),
            "tray_click_behavior": self.tray_click_behavior_combo.currentText(),
        }

    def apply_settings_dict(self, settings: dict[str, Any]) -> None:
        validate_settings_dict(settings)
        hotkey = normalize_hotkey_name(settings.get("hotkey", "F8"))
        if settings.get("pid") is not None:
            self.pid_edit.setText(str(settings["pid"]))
        self.process_edit.setText(str(settings.get("process", "Crimson Desert")))
        self.window_title_edit.setText("\n".join(settings.get("window_titles", [])))
        self.window_filter_edit.setText("\n".join(settings.get("window_filter_patterns", [])))
        self.mode_combo.setCurrentText(str(settings.get("mode", "loop")))
        self.hotkey_edit.setText(hotkey)
        self.interval_spin.setValue(float(settings.get("interval", 2.0)))
        captures_value = settings.get("captures")
        self.captures_spin.setValue(int(captures_value) if captures_value else 0)
        self.output_edit.setText(str(settings.get("output", "logs/cdsniffer.jsonl")))
        self.timestamp_check.setChecked(bool(settings.get("timestamp_output", True)))
        self.session_name_edit.setText(str(settings.get("session_name", "cdsniffer")))
        self.format_combo.setCurrentText(str(settings.get("format", "jsonl")))
        self.label_edit.setText(str(settings.get("label", "capture")))
        self.game_version_edit.setText(str(settings.get("game_version", "")))
        self.capture_gate_combo.setCurrentText(str(settings.get("capture_gate", "off")))
        self.capture_gate_match_combo.setCurrentText(str(settings.get("capture_gate_match", "any")))
        self.unique_only_check.setChecked(bool(settings.get("unique_only", False)))
        self.include_keywords_edit.setPlainText(join_values(settings.get("include_keywords")))
        self.exclude_keywords_edit.setPlainText(join_values(settings.get("exclude_keywords")))
        self.include_regex_edit.setPlainText(join_values(settings.get("include_patterns")))
        self.exclude_regex_edit.setPlainText(join_values(settings.get("exclude_patterns")))
        self.signature_pack_edit.setPlainText(join_values(settings.get("signature_packs")))
        self.watch_edit.setPlainText(join_values(settings.get("watch_patterns")))
        self.gate_keywords_edit.setPlainText(join_values(settings.get("gate_keywords")))
        self.gate_regex_edit.setPlainText(join_values(settings.get("gate_patterns")))
        self.notes_edit.setPlainText(join_values(settings.get("notes")))
        if hasattr(self, "max_region_size"):
            self.max_region_size.setValue(int(settings.get("max_region_size", 16 * 1024 * 1024)))
        if hasattr(self, "max_regions"):
            self.max_regions.setValue(int(settings["max_regions"]) if settings.get("max_regions") else 0)
        if hasattr(self, "max_hits_per_region"):
            self.max_hits_per_region.setValue(int(settings["max_hits_per_region"]) if settings.get("max_hits_per_region") else 0)
        if hasattr(self, "context_bytes_spin"):
            self.context_bytes_spin.setValue(int(settings.get("context_bytes", 0)))
        if hasattr(self, "decode_context_numbers_check"):
            self.decode_context_numbers_check.setChecked(bool(settings.get("decode_context_numbers", False)))
        if hasattr(self, "context_number_radius_spin"):
            self.context_number_radius_spin.setValue(int(settings.get("context_number_radius", 16)))
        if hasattr(self, "gate_max_regions_spin"):
            self.gate_max_regions_spin.setValue(int(settings["gate_max_regions"]) if settings.get("gate_max_regions") else 0)
        if hasattr(self, "gate_max_hits_per_region_spin"):
            self.gate_max_hits_per_region_spin.setValue(
                int(settings["gate_max_hits_per_region"]) if settings.get("gate_max_hits_per_region") else 0
            )
        self.summary_combo.setCurrentText(str(settings.get("summary", "none")))
        self.summary_limit_spin.setValue(int(settings.get("summary_limit", 10)))
        self.compare_check.setChecked(bool(settings.get("compare_last", False)))
        self.compare_limit_spin.setValue(int(settings.get("compare_limit", 20)))
        self.export_manifest_check.setChecked(bool(settings.get("export_manifest", False)))
        self.quiet_check.setChecked(bool(settings.get("quiet", False)))
        self.verbose_check.setChecked(bool(settings.get("verbose", False)))
        self.tray_enabled_check.setChecked(bool(settings.get("tray_enabled", True)))
        self.tray_start_hidden_check.setChecked(bool(settings.get("tray_start_hidden", False)))
        self.tray_minimize_to_tray_check.setChecked(bool(settings.get("tray_minimize_to_tray", True)))
        self.tray_notifications_check.setChecked(bool(settings.get("tray_notifications", True)))
        self.tray_click_behavior_combo.setCurrentText(str(settings.get("tray_click_behavior", "toggle")))
        self.tray_notify_game_detected_check.setChecked(bool(settings.get("tray_notify_game_detected", True)))
        self.tray_notify_game_lost_check.setChecked(bool(settings.get("tray_notify_game_lost", True)))
        self.tray_notify_capture_started_check.setChecked(bool(settings.get("tray_notify_capture_started", True)))
        self.tray_notify_capture_stopped_check.setChecked(bool(settings.get("tray_notify_capture_stopped", True)))
        self.tray_notify_relinked_check.setChecked(bool(settings.get("tray_notify_relinked", True)))
        self.tray_notify_errors_check.setChecked(bool(settings.get("tray_notify_errors", True)))
        self.tray_notify_capture_complete_check.setChecked(bool(settings.get("tray_notify_capture_complete", False)))
        self.write_last_good_settings_snapshot()
        self.refresh_capture_summary()
        self.refresh_target_indicator()
        self.refresh_tray_configuration()

    def open_settings_dialog(self) -> None:
        dialog = SettingsDialog(self, self.collect_settings_dict())
        if dialog.exec() == QDialog.Accepted:
            try:
                self.apply_settings_dict(dialog.settings_dict())
                self.log_action("settings.apply", source="dialog")
            except Exception as exc:
                self.show_error_summary("Settings Update Failed", str(exc), details=traceback.format_exc())
                QMessageBox.warning(self, "Settings Update Failed", str(exc))

    def build_settings_namespace(self) -> argparse.Namespace:
        pid_text = self.pid_edit.text().strip()
        pid = int(pid_text) if pid_text else None
        settings = {
            "pid": pid,
            "process": self.process_edit.text().strip() or "Crimson Desert",
            "window_titles": split_values(self.window_title_edit.text()),
            "window_filter_patterns": split_values(self.window_filter_edit.text()),
            "pick_window": False,
            "list_windows": False,
            "mode": self.mode_combo.currentText(),
            "hotkey": normalize_hotkey_name(self.hotkey_edit.text()),
            "interval": float(self.interval_spin.value()),
            "captures": self.captures_spin.value() or None,
            "output": self.output_edit.text().strip() or "logs/cdsniffer.jsonl",
            "timestamp_output": self.timestamp_check.isChecked(),
            "session_name": self.session_name_edit.text().strip() or "cdsniffer",
            "format": self.format_combo.currentText(),
            "label": self.label_edit.text().strip() or "capture",
            "game_version": self.game_version_edit.text().strip(),
            "capture_gate": self.capture_gate_combo.currentText(),
            "capture_gate_match": self.capture_gate_match_combo.currentText(),
            "unique_only": self.unique_only_check.isChecked(),
            "include_keywords": split_values(self.include_keywords_edit.toPlainText()),
            "exclude_keywords": split_values(self.exclude_keywords_edit.toPlainText()),
            "include_patterns": split_values(self.include_regex_edit.toPlainText()),
            "exclude_patterns": split_values(self.exclude_regex_edit.toPlainText()),
            "signature_packs": split_values(self.signature_pack_edit.toPlainText()),
            "max_region_size": int(self.max_region_size.value()),
            "max_regions": self.max_regions.value() or None,
            "max_hits_per_region": self.max_hits_per_region.value() or None,
            "context_bytes": int(self.context_bytes_spin.value()),
            "decode_context_numbers": self.decode_context_numbers_check.isChecked(),
            "context_number_radius": int(self.context_number_radius_spin.value()),
            "gate_keywords": split_values(self.gate_keywords_edit.toPlainText()),
            "gate_patterns": split_values(self.gate_regex_edit.toPlainText()),
            "gate_max_regions": self.gate_max_regions_spin.value() or None,
            "gate_max_hits_per_region": self.gate_max_hits_per_region_spin.value() or None,
            "summary": self.summary_combo.currentText(),
            "summary_limit": self.summary_limit_spin.value(),
            "compare_last": self.compare_check.isChecked(),
            "compare_limit": self.compare_limit_spin.value(),
            "export_manifest": self.export_manifest_check.isChecked(),
            "quiet": self.quiet_check.isChecked(),
            "verbose": self.verbose_check.isChecked(),
            "tray_enabled": self.tray_enabled_check.isChecked(),
            "tray_start_hidden": self.tray_start_hidden_check.isChecked(),
            "tray_minimize_to_tray": self.tray_minimize_to_tray_check.isChecked(),
            "tray_notifications": self.tray_notifications_check.isChecked(),
            "tray_click_behavior": self.tray_click_behavior_combo.currentText(),
            "tray_notify_game_detected": self.tray_notify_game_detected_check.isChecked(),
            "tray_notify_game_lost": self.tray_notify_game_lost_check.isChecked(),
            "tray_notify_capture_started": self.tray_notify_capture_started_check.isChecked(),
            "tray_notify_capture_stopped": self.tray_notify_capture_stopped_check.isChecked(),
            "tray_notify_relinked": self.tray_notify_relinked_check.isChecked(),
            "tray_notify_errors": self.tray_notify_errors_check.isChecked(),
            "tray_notify_capture_complete": self.tray_notify_capture_complete_check.isChecked(),
            "watch_patterns": split_values(self.watch_edit.toPlainText()),
            "notes": split_values(self.notes_edit.toPlainText()),
        }
        return argparse.Namespace(**settings)

    def refresh_windows(self) -> None:
        try:
            args = self.build_settings_namespace()
            matches = collect_matching_windows(args)
        except Exception as exc:
            QMessageBox.warning(self, "Window Scan Failed", str(exc))
            return
        if matches:
            if len(matches) == 1:
                hwnd, pid, title = matches[0]
                self.window_status.setText(f"Found Crimson Desert window PID {pid} (0x{hwnd:08X}): {title}")
            else:
                self.window_status.setText(f"Found {len(matches)} matching window(s).")
        else:
            self.window_status.setText("No matching windows found.")
        self.refresh_target_indicator()

    def pick_window(self) -> None:
        try:
            args = self.build_settings_namespace()
            matches = collect_matching_windows(args)
        except Exception as exc:
            QMessageBox.warning(self, "Window Scan Failed", str(exc))
            return
        if not matches:
            QMessageBox.information(self, "No Windows", "No matching windows were found.")
            return
        dialog = WindowPickerDialog(self, matches)
        if dialog.exec() == QDialog.Accepted:
            pid = dialog.selected_pid()
            if pid is not None:
                self.pid_edit.setText(str(pid))
                self.window_status.setText(f"Selected PID {pid}.")
                self.refresh_target_indicator()

    def append_log(self, message: str) -> None:
        verbosity = verbosity_mode(self.quiet_check.isChecked(), self.verbose_check.isChecked())
        if verbosity == "quiet" and not message.lower().startswith(("error", "failed", "stop", "capture limit", "watch hit")):
            return
        if verbosity == "normal" and message.startswith("Compare-last:"):
            return
        self.log_view.appendPlainText(message)

    def set_running(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.capture_tab.setEnabled(not running)
        self.window_status.setText("Capture running..." if running else "Idle.")
        self.refresh_target_indicator()
        self.update_tray_status("CDSniffer: capturing" if running else "CDSniffer: idle")
        self.notify_tray("capture_started" if running else "capture_stopped", "CDSniffer", "Capture started." if running else "Capture stopped.")
        self.log_action("capture.running", running=running)

    def start_capture(self) -> None:
        if self.worker is not None:
            self.append_log("Capture is already running.")
            return
        try:
            args = self.build_settings_namespace()
            if args.context_bytes < 0:
                raise ValueError("context_bytes cannot be negative")
            if args.context_number_radius < 0:
                raise ValueError("context_number_radius cannot be negative")
            validate_regex_patterns(args.include_patterns, "--include-regex")
            validate_regex_patterns(args.exclude_patterns, "--exclude-regex")
            validate_regex_patterns(args.window_filter_patterns, "--window-filter-regex")
            validate_regex_patterns(args.watch_patterns, "--watch-pattern")
            validate_regex_patterns(args.gate_patterns, "--gate-regex")
            if args.signature_packs:
                for pack in args.signature_packs:
                    if not Path(pack).exists():
                        raise FileNotFoundError(f"Signature pack not found: {pack}")
        except Exception as exc:
            self.show_error_summary("Invalid Settings", str(exc), details=traceback.format_exc())
            QMessageBox.warning(self, "Invalid Settings", str(exc))
            return

        if args.pid is None:
            QMessageBox.warning(self, "Missing PID", "Select a PID or use Pick Window first.")
            return

        self.set_running(True)
        self.log_action("capture.start", mode=args.mode, pid=args.pid, process=args.process, hotkey=args.hotkey)
        self.worker_thread = QThread(self)
        self.worker = CaptureWorker(vars(args))
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.captured.connect(self.on_capture)
        self.worker.status.connect(self.on_status)
        self.worker.error.connect(self.on_error)
        self.worker.finished.connect(self.on_finished)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)
        self.worker_thread.start()

    def stop_capture(self) -> None:
        if self.worker:
            self.log_action("capture.stop", requested=True)
            self.worker.stop()
        else:
            self.log_action("capture.stop", requested=False)

    @Slot(dict)
    def on_capture(self, payload: dict[str, Any]) -> None:
        self.last_payload = payload
        self.last_capture_at = datetime.fromisoformat(str(payload.get("timestamp"))) if payload.get("timestamp") else datetime.now(timezone.utc)
        self.last_capture_duration_ms = float(payload.get("capture_duration_ms", 0.0) or 0.0)
        self.update_live_view(payload)
        self.update_freshness_view()
        self.append_log(
            f"Captured {payload.get('hit_count', 0)} hits from {payload.get('region_count', 0)} regions."
        )

    @Slot(str)
    def on_status(self, message: str) -> None:
        self.status_label.setText(message)
        self.append_log(message)
        relink_match = re.search(r"Re-linked to PID (\d+)", message, re.IGNORECASE)
        if relink_match:
            self.pid_edit.setText(relink_match.group(1))
            self.refresh_target_indicator()
            self.notify_tray("relinked", "CDSniffer", f"Re-linked to PID {relink_match.group(1)}.")
        elif "game not running" in message.lower() or "attached to pid" in message.lower():
            self.refresh_target_indicator()
        if "capture complete" in message.lower():
            self.notify_tray("capture_complete", "CDSniffer", "Capture complete.")

    @Slot(str)
    def on_error(self, message: str) -> None:
        self.show_error_summary("Capture Error", message)
        self.notify_tray("errors", "CDSniffer Error", message)
        QMessageBox.critical(self, "Capture Error", message)

    @Slot()
    def on_finished(self) -> None:
        self.set_running(False)
        self.worker = None
        self.worker_thread = None
        self.refresh_target_indicator()

    def ipc_state_snapshot(self) -> dict[str, Any]:
        return {
            "running": self.worker is not None,
            "current_tab": self.tabs.tabText(self.tabs.currentIndex()),
            "settings": self.collect_settings_dict(),
            "last_payload": self.last_payload or {},
        }

    def process_ipc_commands(self) -> None:
        while True:
            try:
                command = self.ipc_command_queue.get_nowait()
            except queue.Empty:
                break
            if command.command == "start":
                self.start_capture()
            elif command.command == "stop":
                self.stop_capture()
            elif command.command == "show":
                self.showNormal()
                self.raise_()
                self.activateWindow()
            elif command.command == "hide":
                self.hide()
            elif command.command == "open-settings":
                self.open_settings_dialog()
            elif command.command == "refresh":
                self.refresh_windows()
            elif command.command == "select-tab":
                tab_name = str(command.payload.get("tab", "")).strip().lower()
                for index in range(self.tabs.count()):
                    if self.tabs.tabText(index).lower() == tab_name:
                        self.tabs.setCurrentIndex(index)
                        break
            elif command.command == "apply-settings":
                settings = dict(command.payload.get("settings") or {})
                if settings:
                    self.apply_settings_dict(settings)
                    self.log_action("settings.apply", source="cli")
            else:
                self.append_log(f"Unknown IPC command: {command.command}")

    def execute_terminal_command(self, line: str) -> str:
        try:
            parts = [part.strip('"') for part in shlex.split(line, posix=False)]
        except ValueError as exc:
            return f"Invalid command: {exc}"
        if not parts:
            return ""
        command = parts[0].lower()
        if command in {"help", "?"}:
            return (
                "Commands: help, status, start, stop, settings, show, hide, tab <name>, "
                "search <query>, search-clear, search-export [path], search-import [path], "
                "archive-index <archive-root> <index-db> [glob...], "
                "correlate <capture> <root> [json|csv|markdown], "
                "correlate-file <capture> <decoded-file> [json|csv|markdown], "
                "correlate-diff <baseline> <target> <root> [json|csv|markdown], "
                "correlate-archive <capture> <index-db> <cache-dir> [json|csv|markdown] [glob...], "
                "apply <json>, refresh"
            )
        if command == "status":
            state = self.ipc_state_snapshot()
            return json.dumps(state, ensure_ascii=False, indent=2)
        if command == "start":
            self.start_capture()
            return "Capture requested."
        if command == "stop":
            self.stop_capture()
            return "Stop requested."
        if command == "settings":
            self.open_settings_dialog()
            return "Settings dialog opened."
        if command == "show":
            self.showNormal()
            self.raise_()
            self.activateWindow()
            return "Window shown."
        if command == "hide":
            self.hide()
            return "Window hidden."
        if command == "refresh":
            self.refresh_windows()
            return "Window list refreshed."
        if command == "search":
            query = line.partition(" ")[2].strip()
            self.live_search_edit.setText(query)
            self.tabs.setCurrentWidget(self.live_tab)
            self.apply_live_search_filter()
            self.commit_live_search()
            return f"Search applied: {query or 'cleared'}."
        if command == "search-clear":
            self.live_search_edit.clear()
            self.tabs.setCurrentWidget(self.live_tab)
            self.apply_live_search_filter()
            return "Search cleared."
        if command == "search-export":
            if len(parts) > 1:
                target = Path(" ".join(parts[1:]).strip())
                try:
                    payload = {"history": self.search_history[:25], "saved": self.saved_searches}
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                    return f"Search state exported to {target}."
                except Exception as exc:
                    return f"Export failed: {exc}"
            self.save_search_state()
            return f"Search state exported to {self.search_state_path()}."
        if command == "search-import":
            source = Path(" ".join(parts[1:]).strip()) if len(parts) > 1 else self.search_state_path()
            if not source.exists():
                return f"Search state not found: {source}"
            try:
                data = json.loads(source.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    return "Search state JSON must be an object."
                history = data.get("history", [])
                saved = data.get("saved", [])
                self.search_history = [str(item).strip() for item in history if str(item).strip()] if isinstance(history, list) else []
                self.saved_searches = [dict(item) for item in saved if isinstance(item, dict) and str(item.get("name", "")).strip()] if isinstance(saved, list) else []
                self.save_search_state()
                self.refresh_search_history()
                self.refresh_saved_searches()
                return f"Search state imported from {source}."
            except Exception as exc:
                return f"Import failed: {exc}"
        if command == "archive-index":
            if len(parts) < 3:
                return "Usage: archive-index <archive-root> <index-db> [glob...]"
            archive_root = Path(parts[1])
            index_db = Path(parts[2])
            patterns = parts[3:] or None
            if not archive_root.exists():
                return f"Archive root not found: {archive_root}"
            try:
                result = build_archive_index(index_db, [archive_root], patterns=patterns)
                return render_archive_index_markdown(result)
            except Exception as exc:
                return f"Archive index failed: {exc}"
        if command == "correlate":
            if len(parts) < 3:
                return "Usage: correlate <capture.jsonl> <unpacked-root> [json|csv|markdown]"
            capture_path = Path(parts[1])
            root_path = Path(parts[2])
            output_format = parts[3].lower() if len(parts) > 3 else "markdown"
            if output_format not in {"json", "csv", "markdown"}:
                return "Correlation format must be json, csv, or markdown."
            if not capture_path.exists():
                return f"Capture file not found: {capture_path}"
            if not root_path.exists() or not root_path.is_dir():
                return f"Correlation root not found: {root_path}"
            try:
                result = correlate_capture_to_files(
                    capture_path,
                    root_path,
                    max_total_matches=50,
                    max_matches_per_evidence=10,
                )
                if output_format == "json":
                    return json.dumps(result, ensure_ascii=False, indent=2)
                if output_format == "csv":
                    return render_correlation_csv(result)
                return render_correlation_markdown(result)
            except Exception as exc:
                return f"Correlation failed: {exc}"
        if command == "correlate-file":
            if len(parts) < 3:
                return "Usage: correlate-file <capture.jsonl> <decoded-file> [json|csv|markdown]"
            capture_path = Path(parts[1])
            selected_file = Path(parts[2])
            output_format = parts[3].lower() if len(parts) > 3 else "markdown"
            if output_format not in {"json", "csv", "markdown"}:
                return "Correlation format must be json, csv, or markdown."
            if not capture_path.exists():
                return f"Capture file not found: {capture_path}"
            if not selected_file.exists() or not selected_file.is_file():
                return f"Decoded/unpacked file not found: {selected_file}"
            try:
                result = correlate_capture_to_files(
                    capture_path,
                    selected_file.parent,
                    selected_files=[selected_file],
                    max_total_matches=50,
                    max_matches_per_evidence=10,
                )
                if output_format == "json":
                    return json.dumps(result, ensure_ascii=False, indent=2)
                if output_format == "csv":
                    return render_correlation_csv(result)
                return render_correlation_markdown(result)
            except Exception as exc:
                return f"File correlation failed: {exc}"
        if command == "correlate-archive":
            if len(parts) < 4:
                return "Usage: correlate-archive <capture.jsonl> <index-db> <cache-dir> [json|csv|markdown] [glob...]"
            capture_path = Path(parts[1])
            index_db = Path(parts[2])
            cache_dir = Path(parts[3])
            output_format = "markdown"
            pattern_start = 4
            if len(parts) > 4 and parts[4].lower() in {"json", "csv", "markdown"}:
                output_format = parts[4].lower()
                pattern_start = 5
            patterns = parts[pattern_start:] or None
            if not capture_path.exists():
                return f"Capture file not found: {capture_path}"
            if not index_db.exists():
                return f"Archive index not found: {index_db}"
            try:
                result = correlate_capture_to_archive(
                    capture_path,
                    index_db,
                    cache_dir,
                    patterns=patterns,
                    max_entries=1000,
                    max_total_matches=50,
                    max_matches_per_evidence=10,
                )
                if output_format == "json":
                    return json.dumps(result, ensure_ascii=False, indent=2)
                if output_format == "csv":
                    return render_archive_correlation_csv(result)
                return render_archive_correlation_markdown(result)
            except Exception as exc:
                return f"Archive correlation failed: {exc}"
        if command == "correlate-diff":
            if len(parts) < 4:
                return "Usage: correlate-diff <baseline.jsonl> <target.jsonl> <unpacked-root> [json|csv|markdown]"
            baseline_path = Path(parts[1])
            target_path = Path(parts[2])
            root_path = Path(parts[3])
            output_format = parts[4].lower() if len(parts) > 4 else "markdown"
            if output_format not in {"json", "csv", "markdown"}:
                return "Correlation format must be json, csv, or markdown."
            if not baseline_path.exists():
                return f"Baseline capture file not found: {baseline_path}"
            if not target_path.exists():
                return f"Target capture file not found: {target_path}"
            if not root_path.exists() or not root_path.is_dir():
                return f"Correlation root not found: {root_path}"
            try:
                result = correlate_capture_to_files(
                    target_path,
                    root_path,
                    baseline_capture_path=baseline_path,
                    max_total_matches=50,
                    max_matches_per_evidence=10,
                )
                if output_format == "json":
                    return json.dumps(result, ensure_ascii=False, indent=2)
                if output_format == "csv":
                    return render_correlation_csv(result)
                return render_correlation_markdown(result)
            except Exception as exc:
                return f"Correlation failed: {exc}"
        if command == "tab" and len(parts) > 1:
            tab_name = " ".join(parts[1:]).strip()
            for index in range(self.tabs.count()):
                if self.tabs.tabText(index).lower() == tab_name.lower():
                    self.tabs.setCurrentIndex(index)
                    return f"Switched to {tab_name}."
            return f"Unknown tab: {tab_name}"
        if command == "apply" and len(parts) > 1:
            raw_json = line.partition(" ")[2].strip()
            try:
                settings = json.loads(raw_json)
            except json.JSONDecodeError as exc:
                return f"Invalid JSON: {exc}"
            if isinstance(settings, dict):
                self.apply_settings_dict(settings)
                return "Settings applied."
            return "Settings JSON must be an object."
        return f"Unknown command: {command}"

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self.archive_task_worker is not None:
            event.ignore()
            QMessageBox.information(self, "Archive Task Running", "Wait for the current archive task to finish before closing CDSniffer.")
            return
        if (
            not self._force_close
            and self.tray_minimize_to_tray_check.isChecked()
            and getattr(self, "tray_icon", None)
            and self.tray_icon.isVisible()
        ):
            event.ignore()
            self.hide()
            self.update_tray_status("CDSniffer: hidden to tray")
            return
        try:
            if self.worker:
                self.worker.stop()
            if getattr(self, "ipc_server", None):
                self.ipc_server.stop()
            if getattr(self, "tray_icon", None):
                self.tray_icon.hide()
        finally:
            super().closeEvent(event)

    def update_live_view(self, payload: dict[str, Any]) -> None:
        self.last_payload = payload
        self.stats_label.setText(
            f"Regions: {payload.get('region_count', 0)} | Hits: {payload.get('hit_count', 0)} | Unique: {payload.get('unique_hit_count', 0)}"
        )
        watch_hits = payload.get("watch_hits", [])
        self.watch_label.setText(", ".join(watch_hits) if watch_hits else "No watch hits.")
        comparison = payload.get("comparison")
        if comparison:
            self.comparison_label.setText(
                f"+{comparison.get('added_count', 0)} / -{comparison.get('removed_count', 0)}"
            )
        else:
            self.comparison_label.setText("No comparison available yet.")
        self.apply_live_search_filter()


def main() -> int:
    if _GUI_IMPORT_ERROR is not None:
        print(
            "PySide6 is required for the GUI. Install it with: pip install .[gui]\n"
            f"Import error: {_GUI_IMPORT_ERROR}"
        )
        return 1
    app = QApplication([])
    apply_modern_theme(app)
    app.setWindowIcon(load_app_icon())
    window = MainWindow()
    window.show()
    if window.tray_enabled_check.isChecked() and window.tray_start_hidden_check.isChecked():
        window.hide()
        window.update_tray_status("CDSniffer: hidden to tray")
    return app.exec()
