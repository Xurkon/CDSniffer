from __future__ import annotations

import json
import os
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


try:
    from PySide6.QtCore import QEvent, Qt
    from PySide6.QtGui import QKeyEvent
    from PySide6.QtWidgets import QApplication

    from cd_sniffer.cli import parse_args
    from cd_sniffer.gui import HotkeyLineEdit, MainWindow, SettingsDialog, require_path
except Exception as exc:  # pragma: no cover - depends on optional GUI extra
    QApplication = None  # type: ignore[assignment]
    MainWindow = None  # type: ignore[assignment]
    SettingsDialog = None  # type: ignore[assignment]
    HotkeyLineEdit = None  # type: ignore[assignment]
    require_path = None  # type: ignore[assignment]
    parse_args = None  # type: ignore[assignment]
    GUI_IMPORT_ERROR = exc
else:
    GUI_IMPORT_ERROR = None


@unittest.skipIf(GUI_IMPORT_ERROR is not None, f"PySide6 GUI unavailable: {GUI_IMPORT_ERROR}")
class GuiSmokeTests(unittest.TestCase):
    def test_main_window_instantiates_offscreen(self):
        app = QApplication.instance() or QApplication([])
        window = MainWindow()
        try:
            self.assertEqual(window.windowTitle(), "CDSniffer")
            self.assertEqual(window.tabs.count(), 7)
            tab_names = [window.tabs.tabText(index) for index in range(window.tabs.count())]
            self.assertEqual(tab_names, ["Capture", "Real-Time", "Search", "Archives", "Terminal", "Logs", "Presets"])
            self.assertEqual(window.status_label.text(), "Idle")
            self.assertIn("Game not detected", window.target_status.text())
            self.assertTrue(window.archive_extract_match_button.text())
            self.assertIn("Start capturing", window.start_button.toolTip())
            self.assertIn("selected decoded", window.archive_correlate_file_button.toolTip())
        finally:
            window.close()
            app.processEvents()

    def test_settings_dialog_has_setting_tooltips(self):
        app = QApplication.instance() or QApplication([])
        window = MainWindow()
        dialog = SettingsDialog(window, window.collect_settings_dict())
        try:
            self.assertIn("one snapshot", dialog.mode.toolTip())
            self.assertIn("Camp mission mode", dialog.capture_gate.toolTip())
            self.assertIn("nearby unsigned integer", dialog.decode_context_numbers.toolTip())
            self.assertIn("tray icon", dialog.tray_enabled.toolTip())
        finally:
            dialog.close()
            window.close()
            app.processEvents()

    def test_hotkey_line_edit_captures_and_clears_keys(self):
        app = QApplication.instance() or QApplication([])
        widget = HotkeyLineEdit("F8")
        try:
            widget.keyPressEvent(QKeyEvent(QEvent.KeyPress, Qt.Key_G, Qt.NoModifier, "g"))
            self.assertEqual(widget.text(), "G")
            widget.keyPressEvent(QKeyEvent(QEvent.KeyPress, Qt.Key_Backspace, Qt.NoModifier))
            self.assertEqual(widget.text(), "")
        finally:
            widget.close()
            app.processEvents()

    def test_settings_roundtrip_normalizes_and_rejects_invalid_hotkeys(self):
        app = QApplication.instance() or QApplication([])
        window = MainWindow()
        try:
            window.hotkey_edit.setText("g")
            collected = window.collect_settings_dict()
            self.assertEqual(collected["hotkey"], "G")

            original_hotkey = window.hotkey_edit.text()
            bad_settings = dict(collected)
            bad_settings["hotkey"] = "CTRL+G"
            with self.assertRaises(ValueError):
                window.apply_settings_dict(bad_settings)
            self.assertEqual(window.hotkey_edit.text(), original_hotkey)
        finally:
            window.close()
            app.processEvents()

    def test_imported_settings_profiles_validate_basic_ranges(self):
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as tmp_dir:
            profile_path = Path(tmp_dir) / "bad-profile.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "mode": "unsupported",
                        "hotkey": "F8",
                        "interval": -1,
                    }
                ),
                encoding="utf-8",
            )
            window = MainWindow()
            try:
                with self.assertRaises(ValueError):
                    window.load_settings_profile_from_path(profile_path)
            finally:
                window.close()
                app.processEvents()

    def test_settings_profile_export_and_import_roundtrip(self):
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as tmp_dir:
            export_path = Path(tmp_dir) / "profile.json"
            source = MainWindow()
            target = MainWindow()
            try:
                source.process_edit.setText("Crimson Desert")
                source.hotkey_edit.setText("g")
                source.mode_combo.setCurrentText("hotkey")
                source.unique_only_check.setChecked(True)
                source.tray_enabled_check.setChecked(False)
                source.output_edit.setText(str(Path(tmp_dir) / "captures" / "run.jsonl"))

                source.save_settings_profile_to_path(export_path)
                self.assertTrue(export_path.exists())

                exported = export_path.read_text(encoding="utf-8")
                self.assertIn('"hotkey": "G"', exported)
                self.assertIn('"mode": "hotkey"', exported)

                target.apply_settings_dict(
                    {
                        "process": "Other",
                        "hotkey": "F8",
                        "mode": "loop",
                        "unique_only": False,
                        "tray_enabled": True,
                        "output": "logs/other.jsonl",
                    }
                )
                target.load_settings_profile_from_path(export_path)

                self.assertEqual(target.process_edit.text(), "Crimson Desert")
                self.assertEqual(target.hotkey_edit.text(), "G")
                self.assertEqual(target.mode_combo.currentText(), "hotkey")
                self.assertTrue(target.unique_only_check.isChecked())
                self.assertFalse(target.tray_enabled_check.isChecked())
                self.assertEqual(target.output_edit.text(), str(Path(tmp_dir) / "captures" / "run.jsonl"))
            finally:
                source.close()
                target.close()
                app.processEvents()

    def test_cli_and_gui_default_settings_match_for_shared_fields(self):
        app = QApplication.instance() or QApplication([])
        window = MainWindow()
        try:
            with patch.object(sys, "argv", ["cdsniffer"]):
                cli_defaults = parse_args()
            gui_defaults = window.collect_settings_dict()
            shared_fields = [
                "process",
                "mode",
                "hotkey",
                "interval",
                "output",
                "timestamp_output",
                "session_name",
                "format",
                "label",
                "game_version",
                "capture_gate",
                "capture_gate_match",
                "unique_only",
                "max_region_size",
                "context_bytes",
                "context_number_radius",
                "gate_max_regions",
                "gate_max_hits_per_region",
                "summary",
                "summary_limit",
                "compare_last",
                "compare_limit",
                "export_manifest",
                "quiet",
                "verbose",
            ]
            for field in shared_fields:
                self.assertEqual(gui_defaults[field], getattr(cli_defaults, field if field != "process" else "process"))
        finally:
            window.close()
            app.processEvents()

    def test_capture_summary_updates_when_hotkey_changes(self):
        app = QApplication.instance() or QApplication([])
        window = MainWindow()
        try:
            window.hotkey_edit.setText("G")
            app.processEvents()
            self.assertIn("Hotkey: G", window.settings_preview.toPlainText())
        finally:
            window.close()
            app.processEvents()

    def test_require_path_validates_missing_and_existing_inputs(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            file_path = root / "capture.jsonl"
            file_path.write_text("{}", encoding="utf-8")
            self.assertEqual(require_path(str(file_path), "Capture file", kind="file"), file_path)
            self.assertEqual(require_path(str(root), "Archive root", kind="dir"), root)
            with self.assertRaises(FileNotFoundError):
                require_path(str(root / "missing.json"), "Capture file", kind="file")
            with self.assertRaises(ValueError):
                require_path(str(file_path), "Archive root", kind="dir")

    def test_archive_selected_file_preflight_blocks_missing_file(self):
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            capture_path = tmp / "capture.jsonl"
            capture_path.write_text("{}", encoding="utf-8")
            window = MainWindow()
            try:
                window.archive_capture_edit.setText(str(capture_path))
                window.archive_selected_file_edit.setText(str(tmp / "missing.paseq"))
                with patch("cd_sniffer.gui.QMessageBox.warning") as warning, patch.object(window, "start_archive_task") as start_task:
                    window.run_selected_file_correlation()
                start_task.assert_not_called()
                warning.assert_called_once()
                self.assertIn("Archive Preflight Failed", warning.call_args.args[1])
                self.assertIn("not found", warning.call_args.args[2])
            finally:
                window.close()
                app.processEvents()

    def test_error_summary_copies_to_clipboard(self):
        app = QApplication.instance() or QApplication([])
        window = MainWindow()
        try:
            window.show_error_summary("Test Error", "Something went wrong")
            payload = json.loads(QApplication.clipboard().text())
            self.assertEqual(payload["title"], "Test Error")
            self.assertEqual(payload["message"], "Something went wrong")
            self.assertIn("timestamp", payload)
        finally:
            window.close()
            app.processEvents()

    def test_last_good_settings_snapshot_can_be_restored(self):
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_home = Path(tmp_dir)
            with patch("cd_sniffer.gui.Path.home", return_value=fake_home):
                window = MainWindow()
                try:
                    original = dict(window.collect_settings_dict())
                    original["hotkey"] = "G"
                    original["mode"] = "hotkey"
                    original["unique_only"] = True
                    window.apply_settings_dict(original)
                    snapshot_path = fake_home / ".cdsniffer" / "last-good-settings.json"
                    self.assertTrue(snapshot_path.exists())

                    window.hotkey_edit.setText("F8")
                    window.mode_combo.setCurrentText("loop")
                    window.unique_only_check.setChecked(False)
                    window.restore_last_good_settings_snapshot()

                    self.assertEqual(window.hotkey_edit.text(), "G")
                    self.assertEqual(window.mode_combo.currentText(), "hotkey")
                    self.assertTrue(window.unique_only_check.isChecked())
                finally:
                    window.close()
                    app.processEvents()


if __name__ == "__main__":
    unittest.main()
