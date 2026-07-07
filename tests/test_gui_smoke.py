from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


try:
    from PySide6.QtCore import QEvent, Qt
    from PySide6.QtGui import QKeyEvent
    from PySide6.QtWidgets import QApplication

    from cd_sniffer.gui import HotkeyLineEdit, MainWindow, SettingsDialog
except Exception as exc:  # pragma: no cover - depends on optional GUI extra
    QApplication = None  # type: ignore[assignment]
    MainWindow = None  # type: ignore[assignment]
    SettingsDialog = None  # type: ignore[assignment]
    HotkeyLineEdit = None  # type: ignore[assignment]
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


if __name__ == "__main__":
    unittest.main()
