from __future__ import annotations

import os
import unittest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


try:
    from PySide6.QtWidgets import QApplication

    from cd_sniffer.gui import MainWindow, SettingsDialog
except Exception as exc:  # pragma: no cover - depends on optional GUI extra
    QApplication = None  # type: ignore[assignment]
    MainWindow = None  # type: ignore[assignment]
    SettingsDialog = None  # type: ignore[assignment]
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


if __name__ == "__main__":
    unittest.main()
