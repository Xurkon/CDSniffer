# Changelog

## Unreleased

- Added module and region provenance to captures, including module name/path/base, region protection/type, region offsets, and module-relative RVA
- Added optional hit byte context capture with `--context-bytes`
- Added optional nearby integer candidate decoding with `--decode-context-numbers` and `--context-number-radius`
- Added capture gates so CLI and GUI sessions can wait for camp mission UI sentinel strings before writing snapshots
- Added custom gate keywords/regex, any/all gate matching, and separate gate scan limits
- Added `--unique-only` plus GUI setting support to skip repeated hit text values during a session
- Fixed memory hit addresses so captures report the exact string address instead of the region base address
- Unified CLI and GUI PID resolution through the shared core resolver
- Clarified search result rows by making `snapshot_index` refer to the matched snapshot
- Refreshed README tab list, roadmap, and dependency wording
- Added capture search support to the CLI with file search, regex matching, case sensitivity, and result limits
- Added folder-wide capture search support to the CLI
- Added CLI search result export in JSON, CSV, and Markdown formats
- Added shared search helpers so the CLI and GUI use the same matching logic
- Added a live search panel to the GUI `Real-Time` tab that filters the current capture view in place
- Added live raw-view match highlighting for GUI search results
- Added recent-search history and named saved searches to the GUI
- Added GUI import/export for search history and saved searches
- Added a toggle for filtering the top-hit table to only matching rows
- Added a dedicated Search tab with folder-wide result table filtering
- Added terminal commands to export and import search presets without file dialogs
- Added terminal commands in the GUI for `search <query>` and `search-clear`
- Split the shared scan/export helpers into `cd_sniffer.core` so the CLI and GUI share one implementation surface
- Added a PySide6-based GUI with its own `cdsniffer-gui` entry point
- Added a real-time capture tab that updates as snapshots arrive
- Added a terminal tab inside the GUI for CLI-style commands
- Added a dedicated settings dialog for the full configuration set
- Added a visible game-detection indicator in the GUI capture dashboard
- Added hotkey visibility in the GUI summary and preserved configurable CLI hotkey support
- Added tray icon controls for show/hide, start/stop, settings, and exit
- Added a custom shared icon asset for the app and tray
- Added tray behavior controls to the settings dialog
- Added event-specific tray notification toggles
- Added settings profile import/export in the GUI
- Added a named preset manager tab for reusable profiles
- Added a compact status bar with icon, PID, and capture age
- Added a live freshness panel with last-capture age and duration
- Added automatic PID relinking when the game restarts
- Added localhost IPC so the CLI can control the GUI window
- Added GUI launch and command flags to the CLI
- Converted the main GUI tab into a dashboard while moving editable settings into the settings dialog
- Added verbosity controls in both CLI and GUI workflows
- Added timestamped session logs, manifests, compare-last, watch alerts, and shared signature packs
- Added CSV and Markdown export paths for community sharing
- Added JSON schema output for snapshot interchange

## 0.1.0

- Initial CLI-based Windows memory scanner for Crimson Desert research
- Memory scanning for readable regions with ASCII and UTF-16LE extraction
- Keyword filtering, regex filtering, window targeting, and hotkey capture modes
