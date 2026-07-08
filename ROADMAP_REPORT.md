# CDSniffer Roadmap Report

**Prepared for:** future agents and maintainers  
**Project:** CDSniffer  
**Purpose:** give a current-state snapshot plus a practical development roadmap so work can continue without re-learning the project from scratch.

## 1. Project Snapshot

CDSniffer is a Windows-only Crimson Desert research tool that captures runtime memory strings, correlates captures back to unpacked game files, and produces DMM-friendly patch drafts.

The codebase is currently in a strong usable state:

- CLI and GUI both work from the same shared core.
- GUI state and defaults are aligned with CLI defaults.
- Capture, live search, archive indexing, archive correlation, and DMM export flows are implemented.
- Archive extraction and correlation can operate without an external unpacker.
- The latest test suite run passed: `73` tests.

## 2. Current State Of The App

### 2.1 What already works

Capture and runtime analysis:

- Attach to Crimson Desert by PID or process name.
- Optionally locate a target window when auto-detection is ambiguous.
- Capture ASCII and UTF-16LE strings from readable memory regions.
- Use capture gates to wait for UI sentinel strings before capturing.
- Capture byte context around hits.
- Decode nearby integer candidates from captured byte context.
- Filter and deduplicate hits with keywords, regex, and unique-only capture mode.
- Compare baseline and target captures.
- Roll up repeat target captures for stronger confidence.

GUI:

- Modern Qt dashboard with Capture, Real-Time, Search, Archives, Terminal, Logs, and Presets tabs.
- Live real-time search against the current capture.
- Search history and saved searches.
- Folder-wide search for older capture logs.
- Settings profiles import/export.
- Tray icon and tray behavior controls.
- Hover tips on most controls.
- Live freshness/status indicators.
- Copyable error summaries and a rollback-friendly last-good settings snapshot.
- Automatic summary preview sync when controls change.
- Hotkey capture widget for keyboard input.

Archive and file correlation:

- Parse PAMT/PAZ archives.
- Decode encrypted XML and compressed entries.
- Build a reusable SQLite archive index.
- Correlate capture evidence against indexed archive entries.
- Correlate capture evidence against one unpacked/decoded file.
- Correlate capture evidence against a decoded folder tree.
- Extract a decoded cache file behind a selected archive match.
- Export DMM patch drafts and DMM conflict checks.
- Sample-pack decoder fallback for future unknown PAZ compression payloads.

Safety and validation:

- Fail fast on invalid hotkeys, paths, and imported settings.
- Archive preflight checks before correlation/extraction work runs.
- JSON schema validation gates.
- Offscreen GUI smoke tests.
- Full test suite currently passing.

### 2.2 Current architecture

Main modules:

- `cd_sniffer/core.py` - capture orchestration and shared logic
- `cd_sniffer/scanner.py` - memory scanning and hit extraction
- `cd_sniffer/paz_archive.py` - PAMT/PAZ parsing, extraction, and decode pipeline
- `cd_sniffer/archive_index.py` - archive indexing and archive-cache correlation
- `cd_sniffer/correlator.py` - capture-to-file evidence matching
- `cd_sniffer/format_analyzers.py` - text/JSON/PASEQ hints and heuristics
- `cd_sniffer/dmm.py` - DMM patch draft export and conflict checks
- `cd_sniffer/cli.py` - command-line entry point and dispatch
- `cd_sniffer/gui.py` - Qt GUI and embedded terminal commands
- `cd_sniffer/ipc.py` - localhost GUI IPC
- `cd_sniffer/windows.py` - Win32 helpers

### 2.3 Recent verified hardening work

Recent changes that are already in place and tested:

- GUI summary preview now updates automatically when relevant widgets change.
- GUI and CLI defaults match for shared capture fields.
- Imported settings profiles are validated before application.
- Settings import/export and hotkey normalization are covered by smoke tests.
- Archive workflow now preflights missing roots, missing files, and invalid inputs.
- Sample-pack decoder fallback can load exact-match compressed/decoded pairs from a manifest or folder.

## 3. Intended Feature Additions

This section is the actionable roadmap. The items are ordered roughly by value and dependency.

### 3.1 Release and packaging

Priority: High

Add a build/release script for:

- `cdsniffer.exe`
- `cdsniffer-gui.exe`

Why this matters:

- The project is already stable enough to ship, but users need a repeatable way to create release builds.
- Build automation will also make it easier to test optional extras and verify packaging on a clean machine.

Suggested deliverables:

- A Windows build script.
- Release artifact layout.
- Version stamping.
- Minimal smoke verification for both executables.

### 3.2 GUI IPC hardening

Status: Implemented July 8, 2026

The localhost GUI IPC channel now writes a per-session random token to the temp IPC state file, requires that token on every command, and refuses stale state files when the recorded GUI PID is no longer running.

Why this matters:

- The GUI already exposes localhost control commands.
- A token prevents accidental or unauthorized control by another local process.

Implemented deliverables:

- Token generation at GUI startup.
- Token validation for IPC clients.
- CLI support for passing the token automatically when controlling the GUI.
- Stale PID rejection before a CLI command connects to the recorded GUI socket.
- Documentation updates for startup and control commands.

### 3.3 GUI refactor into smaller widgets

Priority: Medium

Split `gui.py` into smaller files once the interface settles.

Why this matters:

- `gui.py` is now very large.
- The feature surface is useful, but maintenance becomes harder as new tools are added.

Suggested target structure:

- capture tab widget
- live search widget
- archive workflow widget
- presets widget
- logs/error widget
- terminal widget
- shared utility/helpers

### 3.4 Archive workflow improvements

Priority: Medium

Continue improving archive UX and file comparison workflows.

Recommended additions:

- Better file picker support for choosing a specific unpacked file from decoded data.
- Faster comparison flows between captures and selected unpacked files.
- Clearer cache management for decoded archive entries.
- More surface area for previewing decoded bytes and offsets before export.

Why this matters:

- The archive features are one of the strongest parts of the app, and they are central to getting exact offsets for DMM work.

### 3.5 Additional robustness around capture inputs

Priority: Medium

Expand fail-fast validation where it still helps:

- more path validation in GUI forms
- more field validation in import workflows
- better error messages for bad folder and file selections
- tighter validation around capture gate settings

Why this matters:

- The app is already good at runtime validation, but a little more front-loaded validation will reduce user confusion.

### 3.6 Better future decoder support

Priority: Low-Medium

The current sample-pack fallback is a good safety net, but future decoder support can be improved further.

Potential additions:

- More structured sample-pack manifest tooling.
- A small UI for loading and validating sample packs.
- Reporting for which sample pack decoded a given entry.
- Better diagnostics when a sample pack fails to match.

Why this matters:

- The current fallback is exact-match only.
- If future game updates introduce new payload types, a more guided sample workflow would help maintainers adapt faster.

## 4. Recommended Next Work Queue

If a future agent is picking up the project, the best sequence is:

1. Build/release script for the two executables.
2. DMM baseline/target auto-fill research for reviewed patch drafts.
3. GUI refactor plan and first extraction pass.
4. Archive workflow polish for selecting and comparing decoded files.
5. Extra validation polish for imported profiles and file/path workflows.
6. Sample-pack UI/tooling improvements if future decoder research needs them.

## 5. Open Technical Risks

- `gui.py` remains large and still carries maintenance risk.
- DMM patch drafts still require human-reviewed `patched` values unless the user supplies an explicit placeholder.
- Sample-pack decoding is intentionally conservative and will not magically decode unknown compression schemes without matched training samples.
- Some release mechanics are still manual because there is no build script yet.

## 6. Verification Baseline

Current known-good baseline:

- `python -m unittest discover -s tests`
- `python -m compileall -q cd_sniffer tests`
- `git diff --check`

Last verified result:

- `58` tests passed
- sample-pack fallback coverage added
- GUI summary sync and settings validation already verified

## 7. Notes For Future Agents

- Treat the README roadmap and this report as the authoritative backlog summary.
- Prefer incremental changes with tests over large UI refactors.
- Keep CLI and GUI defaults aligned whenever a new setting is added.
- When adding a new archive or decoder feature, make sure it flows through:
  - direct extraction
  - archive indexing/correlation
  - GUI workflows
  - tests
- If a task touches user-facing settings, update the hover tips and README examples at the same time.
