# CDSniffer

CDSniffer is a local Windows memory scanner for Crimson Desert research.

It is designed to help capture the exact mission and camp identifiers the game loads at runtime so we can build a precise whitelist for DMM mods.

The codebase is split into a shared `cd_sniffer.core` layer plus thin CLI and GUI entry points, so both executables stay consistent while still serving different workflows.

There are two entry points:

- `cdsniffer` for the CLI
- `cdsniffer-gui` for the modern Qt GUI

The CLI can also control a running GUI through localhost IPC commands.

For compiled releases, the clean target is two executables:

- `cdsniffer.exe` for headless / automation use
- `cdsniffer-gui.exe` for the dashboard and terminal UI

## What it does

- Attaches to a running Crimson Desert process by name or PID
- Can locate the target by window title fragment when the process name is ambiguous
- Scans readable memory regions for ASCII and UTF-16LE strings
- Filters hits by mission-related keywords and optional regex patterns
- Records region provenance, module metadata, and module-relative RVA when available
- Can capture byte context around each hit for nearby hex/ID analysis
- Can decode nearby integer candidates from captured byte context
- Can correlate captured strings, hit bytes, and numeric candidates back to unpacked file offsets
- Groups duplicate evidence at the same file offset so one candidate carries its full evidence trail
- Can compare baseline and target captures to highlight target-only file-offset candidates
- Adds format-aware correlation hints for JSON/JSONL records, text line locations, PASEQ candidates, nearby strings, and little-endian integers
- Can parse PAMT indexes and extract/validate/decode PAZ archive entries without launching an external unpacker
- Can gate captures until camp mission UI sentinel strings are present in memory
- Can write only new unique hit text values during a capture session
- Searches captured payloads from the CLI and the GUI
- Lets the GUI live view search the current real-time capture without changing the underlying snapshot
- Lets the GUI keep a searchable recent-history list and named saved searches
- Lets the GUI optionally filter the top-hit table to only matching rows
- Lets the GUI export and import search history plus saved searches
- Adds a dedicated `Search` tab for folder-wide capture searches with a filterable results table
- Writes JSONL logs for later comparison with unpacked game tables
- Supports one-shot, looped, and hotkey-triggered captures
- Produces a JSON schema-compatible output shape with top-hit summaries
- Can auto-stamp each session output file with a UTC timestamp
- Can export session manifests for sharing exact settings
- Shows a clear game-detected status in the GUI
- Includes a tray icon for quick show/hide/start/stop control
- Uses a custom shared app/tray icon
- Lets users configure tray behavior in settings
- Lets users pick exactly which tray events should notify
- Supports importing and exporting GUI settings profiles
- Shows a live freshness panel with capture age and duration
- Can automatically relink if the game restarts and gets a new PID
- Includes a named preset manager for reusable profiles
- Shows a compact status bar with icon, PID, and capture age
- Can compare each capture against the previous one
- Supports CSV and Markdown exports for community sharing
- Can load shared signature packs from text or JSON files
- Can watch for specific mission families and print alerts
- Can store operator notes in the session metadata

## What it does not do

- It does not inject code
- It does not modify the game process
- It does not edit save files or game files

## Usage

```powershell
python -m cd_sniffer --process "Crimson Desert.exe" --interval 2.0 --output logs\cdsniffer.jsonl
```

You can also point it at a PID:

```powershell
python -m cd_sniffer --pid 12345
```

GUI launcher:

```powershell
cdsniffer-gui
```

Launch the GUI from the CLI:

```powershell
python -m cd_sniffer --gui
```

Send a command to a running GUI:

```powershell
python -m cd_sniffer --gui-command status
python -m cd_sniffer --gui-command open-settings
python -m cd_sniffer --gui-command select-tab --gui-tab "Real-Time"
python -m cd_sniffer --gui-command apply-settings --gui-settings-file .\settings.json
```

Install the GUI extra if needed:

```powershell
pip install .[gui]
```

Install archive decode extras if you need encrypted XML or LZ4 entries:

```powershell
pip install .[unpack]
```

To find the right window first:

```powershell
python -m cd_sniffer --list-windows --window-title "Crimson Desert"
```

Useful capture modes:

```powershell
python -m cd_sniffer --mode once --pid 12345
python -m cd_sniffer --mode loop --interval 1.0 --captures 10
python -m cd_sniffer --mode hotkey --hotkey F8 --captures 5
```

Recommended camp mission capture:

```powershell
python -m cd_sniffer --mode loop --window-title "Crimson Desert" --capture-gate camp-mission --unique-only --context-bytes 64 --decode-context-numbers --summary top-hits --timestamp-output --output logs\camp-mission.jsonl
```

Timestamped session logs:

```powershell
python -m cd_sniffer --mode hotkey --timestamp-output --session-name cdmission --output logs\cdsniffer.jsonl
```

Useful filters and safety limits:

- `--include-keyword` adds a keyword to the built-in mission/camp whitelist
- `--exclude-keyword` removes noisy strings
- `--include-regex` matches a string by regex instead of literal keyword
- `--exclude-regex` filters out regex matches
- `--max-region-size` skips very large memory regions
- `--max-regions` stops after a fixed number of matching regions
- `--max-hits-per-region` keeps huge pages from flooding the log
- `--context-bytes` stores bytes before and after each hit
- `--decode-context-numbers` decodes nearby unsigned integer candidates from the byte context
- `--context-number-radius` controls how far from each hit numeric decoding scans
- `--capture-gate camp-mission` only captures when camp/dispatch UI sentinel strings are found
- `--capture-gate custom` uses only your `--gate-keyword` and `--gate-regex` sentinels
- `--capture-gate-match any|all` controls whether one or every gate sentinel must match
- `--gate-max-regions` and `--gate-max-hits-per-region` keep the gate pre-scan cheap
- `--unique-only` skips repeated hit text values already captured during the same session
- `--summary top-hits` prints the most frequent strings after each capture
- `--pick-window` prompts you to choose a target window if auto-detection misses
- `--timestamp-output` creates a fresh log file per session
- `--session-name` controls the filename prefix used for timestamped logs
- `--export-manifest` writes a sidecar JSON manifest with the exact CLI settings
- `--compare-last` compares the current snapshot against the previous snapshot
- `--quiet` reduces console output
- `--verbose` prints extra diagnostics
- `--game-version` stores the game version in the capture metadata
- `--signature-pack` loads extra keyword or regex filters from a file
- `--watch-pattern` alerts when a target regex appears in the capture
- `--note` stores a freeform note with the session metadata

Search existing captures:

```powershell
python -m cd_sniffer --search "DeepForestBeacon" --search-file logs\cdsniffer.jsonl
python -m cd_sniffer --search "Mission_.*Camp" --search-regex --search-file logs\cdsniffer.jsonl
python -m cd_sniffer --search "Mission_" --search-dir logs --search-recursive
python -m cd_sniffer --search "Mission_" --search-dir logs --search-format csv --search-output logs\search-results.csv
python -m cd_sniffer --search "Mission_" --search-dir logs --search-format markdown --search-output logs\search-results.md
```

List game archive contents with the built-in PAMT parser:

```powershell
python -m cd_sniffer --archive-list --archive-root "C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert" --archive-filter "*mission*" --archive-limit 200 --archive-format markdown --archive-report-output logs\archive-mission-index.md
```

Extract and decode matching PAZ entries:

```powershell
python -m cd_sniffer --archive-extract --archive-root "C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert" --archive-filter "*mission*.xml" --archive-output D:\Documents\CrimsonDesertMods\decoded --archive-format json --archive-report-output logs\archive-extract.json
```

Validate decode coverage without writing extracted files:

```powershell
python -m cd_sniffer --archive-extract --archive-validate --archive-root "C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert" --archive-filter "*.paseq" --archive-limit 500 --archive-format json --archive-report-output logs\archive-validate-paseq.json
```

Useful archive options:

- `--archive-root` points to the game root, an archive folder, or a specific `.pamt` file and can be repeated
- `--archive-paz-dir` points to the matching `.paz` directory when listing a standalone `.pamt`
- `--archive-list` parses PAMT indexes and reports archive entries without extracting
- `--archive-extract` extracts matching entries to `--archive-output`
- `--archive-filter` filters by entry path glob or substring and can be repeated
- `--archive-limit` caps list or extract operations
- `--archive-all` is required when extracting everything without a filter or limit
- `--archive-no-decrypt` extracts encrypted XML bytes without decrypting
- `--archive-dry-run` previews extraction without writing decoded files
- `--archive-validate` reads, decrypts, and decodes entries without writing decoded files
- `--archive-format json|csv|markdown` controls report format
- `--archive-report-output` writes the archive report to a file

Archive decode notes:

- Compression type `0` is uncompressed pass-through.
- Compression type `1` is treated as raw asset storage. Current 1.13 game files use this for `.dds`, `.pam`, `.pamlod`, and `.pac` assets; many of those entries intentionally have a stored size smaller than the logical asset size while already beginning with valid asset headers like `DDS ` or `PAR `.
- Compression type `2` is LZ4 block data and needs `pip install .[unpack]`.
- Compression type `3` uses adaptive decoding: CDSniffer tries raw, zlib, and LZ4 paths and records the decoder that worked. The current tested 1.13 install did not contain type `3` entries, so genuinely proprietary future samples will be reported instead of guessed.
- Compression type `4` is zlib and uses the Python standard library.

Correlate a capture against unpacked files:

```powershell
python -m cd_sniffer --correlate-capture logs\camp-mission.jsonl --correlate-root D:\Documents\CrimsonDesertMods\unpacked --correlate-glob *.json --correlate-glob *.paseq --correlate-format markdown --correlate-output logs\correlation.md
```

Correlate a baseline/target pair against unpacked files:

```powershell
python -m cd_sniffer --correlate-baseline logs\before-camp-ui.jsonl --correlate-target logs\camp-ui-open.jsonl --correlate-root D:\Documents\CrimsonDesertMods\unpacked --correlate-glob *.json --correlate-glob *.paseq --correlate-format markdown --correlate-output logs\correlation-diff.md
```

Useful correlation options:

- `--correlate-capture` points to a CDSniffer JSON or JSONL capture
- `--correlate-target` is an explicit target-capture alias for diff workflows
- `--correlate-baseline` compares a before-state capture against the target capture
- `--correlate-root` points to the unpacked/game file tree to scan
- `--correlate-glob` limits scanned files by glob and can be repeated
- `--correlate-max-file-size` skips huge files
- `--correlate-max-matches` limits total results
- `--correlate-max-matches-per-evidence` limits repeated offsets for one evidence item
- `--correlate-context-bytes` includes surrounding file bytes in JSON output
- `--correlate-no-numeric` skips decoded numeric candidate bytes
- `--correlate-no-format-hints` skips JSON/text/binary analyzers for a faster raw-byte pass
- `--correlate-format json|csv|markdown` controls the report format
- `--correlate-output` writes the report to a file

Correlation results include:

- Matching file path and file offset
- Match type, such as text, hit bytes, or decoded numeric candidate bytes
- File format, such as `json`, `paseq`, `txt`, or `binary`
- Evidence count and evidence trail for grouped candidates
- Confidence reasons such as exact hit bytes, text-and-bytes, nearby numeric evidence, or target-only
- Format hints such as JSON record keys, text line/column, PASEQ candidate markers, nearby printable strings, and little-endian values
- Diff status when a baseline is provided: `target-only` or `shared-with-baseline`
- Original bytes at the file offset
- Runtime address and module-relative RVA when available
- Confidence score
- A generic byte patch skeleton with file, offset, original bytes, and empty replacement bytes

Search the live GUI capture:

- Use the search box on the `Real-Time` tab
- Toggle `Regex` when you want pattern matching instead of a literal string
- Toggle `Case sensitive` when you need exact casing
- Toggle `Filter top-hits table` when you want only the matching rows in the hit list
- Use the embedded terminal with `search <query>` or `search-clear`
- Use the embedded terminal with `search-export [path]` and `search-import [path]` to manage search presets
- Use the embedded terminal with `correlate <capture> <root> [json|csv|markdown]` to run a compact file-offset report
- Use the embedded terminal with `correlate-diff <baseline> <target> <root> [json|csv|markdown]` to compare before/after captures
- Matching text is highlighted directly in the live raw snapshot view
- Use the `Recent` dropdown to reuse previous searches
- Use the saved-search controls to store and restore named search presets
- Use the import/export buttons if you want to share search history with another machine
- Use the `Search` tab to search a folder of capture logs and filter the results table live

## Suggested workflow

1. Start the game
2. Open the camp or dispatch mission screen
3. Run CDSniffer
4. Compare the log output to the unpacked `questgaugeinfo`, `questinfo`, and `missioninfo` tables
5. Add only the confirmed camp families to the whitelist

## Best Capture Method

The most reliable way to get the exact data you want is:

1. Open only the one game screen you care about, such as a camp dispatch screen or a specific mission detail panel.
2. Use `--capture-gate camp-mission` so looped captures wait for camp mission UI labels instead of logging unrelated gameplay state.
3. Add `--unique-only` when looping so repeated strings are not written again and again.
4. Add `--context-bytes 64 --decode-context-numbers` when you need nearby IDs or original byte evidence.
5. Capture twice: once before the action you care about and once after the action appears.
6. Use `--summary top-hits` so you can see the dominant strings immediately after each capture.
7. Keep the capture window small with `--captures 1` or a short hotkey session so the log only contains the relevant state.
8. Use `--include-regex` to focus on families you already know, and `--exclude-regex` to filter noisy quest or story strings.
9. Use `--archive-list` to find likely mission/table entries inside the game PAZ/PAMT archives.
10. Use `--archive-extract --archive-validate` first to prove the focused subset can be read/decrypted/decoded without writing files.
11. Use `--archive-extract` to decode only the focused subset you need into a clean working folder.
12. Compare the resulting strings against decoded `questgaugeinfo`, `questinfo`, and `missioninfo` style tables and keep only the entries that consistently show up in the correct camp UI.
13. Run `--correlate-baseline` plus `--correlate-target` against the decoded file tree and inspect `target-only` rows first.
14. Prefer rows with format hints that point to JSON record keys, mission-like tables, PASEQ candidates, or nearby little-endian values.
15. Prefer module-relative `module_rva` over absolute `address` whenever it is available; absolute addresses can shift between launches.
16. If a string appears in multiple game systems, prefer the one that is unique to the camp/dispatch screen over one that also appears in player quests.

In practice, that means the best workflow is to:

- Open the target screen
- Run a single hotkey capture
- Read the top-hit summary
- Repeat on a different screen state
- Diff the two logs

That produces much better evidence than trying to infer the exact hex value first.

## GUI Layout

The GUI is split into these primary tabs:

- `Capture` for target selection, verbosity, filters, export settings, and session control
- `Real-Time` for the live top-hit table and the latest snapshot payload
- `Search` for folder-wide capture search with a filterable results table
- `Terminal` for CLI-style commands inside the app
- `Logs` for the rolling session log
- `Presets` for reusable capture settings

The GUI uses the same backend as the CLI, so captures, manifests, comparisons, and export formats all stay consistent between both entry points.

The GUI also includes:

- A dedicated settings dialog for the full configuration set
- IPC handling so the CLI can start, stop, show, hide, and retarget the GUI
- A read-only capture dashboard so the main tab stays clean
- A live search box on the `Real-Time` tab that filters the current capture in place

Suggested starting command:

```powershell
python -m cd_sniffer --mode hotkey --hotkey F8 --window-title "Crimson Desert" --captures 20 --context-bytes 64 --decode-context-numbers --summary top-hits --timestamp-output --output logs\cdsniffer.jsonl
```

## Near-Term Roadmap

Good next steps before opening this up more broadly:

- Add exact GUI smoke tests with the `PySide6` extra installed
- Add DMM-specific patch emitters on top of the generic correlation patch skeletons
- Expand format analyzers with deeper PASEQ, quest/mission table, hash, and typed record parsers
- Add sample-driven decoders for any future proprietary PAZ compression payloads that are not raw, zlib, or LZ4
- Add repeat-run confidence rollups across multiple target captures
- Add a build/release script for `cdsniffer.exe` and `cdsniffer-gui.exe`
- Add a random session token to the localhost GUI IPC channel
- Split the large GUI module into smaller files once the interface settles

## Notes

- This tool is Windows-only.
- CLI mode relies on standard library APIs only; GUI mode needs `PySide6`.
- The scanner is intentionally conservative and only looks at readable committed regions.
- Capture gates are memory-sentinel checks, not computer-vision screen cropping.
- If the camp gate misses a UI state, use `--capture-gate custom` with `--gate-keyword` or `--gate-regex` from a known visible label.
- If the process name lookup is unreliable, prefer `--window-title` or `--pid`.
- The JSON schema for capture output lives in `schemas/cdsniffer-output.schema.json`.
- The JSON schema for correlation output lives in `schemas/cdsniffer-correlation.schema.json`.
- The JSON schema for archive list/extract output lives in `schemas/cdsniffer-archive.schema.json`.
- The detailed project history lives in `CHANGELOG.md`.
- The GUI is optional and needs `pip install .[gui]`.
- Encrypted XML and LZ4 archive decoding need `pip install .[unpack]`; PAMT listing, raw pass-through, and zlib extraction use the standard library.
- The main GUI capture tab is intentionally a dashboard; all editable settings live in the settings dialog.
- Live search only filters the current snapshot view; it does not mutate the underlying capture payload.
