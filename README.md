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
- Can roll up repeated target captures to boost candidates that reappear across multiple runs
- Adds format-aware correlation hints for domain paths, mission/quest-like JSON records, text line locations, PASEQ timing/label candidates, nearby strings, hash candidates, and little-endian integers
- Can parse PAMT indexes and extract/validate/decode PAZ archive entries without launching an external unpacker
- Can build a reusable SQLite PAMT/PAZ archive index for fast repeated lookups after a game patch
- Can correlate captures directly against indexed archive entries with a lazy decoded-entry cache
- Can export the decoded cache file behind a selected archive correlation match from the GUI
- Provides a dedicated GUI `Archives` tab for building/searching archive indexes and viewing archive correlation matches
- Can optionally validate generated JSON payloads against bundled schemas before writing reports
- Can check generated DMM patch drafts against existing DMM mod JSON files for overlapping byte ranges
- Includes an offscreen PySide6 GUI smoke test for the main window/tab layout
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

## GUI Quick Start

Use the GUI when you want a guided workflow, live capture search, archive comparison, or one-click exports.

1. Start Crimson Desert.
2. Launch `cdsniffer-gui`.
3. Check the `Capture` tab status. It should show `Game Detected` in green when the game is found, or `Game not detected` if CDSniffer cannot see it yet. The GUI keeps polling, so a late-starting game should appear automatically once Windows exposes it.
4. Click `Refresh Window List` if you want to manually confirm the detected game PID or if auto-detection is ambiguous. It should no longer dump every visible window when no extra title filter is set.
5. Click `Settings`, then choose the capture behavior you want.
6. For camp mission research, start with `Mode: hotkey`, click the `Hotkey` field and press a key like `F8`, then set `Capture Gate: camp-mission`, `Unique only: on`, `Context Bytes: 64`, and `Decode context numbers: on`.
7. Open the game screen you want to study, press the hotkey, and inspect the `Real-Time` tab.
8. Use the `Real-Time` search box to search the current capture without changing the saved payload.
9. Use the `Search` tab to search older capture logs across a folder.
10. Use the `Archives` tab to build an archive index, search decoded game entries, correlate a capture against indexed archives, or compare a capture with one selected decoded file.
11. Select a correlation row to preview decoded bytes, printable context, evidence metadata, and a patch skeleton.
12. Export a DMM draft only after reviewing high-confidence matches, then run a DMM conflict check before using the patch.

Most GUI controls include short hover tips. Hover any setting or action button when you need a quick reminder of what it changes and when to use it.

Recommended first GUI settings for camp mission work:

- `Mode`: `hotkey`
- `Hotkey`: `F8`
- `Capture Gate`: `camp-mission`
- `Gate Match`: `any`
- `Unique only`: enabled
- `Context Bytes`: `64`
- `Decode context numbers`: enabled
- `Summary`: `top-hits`
- `Timestamp output`: enabled
- `Export manifest`: enabled

Install archive decode extras if you need encrypted XML or LZ4 entries:

```powershell
pip install .[unpack]
```

Install schema validation extras if you want hard validation gates for automation:

```powershell
pip install .[schema]
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
- `--no-interactive` suppresses the fallback window picker so scripts fail cleanly when the game is not detected
- `--hotkey-poll-interval` controls hotkey polling cadence separately from loop capture interval
- `--timestamp-output` creates a fresh log file per session
- `--session-name` controls the filename prefix used for timestamped logs
- `--export-manifest` writes a sidecar JSON manifest with the exact CLI settings
- `--compare-last` compares the current snapshot against the previous snapshot
- `--validate-schemas` validates generated JSON payloads against bundled schemas before writing or rendering
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

Build a reusable archive index:

```powershell
python -m cd_sniffer --archive-index --archive-root "C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert" --archive-filter "*.paseq" --archive-filter "*.json" --archive-index-db logs\cdsniffer-archive-index.sqlite --archive-format markdown --archive-report-output logs\archive-index.md
```

Correlate a capture directly against indexed archive entries:

```powershell
python -m cd_sniffer --correlate-archive logs\camp-mission.jsonl --correlate-archive-index logs\cdsniffer-archive-index.sqlite --correlate-archive-cache logs\archive-cache --correlate-archive-glob "*.paseq" --correlate-archive-term mission --correlate-format markdown --correlate-output logs\archive-correlation.md
```

Useful archive options:

- `--archive-root` points to the game root, an archive folder, or a specific `.pamt` file and can be repeated
- `--archive-paz-dir` points to the matching `.paz` directory when listing a standalone `.pamt`
- `--archive-list` parses PAMT indexes and reports archive entries without extracting
- `--archive-extract` extracts matching entries to `--archive-output`
- `--archive-index` builds a reusable SQLite metadata index for later capture-to-archive correlation
- `--archive-index-db` controls where the SQLite archive index is written
- `--archive-filter` filters by entry path glob or substring and can be repeated
- `--archive-limit` caps list or extract operations
- `--archive-all` is required when extracting everything without a filter or limit
- `--archive-no-decrypt` extracts encrypted XML bytes without decrypting
- `--archive-dry-run` previews extraction without writing decoded files
- `--archive-validate` reads, decrypts, and decodes entries without writing decoded files
- `--decoder-sample` loads exact-match sample packs for archive extraction
- `--archive-format json|csv|markdown` controls report format
- `--archive-report-output` writes the archive report to a file
- `--validate-schemas` or `CDSNIFFER_VALIDATE_SCHEMAS=1` validates archive JSON payloads before output

Useful archive correlation options:

- `--correlate-archive` points to a CDSniffer JSON or JSONL capture to compare against indexed archive entries
- `--correlate-archive-index` points to the SQLite archive index; if omitted, CDSniffer uses `--archive-index-db`
- `--correlate-archive-cache` stores decoded archive entries so repeated searches do not decode the same PAZ payload again
- `--correlate-archive-glob` limits candidate archive paths by glob and can be repeated
- `--correlate-archive-term` limits candidate archive paths by substring and can be repeated
- `--correlate-archive-max-entries` caps how many archive entries are decoded in one run
- `--correlate-archive-no-decrypt` keeps XML payloads encrypted during archive correlation
- `--decoder-sample` loads exact-match sample packs for archive correlation
- `--correlate-max-matches`, `--correlate-max-matches-per-evidence`, `--correlate-context-bytes`, `--correlate-no-numeric`, `--correlate-no-format-hints`, `--correlate-format`, and `--correlate-output` also apply to archive correlation

Archive decode notes:

- Compression type `0` is uncompressed pass-through.
- Compression type `1` is treated as raw asset storage. Current 1.13 game files use this for `.dds`, `.pam`, `.pamlod`, and `.pac` assets; many of those entries intentionally have a stored size smaller than the logical asset size while already beginning with valid asset headers like `DDS ` or `PAR `.
- Compression type `2` is LZ4 block data and needs `pip install .[unpack]`.
- Compression type `3` uses adaptive decoding: CDSniffer tries raw, zlib, and LZ4 paths and records the decoder that worked.
- Compression type `4` is zlib and uses the Python standard library.
- `--decoder-sample` can point to a folder or manifest containing exact-match decoder samples for future proprietary PAZ payloads. Each sample manifest is a JSON object with a `samples` array, and each sample points at a compressed source file plus the decoded bytes it should produce. When the compressed SHA-256 matches, CDSniffer reuses the learned decoded bytes and labels the decoder as `sample:<name>`.

Correlate a capture against unpacked files:

```powershell
python -m cd_sniffer --correlate-capture logs\camp-mission.jsonl --correlate-root D:\Documents\CrimsonDesertMods\unpacked --correlate-glob *.json --correlate-glob *.paseq --correlate-format markdown --correlate-output logs\correlation.md
```

Correlate a capture against one selected decoded or unpacked file:

```powershell
python -m cd_sniffer --correlate-capture logs\camp-mission.jsonl --correlate-file D:\Documents\CrimsonDesertMods\decoded\sequencer\binary__\baseseq\gimmickcalledseq\gimmick_craft_shortcook_oven_00.paseq --correlate-format markdown --correlate-output logs\selected-file-correlation.md
```

Correlate a baseline/target pair against unpacked files:

```powershell
python -m cd_sniffer --correlate-baseline logs\before-camp-ui.jsonl --correlate-target logs\camp-ui-open.jsonl --correlate-root D:\Documents\CrimsonDesertMods\unpacked --correlate-glob *.json --correlate-glob *.paseq --correlate-format markdown --correlate-output logs\correlation-diff.md
```

Correlate repeated target captures and boost candidates that show up every time:

```powershell
python -m cd_sniffer --correlate-target logs\camp-ui-open-1.jsonl --correlate-repeat logs\camp-ui-open-2.jsonl --correlate-repeat logs\camp-ui-open-3.jsonl --correlate-root D:\Documents\CrimsonDesertMods\unpacked --correlate-glob *.json --correlate-glob *.paseq --correlate-format markdown --correlate-output logs\correlation-repeat-rollup.md
```

Export a DMM byte-patch draft from a JSON correlation report:

```powershell
python -m cd_sniffer --dmm-export logs\archive-correlation.json --dmm-output logs\cdsniffer-dmm-draft.json --dmm-title "My Patch Draft" --dmm-author "YourName"
```

Check a generated DMM draft against existing DMM mod JSON files:

```powershell
python -m cd_sniffer --dmm-check logs\cdsniffer-dmm-draft.json --dmm-against D:\Documents\CrimsonDesertMods\mods\ExistingMod\existing.json --dmm-check-format markdown --dmm-check-output logs\dmm-conflicts.md
```

How unpacking, decoding, and comparison fit together:

- `--archive-list` only reads PAMT metadata and helps you find candidate archive paths.
- `--archive-extract` decodes matching PAZ entries into ordinary files you can inspect or pass to `--correlate-file`.
- `--archive-index` stores archive metadata in SQLite so repeated archive searches do not reparse every PAMT.
- `--correlate-archive` compares a capture against indexed archive entries directly; it lazily decodes candidates into `--correlate-archive-cache` and reports each decoded cache path.
- `--correlate-root` scans a whole unpacked/decoded folder tree.
- `--correlate-file` scans only the selected decoded/unpacked file, which is best when the archive report or manual review already gave you one likely target.
- `--dmm-export` converts a JSON correlation report into a DMM-style byte-patch draft. It keeps `patched` values blank by default, so every change must be reviewed and completed before use.
- `--dmm-check` compares a DMM draft/mod JSON against existing DMM mod JSON files and exits with code `2` when conflicts are found.

Choosing the right comparison mode:

- Use `--correlate-archive` first when you have a capture and want CDSniffer to search likely archive entries without unpacking whole folders manually.
- Use `--correlate-file` when you already have one decoded cache file, extracted file, or manually identified candidate and need the exact file offset quickly.
- Use `--correlate-root` when you do not know which decoded file contains the value yet and need a broader search across a folder tree.
- Use `--correlate-baseline` plus `--correlate-target` when you captured a before/after state and want target-only candidates ranked higher.

Useful correlation options:

- `--correlate-capture` points to a CDSniffer JSON or JSONL capture
- `--correlate-target` is an explicit target-capture alias for diff workflows
- `--correlate-baseline` compares a before-state capture against the target capture
- `--correlate-repeat` adds another target capture to the repeat-run rollup and can be repeated
- `--correlate-root` points to the unpacked/game file tree to scan
- `--correlate-file` points to one specific decoded/unpacked file to scan and can be repeated
- `--correlate-glob` limits scanned files by glob and can be repeated
- `--correlate-max-file-size` skips huge files
- `--correlate-max-matches` limits total results
- `--correlate-max-matches-per-evidence` limits repeated offsets for one evidence item
- `--correlate-context-bytes` includes surrounding file bytes in JSON output
- `--correlate-no-numeric` skips decoded numeric candidate bytes
- `--correlate-no-format-hints` skips JSON/text/binary analyzers for a faster raw-byte pass
- `--correlate-format json|csv|markdown` controls the report format
- `--correlate-output` writes the report to a file
- `--validate-schemas` or `CDSNIFFER_VALIDATE_SCHEMAS=1` validates correlation JSON payloads before output
- `--dmm-export`, `--dmm-output`, `--dmm-title`, `--dmm-author`, `--dmm-version`, and `--dmm-patched-placeholder` control DMM draft export
- `--dmm-check`, `--dmm-against`, `--dmm-check-format`, and `--dmm-check-output` control indexed DMM overlap reports grouped by normalized game file

Correlation results include:

- Matching file path and file offset
- Match type, such as text, hit bytes, or decoded numeric candidate bytes
- File format, such as `json`, `paseq`, `txt`, or `binary`
- Evidence count and evidence trail for grouped candidates
- Confidence reasons such as exact hit bytes, text-and-bytes, nearby numeric evidence, or target-only
- Repeat-run fields showing how many target captures reproduced the same file/offset/original-byte candidate
- Format hints such as domain path terms, mission/quest-like JSON records, text line/column, PASEQ timing and sequence labels, nearby printable strings, CRC/hash candidates, and little-endian values
- Diff status when a baseline is provided: `target-only` or `shared-with-baseline`
- Original bytes at the file offset
- Runtime address and module-relative RVA when available
- Confidence score
- A generic byte patch skeleton with file, offset, original bytes, and empty replacement bytes

Archive correlation results include the same evidence and confidence fields, plus:

- `archive_path`, the original path inside the PAZ/PAMT archive
- `decoded_offset`, the byte offset inside the decoded entry that a DMM-style file patch should usually target
- `archive_offset`, the stored byte offset inside the PAZ container for provenance only
- `paz_file` and `pamt_file`, so the source archive can be verified
- `compression_name`, `compression_decoder`, `decrypted`, and `decompressed`, so users can see how the cache entry was produced
- `cache_path`, the decoded file CDSniffer searched for that specific archive entry

Search the live GUI capture:

- Use the search box on the `Real-Time` tab
- Toggle `Regex` when you want pattern matching instead of a literal string
- Toggle `Case sensitive` when you need exact casing
- Toggle `Filter top-hits table` when you want only the matching rows in the hit list
- Use the embedded terminal with `search <query>` or `search-clear`
- Use the embedded terminal with `search-export [path]` and `search-import [path]` to manage search presets
- Use the embedded terminal with `correlate <capture> <root> [json|csv|markdown]` to run a compact file-offset report
- Use the embedded terminal with `correlate-file <capture> <decoded-file> [json|csv|markdown]` to compare against one selected file
- Use the embedded terminal with `correlate-diff <baseline> <target> <root> [json|csv|markdown]` to compare before/after captures
- Use the embedded terminal with `archive-index <archive-root> <index-db> [glob...]` to build a reusable archive index
- Use the embedded terminal with `correlate-archive <capture> <index-db> <cache-dir> [json|csv|markdown] [glob...]` to correlate a capture against indexed game archives
- Matching text is highlighted directly in the live raw snapshot view
- Use the `Recent` dropdown to reuse previous searches
- Use the saved-search controls to store and restore named search presets
- Use the import/export buttons if you want to share search history with another machine
- Use the `Search` tab to search a folder of capture logs and filter the results table live

Use the GUI `Archives` tab:

- Use `Guided Correlation Workspace` when you want the UI to walk through index building, index search, archive correlation, selected-file correlation, decoded-folder correlation, or DMM draft export
- Set `Archive root` to the Crimson Desert install folder or a specific `.pamt` file
- Set `Index DB` to the SQLite file you want to create or reuse
- Use `Index globs` to keep the index focused, such as `*.paseq`, `*.json`, or `*.xml`
- Click `Build / Rebuild Index` after a game update or when changing indexed file families
- Use `Search Indexed Archive Entries` to quickly inspect archive paths before decoding anything
- Set `Capture` to a CDSniffer JSON/JSONL capture and `Cache dir` to a decoded cache folder
- Use archive correlation globs and path terms to narrow candidates before clicking `Run Archive Correlation`
- Use `Decoded file` plus `Run File Correlation` when you want to compare the capture against one selected unpacked/cache file instead of an entire folder or archive index
- Use `Decoded root`, optional `Baseline`, and `Run Folder Correlation` when you want to compare a capture against a decoded folder tree and optionally rank target-only before/after candidates
- Inspect the `Correlation Matches` table for confidence, decoded offset, evidence value, decoder, original bytes, cache path, and confidence reasons
- Select a correlation row to preview the decoded/cache bytes around the offset, printable text, evidence metadata, and generic patch skeleton
- Click `Extract Selected Entry` to copy the decoded cache file behind an archive correlation match into a chosen folder, preserving the archive-relative path and writing a `.cdsniffer.json` metadata sidecar
- Click `Export DMM Draft` after correlation to write a review-required DMM patch JSON draft with grouped `game_file` and `changes` entries
- Export the latest index summary or correlation report from the tab when sharing results

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
11. Build a reusable `--archive-index` for likely file families, such as `*.paseq`, `*.json`, `*.xml`, and mission-related path terms.
12. Run `--correlate-archive` with focused globs/path terms and inspect the highest-confidence decoded offsets first.
13. Use the decoded cache path from the archive-correlation report when you need to manually inspect one candidate file.
14. Use `--archive-extract` to decode only the focused subset you need into a clean working folder when manual review needs full folders.
15. Compare the resulting strings against decoded `questgaugeinfo`, `questinfo`, and `missioninfo` style tables and keep only the entries that consistently show up in the correct camp UI.
16. Run `--correlate-baseline` plus `--correlate-target` against a decoded file tree when you specifically need before/after diff status.
17. Prefer rows with format hints that point to JSON record keys, mission-like tables, PASEQ candidates, or nearby little-endian values.
18. Prefer module-relative `module_rva` over absolute `address` whenever it is available; absolute addresses can shift between launches.
19. If a string appears in multiple game systems, prefer the one that is unique to the camp/dispatch screen over one that also appears in player quests.

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
- `Archives` for PAMT/PAZ index building, index search, archive correlation, and report export
- `Terminal` for CLI-style commands inside the app
- `Logs` for the rolling session log
- `Presets` for reusable capture settings

The GUI uses the same backend as the CLI, so captures, manifests, comparisons, and export formats all stay consistent between both entry points.

The GUI also includes:

- A dedicated settings dialog for the full configuration set
- Hover tips for settings, capture controls, search controls, archive workflows, and preset actions
- IPC handling so the CLI can start, stop, show, hide, and retarget the GUI
- A read-only capture dashboard so the main tab stays clean
- A live search box on the `Real-Time` tab that filters the current capture in place
- A dedicated archive workflow tab that surfaces decoded-offset correlation without requiring terminal commands

Suggested starting command:

```powershell
python -m cd_sniffer --mode hotkey --hotkey F8 --window-title "Crimson Desert" --captures 20 --context-bytes 64 --decode-context-numbers --summary top-hits --timestamp-output --output logs\cdsniffer.jsonl
```

## Near-Term Roadmap

Good next steps before opening this up more broadly:

For a fuller development handoff, see [`ROADMAP_REPORT.md`](ROADMAP_REPORT.md).

- [x] Add archive/file match preview in the GUI so selecting a correlation row shows decoded bytes, printable text, offset metadata, and patch skeleton context
- [x] Add DMM-specific patch emitters on top of the generic correlation patch skeletons
- [x] Add a guided correlation workspace that walks users through capture selection, archive/folder/file comparison, baseline selection, and export format
- [x] Expand format analyzers with deeper PASEQ, quest/mission table, hash, and typed record parsers
- [x] Add repeat-run confidence rollups across multiple target captures
- [x] Add one-click extraction for the archive entry behind a selected archive correlation match
- [x] Add JSON schema validation gates through a `--validate-schemas` flag and optional environment variable
- [x] Add DMM conflict/overlap checking for generated patches against existing DMM mod JSON
- [x] Add exact GUI smoke tests with the `PySide6` extra installed
- [x] Validate more inputs before they reach capture/correlation so bad hotkeys, paths, and imported settings fail fast
- [x] Add more headless tests for settings round-trips, GUI profile import/export, and CLI/GUI defaults parity
- [x] Harden the GUI state model so the preview, hotkey field, and capture settings stay consistent after edits and imports
- [x] Make the archive workflow more resilient with preflight checks for index build, correlation, and selected-file comparison inputs
- [x] Improve diagnostics with copyable error summaries, structured action logs, and a rollback-friendly last-good settings snapshot
- [x] Add sample-driven decoders for any future proprietary PAZ compression payloads that are not raw, zlib, or LZ4
- [x] Add a random session token and stale-PID checks to the localhost GUI IPC channel
- [ ] Add a build/release script for `cdsniffer.exe` and `cdsniffer-gui.exe`
- [ ] Add DMM baseline/target auto-fill for reviewed patch drafts once byte-source rules are proven
- [ ] Split the large GUI module into smaller files once the interface settles

## Notes

- This tool is Windows-only.
- CLI mode relies on standard library APIs only; GUI mode needs `PySide6`.
- The scanner is intentionally conservative and only looks at readable committed regions.
- Capture gates are memory-sentinel checks, not computer-vision screen cropping.
- If the camp gate misses a UI state, use `--capture-gate custom` with `--gate-keyword` or `--gate-regex` from a known visible label.
- If the process name lookup is unreliable, prefer `--window-title` or `--pid`.
- Keep `--pick-window` as a human fallback for ambiguous process/window state; normal captures should still auto-target Crimson Desert by process name, PID, or window title.
- Use `--no-interactive` for scheduled tasks, wrappers, or CI-style probes that should not wait for keyboard input.
- The CLI-to-GUI IPC channel is localhost-only, token-protected per GUI session, and refuses stale state files when the recorded GUI PID is no longer running.
- Set `CDSNIFFER_VALIDATE_SCHEMAS=1` when you want every CLI run to use schema validation without adding `--validate-schemas`.
- The JSON schema for capture output lives in `schemas/cdsniffer-output.schema.json`.
- The JSON schema for correlation output lives in `schemas/cdsniffer-correlation.schema.json`.
- The JSON schema for archive list/extract output lives in `schemas/cdsniffer-archive.schema.json`.
- The JSON schema for archive index output lives in `schemas/cdsniffer-archive-index.schema.json`.
- The JSON schema for archive correlation output lives in `schemas/cdsniffer-archive-correlation.schema.json`.
- The detailed project history lives in `CHANGELOG.md`.
- The reviewed project audit and maintainer follow-up live in `AUDIT_REPORT.md`.
- The GUI is optional and needs `pip install .[gui]`.
- Encrypted XML and LZ4 archive decoding need `pip install .[unpack]`; PAMT listing, raw pass-through, and zlib extraction use the standard library.
- The main GUI capture tab is intentionally a dashboard; all editable settings live in the settings dialog.
- Live search only filters the current snapshot view; it does not mutate the underlying capture payload.
