# CDSniffer Project Audit Report

**Audit Date:** July 7, 2026  
**Project:** CDSniffer — Crimson Desert Runtime Memory Logger  
**Reviewer:** Code Audit

---

## Maintainer Follow-Up

**Follow-up Date:** July 7, 2026  
**Status:** Reviewed and partially implemented

This audit was useful, but a few findings were stale by the time it was reviewed. The accepted items below were implemented in `f33b263 feat: add focused file correlation`.

### Accepted And Implemented

- Added explicit archive-correlation truncation metadata: `raw_match_limit`, `pre_limit_match_count`, `truncated`, and `truncated_at_raw_match_count`.
- Added focused selected-file correlation so users can compare a capture against one decoded or unpacked file instead of scanning a whole tree.
- Added CLI support with repeatable `--correlate-file`.
- Added GUI support in the `Archives` tab with `Decoded file` and `Run File Correlation`.
- Added embedded terminal support with `correlate-file <capture> <decoded-file> [json|csv|markdown]`.
- Updated schemas and tests for selected-file correlation and archive truncation reporting.

### Correct But Deferred

- Splitting `gui.py` into smaller widgets is directionally right, but should be a deliberate refactor after the feature surface settles.
- Splitting `cli.py` into command handlers is worthwhile, but lower risk after schema and command behavior stabilize.
- Structured logging would help long-running sessions, but should be introduced consistently rather than mixed with the current simple CLI output.
- Archive entry preview in the GUI is a strong next feature because it would connect a match row directly to decoded bytes/text around the offset.

### Stale Or Not Accepted

- The optional dependency finding was stale. `pyproject.toml` already declares `gui`, `unpack`, and `full` extras.
- The SQL `LIMIT` before Python pattern filtering finding was stale for the current code. `select_archive_entries()` fetches SQL-filtered rows, applies Python glob matching, and only then stops at the requested selected-entry limit.
- Direct hex editor launch is not a priority yet because CDSniffer currently reports file offsets and patch skeletons; external editor integration should wait until offset navigation targets are better standardized.

---

## Table of Contents

0. [Maintainer Follow-Up](#maintainer-follow-up)
1. [What's Done Well](#1-whats-done-well)
2. [What's Bad / Needs Improvement](#2-whats-bad--needs-improvement)
3. [Useful Features to Add](#3-useful-features-to-add)
4. [Summary](#4-summary)

---

## 1. What's Done Well

### 1.1 Architecture — Clean Separation of Concerns

The project is cleanly split into focused modules, each with a single clear responsibility:

| Module | Responsibility |
|---|---|
| `windows.py` | Native Win32 API wrappers (ctypes) |
| `scanner.py` | Memory scanning, string extraction, hit filtering |
| `paz_archive.py` | PAMT/PAZ archive format RE and extraction |
| `archive_index.py` | SQLite-backed archive indexing |
| `correlator.py` | Evidence extraction and file-offset correlation |
| `format_analyzers.py` | JSON/binary structure detection and hints |
| `ipc.py` | CLI↔GUI communication via socket + state file |
| `core.py` | Orchestration: capture, gating, search, comparison |
| `cli.py` | Argument parsing and command dispatch |
| `gui.py` | PySide6 Qt dashboard with dark theme |

This structure allows each component to be understood and tested in isolation.

### 1.2 Binary Protocol Reverse Engineering

`paz_archive.py` contains deep RE work:

- **`hashlittle`** — Correct implementation of the 32-bit hash function used for XML decryption key derivation
- **XOR key derivation** — `derive_key_iv()` using `HASH_INITVAL`, `IV_XOR`, and `XOR_DELTAS` constants
- **ChaCha20 decryption** — Full decryption pipeline for `.xml` entries in PAZ archives
- **Multi-format decompression** — LZ4, adaptive fallback (zlib → LZ4 → raw), and zlib — all handled with correct `uncompressed_size` validation
- **`_looks_decoded` heuristic** — Magic-byte prefix detection + printable-ratio check to avoid unnecessary decompression

This represents months of careful reverse engineering and shows in the correctness of the implementation.

### 1.3 Evidence Correlation Engine

The correlator (`correlator.py`) is sophisticated and well-designed:

- **Three evidence types**: text (ASCII/UTF-16LE encoded), hit-bytes (raw matched bytes), and numeric candidates (decoded integers from byte context)
- **Weighted confidence scoring**: base weight per evidence type, file uniqueness bonus, size bonuses, format context bonuses
- **Format hints**: JSON record detection with identifier-key extraction, PASEQ binary hints, little-endian integer context
- **Baseline-vs-target diffing**: shared vs. target-only classification with confidence adjustments
- **Deduplication**: raw matches aggregate by (file, offset, bytes) into a single grouped result

The confidence scoring is principled and extensible.

### 1.4 Archive Indexing with Cache Invalidation

SQLite-backed indexing of PAMT/PAZ entries with:

- **Per-entry cache key**: hash of (path, paz_file, offset, comp_size, orig_size, flags, mtime, size) — invalidates on any archive modification
- **Selective decoding**: correlation only decodes entries matching the active patterns, respecting `max_entries`
- **Cache metadata**: JSON sidecar files track `from_cache`, `decrypted`, `decompressed`, `archive_entry` provenance

### 1.5 CLI Design

The argument parser in `cli.py` covers 80+ arguments consistently:

- Consistent `dest` naming (`window_titles`, `include_keywords`, etc.)
- Boolean flags use `action="store_true"` / `store_false`
- Mutually exclusive groups handled via `choices`
- Subcommands (archive, search, correlate) fully wired with validation and multi-format output (JSON, CSV, Markdown)

### 1.6 IPC Mechanism

The file-based IPC discovery (`ipc.py`) is clean:

- `GuiIpcServer` writes its bound port+host+pid to a tempfile JSON state file
- CLI reads state file and connects via TCP socket
- Socket uses `SO_REUSEADDR` to avoid bind failures on rapid restart
- Threaded server with `daemon=True` so it doesn't block shutdown

### 1.7 Test Suite

`tests/test_scanner.py` (699 lines) provides real behavioral coverage:

- String extraction (ASCII + UTF-16LE, mixed blob)
- Keyword and regex filter combinations
- Virtual-key code mapping
- Duplicate counting in `summarize_top_hits`
- Context window hex/ASCII/numeric decoding
- Capture gate modes (off, camp-mission, custom) with `any`/`all` matching
- Unique-hit filtering across sessions
- JSONL/JSON capture file and directory search
- Correlation with baseline diffing
- Archive parsing, extraction, and format hints (JSON records, PASEQ binary)
- Search result rendering (CSV and Markdown)

### 1.8 Frozen Dataclasses

`MemoryHit`, `RegionScan`, `PazEntry`, `Evidence`, `IndexedArchiveEntry`, `GuiCommand` — all use `@dataclass(frozen=True)`. Immutable by design, preventing accidental mutation bugs in a project that processes large volumes of in-memory data.

### 1.9 Graceful Degradation

- `psapi` DLL missing → returns empty module list
- `cryptography` not installed → `MissingArchiveDependency` with pip install hint
- `lz4` not installed → same pattern
- `VirtualQueryEx` read failures → silently skipped
- Adaptive compression → fallback chain (zlib → LZ4 → raw)
- No crash paths for malformed PAMT headers

### 1.10 Domain-Specific Default Keywords

`config.py` ships with curated keywords relevant to the game's content: camp/beacon/stronghold/fort/mine/quarry/prison/outpost/watchtower and mission-gating terms (graymane, greywolf, pailuneoperation, reoccupation, etc.). Not generic.

---

## 2. What's Bad / Needs Improvement

### 2.1 `gui.py` — 3,233 Lines, God Object Pattern

**Severity:** Medium  
**File:** `cd_sniffer/gui.py`

`MainWindow` is a single class with ~60 instance attributes for every UI control. It has 4 `build_*_tab()` methods and at least 8 `on_*` handler methods. A 3,233-line class is difficult to maintain, test, and navigate.

**Recommended Fix:** Break `MainWindow` into sub-widgets:

```
MainWindow (composition only)
├── CaptureSettingsWidget
├── FiltersWidget
│   └── SignaturePackWidget
├── AdvancedWidget
│   └── RegionLimitsWidget
├── BehaviorWidget
│   └── TrayNotificationWidget
└── ArchiveCorrelationWidget
```

Each sub-widget owns its controls and emits signals or calls callbacks to the parent.

---

### 2.2 `cli.py` — 664-Line `main()` Function

**Severity:** Low-Medium  
**File:** `cd_sniffer/cli.py`

`main()` handles 15+ distinct command branches (archive-index, archive-list, archive-extract, correlate-archive, correlate, search, capture). Each block is 30-60 lines of validation + execution + rendering.

**Recommended Fix:** Extract each branch:

```python
def handle_archive_index(args) -> int: ...
def handle_archive_list(args) -> int: ...
def handle_correlate_files(args) -> int: ...
def handle_search(args) -> int: ...
def handle_capture(args) -> int: ...
```

`main()` becomes a dispatch table.

---

### 2.3 `core.py` — Missing Type Annotations

**Severity:** Low  
**File:** `cd_sniffer/core.py`

Search and correlation functions (`search_payload_values`, `search_flattened_hits`, `search_capture_file`, `search_capture_directory`, `flatten_hits`, `build_manifest`) are heavily used across the codebase but lack full type annotations on their signatures and return types. Hinders static analysis and IDE tooling.

---

### 2.4 `archive_index.py` — SQL `LIMIT` Applied Before Python Pattern Filter

**Severity:** Medium  
**File:** `cd_sniffer/archive_index.py`, `select_archive_entries()`

```python
sql = "SELECT * FROM entries ..."
# ... WHERE clause with parameterized queries ...
cursor = conn.execute(sql, params)
for row in cursor:
    entry = _indexed_entry_from_row(row)
    if lowered_patterns and not _matches_any_pattern(entry.path, lowered_patterns):
        continue   # ← counts toward nothing; LIMIT already applied at DB level
    selected.append(entry)
    if limit is not None and len(selected) >= limit:
        break
```

`LIMIT` is enforced by SQLite before Python pattern matching. If `limit=100` and only 40 of 100 rows pass the Python `fnmatch` filter, the caller receives 40 results with no indication that the result set was truncated by the database `LIMIT`.

**Fix:** Either (a) fetch all matching rows from SQLite and apply Python filtering in-memory, or (b) build `LIKE` clauses for patterns and push the filtering entirely into SQL.

---

### 2.5 `correlator.py` — Silent Early Exit in Archive Correlation

**Severity:** Medium  
**File:** `cd_sniffer/archive_index.py`, `correlate_capture_to_archive()`

```python
raw_limit = max_total_matches * 4
for entry in entries:
    if len(raw_matches) >= raw_limit:
        break   # stops collecting raw matches
# ...
matches = aggregate_archive_correlation_matches(raw_matches)
matches = matches[:max_total_matches]
```

If 2,000 raw matches deduplicate to 150 unique matches, the caller receives 150 — silently incomplete — rather than 500 as requested. No `truncated` or `early_exit` flag is set in the result dict.

**Fix:** Add `"truncated": len(raw_matches) >= raw_limit` and `"truncated_at_raw_match_count": len(raw_matches)` to the result.

---

### 2.6 No Structured Logging

**Severity:** Low-Medium  
**Files:** `cd_sniffer/core.py`, `cd_sniffer/cli.py`

```python
def log_message(args, msg, verbose_only=False):
    if verbose_only and not args.verbose:
        return
    print(msg)
```

Ad-hoc `print()` and `log_message()` are used throughout. No log levels, no dynamic control, no output to file. The `--quiet`/`--verbose` flags exist but are implemented with conditional branches.

**Recommended Fix:** Replace with Python's `logging` module. Set `INFO` as default, `DEBUG` when `--verbose`, suppress non-errors when `--quiet`.

---

### 2.7 IPC File-Based Discovery — Race Condition on Port Collision

**Severity:** Medium  
**File:** `cd_sniffer/ipc.py`

If two CDSniffer GUI instances run simultaneously:

1. Both write to `GUI_IPC_STATE_FILE` (overwrite each other's)
2. If both bind to `port=0` (auto-assign), they get different ports
3. The CLI reads whichever instance wrote last → sends command to the wrong process

Additionally, if `server.bind()` fails silently (exception caught in `handle_client`, not in `run`), the server continues on port 0 but `write_state_file()` writes the correct port — the CLI connects to nothing.

**Fix:** Write the PID to the state file first. CLI reads PID and verifies the process exists before connecting. On port bind failure, log and exit rather than silently continuing.

---

### 2.8 `read_memory` — No Retry on Transient Guard Pages

**Severity:** Low  
**File:** `cd_sniffer/windows.py`

```python
def read_memory(handle, address, size):
    ok = kernel32.ReadProcessMemory(...)
    if not ok:
        return b""   # single attempt; no retry
```

PAGE_GUARD regions always fail (correct), but a single retry after a 1ms sleep would handle transient guard-page scenarios more robustly. Guard pages are used by some games for copy-on-write memory init.

---

### 2.9 Default Keywords May Not Match In-Memory Strings

**Severity:** Low  
**File:** `cd_sniffer/config.py`

Default keywords (`"pailuneoperation"`, `"reoccupation"`, `"reconstruction"`) are lowercase. The game's in-memory strings use PascalCase internal naming (`Quest_Node_Her_DeepForestBeacon_Normal`). The `--include-keyword camp` will match `"camp"` in `"Camp_Mission_..."` because filtering is case-insensitive, but `"pailuneoperation"` will not match `"PailuneOperation"`.

**Fix:** Document this in the README and consider adding both lowercase and PascalCase variants to the default keyword list.

---

### 2.10 `pyproject.toml` — Optional Dependencies Not Properly Declared

**Severity:** Low  
**File:** `pyproject.toml`

`PySide6>=6.7`, `cryptography>=42`, and `lz4>=4.3` are listed as dependencies but not under a named `[project.optional-dependencies]` extra. Running `pip install .[unpack]` will fail if the extra isn't properly declared.

---

### 2.11 `flatten_hits` — Redundant `isinstance` Check

**Severity:** Cosmetic  
**File:** `cd_sniffer/core.py`, `flatten_hits()`

```python
module = region.get("module") or {}
module_name = module.get("name") if isinstance(module, dict) else None
```

`module = region.get("module") or {}` already guarantees a dict (or an empty dict), so `isinstance(module, dict)` is always `True` here. Minor.

---

### 2.12 `GuiIpcServer.handle_client` — Silent Exception Swallowing

**Severity:** Low  
**File:** `cd_sniffer/ipc.py`, `handle_client()`

```python
except Exception as exc:
    try:
        client.sendall(...)  # if this also fails, silently lost
    except OSError:
        pass
```

If the client disconnects mid-response and `sendall` fails, no log entry is made. Difficult to debug in production.

---

### 2.13 `find_pid_by_name` — Synchronous `tasklist` Per Launch

**Severity:** Low  
**File:** `cd_sniffer/core.py`, `find_pid_by_name()`

```python
subprocess.run(["tasklist", "/fo", "csv", "/nh"], ...)
```

On a system with many processes, `tasklist` takes 1-2 seconds. It's called synchronously every time the CLI starts without `--pid`. Consider caching within the session or using the Windows API directly (`EnumProcesses` via ctypes).

---

### 2.14 `iter_memory_regions` — Zero-Size Region Handling

**Severity:** Low (theoretical)  
**File:** `cd_sniffer/windows.py`, `iter_memory_regions()`

```python
next_address = base + region_size
if next_address <= address:
    break
address = next_address
```

If `RegionSize = 0` (possible with `MEM_RESERVE` without `MEM_COMMIT`), `next_address == address`, the loop correctly breaks. However, the conversion `int(ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value or 0)` could produce unexpected results on edge cases with very large address spaces. The `c_size_t` arithmetic is correct but the Python `int()` conversion should be audited for signed/unsigned edge cases.

---

### 2.15 Missing JSON Schema Validation

**Severity:** Low  
**Files:** `json/` directory (schemas exist but are not enforced)

The project ships JSON schema files but nothing validates output against them. A `SCHEMA_VALIDATE=1` environment variable or `--validate-schemas` CLI flag that runs output through `jsonschema` before writing would catch regressions.

---

## 3. Useful Features to Add

### 3.1 Live Memory Diff View (GUI)
Currently `compare-last` is CLI-only and shows added/removed strings. A GUI panel that shows a live diff between two running snapshots — highlighting changed byte offsets, frequency changes in repeated strings, and newly committed memory regions — would be significantly more useful for tracking game state changes in real time.

### 3.2 Pattern Marketplace / Signature Pack Sharing
Export signature packs as `.csp` (CDSniffer Signature Pack) files with metadata (author, game version, date, description). A git-lfs repo or simple HTTP index would allow the community to share curated keyword sets for different game versions or research goals. The `load_signature_pack` already supports JSON and text formats.

### 3.3 Memory Region Watcher
Instead of scanning all readable regions, allow specifying a fixed address range (e.g., `0x140000000+0x10000`) to watch continuously. Useful for monitoring a specific module's `.data` section or a known game structure for changes without the noise of a full memory scan.

### 3.4 Hex Editor Integration
When the GUI shows a hit at address `0x7FF6A4B3C100`, add an "Open in Hex Editor" button that launches `HxD` or `010 Editor` at that address. Implement via a URL scheme (`cdsniffer://goto/0x...`) or direct CLI invocation with `--hex-edit` flag.

### 3.5 Archive Entry Preview in GUI
In the archive correlation results view, clicking a match should show a decoded preview of the file at that offset — decompressed and decrypted, rendered as formatted JSON/XML/text depending on detected type. The decoded data already exists in the cache; it just needs a viewer widget.

### 3.6 Web Dashboard
A lightweight FastAPI/Flask server alongside the GUI that serves a web dashboard accessible from a phone or another PC on the LAN. Useful for monitoring captures on a gaming laptop from a secondary monitor. Share state via the existing IPC socket or add a WebSocket.

### 3.7 Plugin / Hook System
Allow users to register Python functions in `~/.cdsniffer/plugins/` that are called after each capture:

```python
def on_capture(payload: dict, args: Namespace) -> None:
    ...
```

Example hooks: POST to a webhook, run regex substitutions, feed into an external tool, trigger a notification.

### 3.8 Capture Session Replay
Replay a capture session from a manifest + JSONL file — replay keyword filtering, gate logic, and unique-only logic against a new PID or game version. Useful for applying the same signature pack to a different game version to find renamed or moved strings.

### 3.9 Memory Write Detection Mode
Currently read-only scanning. Add a mode that polls for memory region protection changes (`MEM_COMMIT` new regions, protection changes to `PAGE_READWRITE`) and alerts when a region that was previously unreadable becomes readable — useful for tracking when games decrypt/load data into memory mid-session.

### 3.10 Game Version Auto-Detection
Read the game's PE module headers automatically to extract the build version string and store it in captures. Currently a manual `--game-version` flag. Use `GetFileVersionInfo` Win32 API or parse the PE header's `VS_FIXEDFILEINFO`.

### 3.11 Dark Theme Tray Icon
The SVG icon may not contrast well with all Windows taskbar themes. Add a proper dark-variant icon alongside the current one, selected based on the Windows theme (light/dark).

### 3.12 Archive Cache Cleanup
The decoded archive cache in `logs/archive-cache` grows indefinitely. Add:

- `--cache-max-age` flag to auto-delete cache entries older than N days
- GUI button to clear the cache
- Periodic cleanup job on startup

### 3.13 Fuzzy String Matching for Correlation
Currently evidence matching is exact byte/substring. Add an optional fuzzy match mode using Levenshtein distance (or a faster variant like `rapidfuzz`) for near-duplicate strings that differ by a few characters across game versions. Useful for finding renamed nodes or migrated strings.

### 3.14 JSON Schema Validation Gate
Add a `--validate-schemas` flag that validates all output JSON against the schemas in `json/` before writing. Set `SCHEMA_VALIDATE=1` as an environment variable to enable globally.

### 3.15 Structured CSV Export for Capture Data
JSONL is great for tooling but hard to browse manually. Add a "flattened CSV" export mode that flattens every hit into a row with columns: `timestamp, pid, session_name, label, base_address, region_size, protection, module_name, address, encoding, text`. Equivalent to what `flatten_hits()` produces but wired to the CLI `--format csv` output path.

---

## 4. Summary

| Category | Count |
|---|---|
| Strengths | 10 |
| Weaknesses / Bugs | 15 |
| Feature Suggestions | 15 |

### Top 5 Priority Improvements

1. **Break up `MainWindow`** (gui.py) — maintainability, testability
2. **Fix SQL LIMIT before Python filter bug** (archive_index.py) — correctness
3. **Add structured logging** (core.py, cli.py) — debuggability
4. **Refactor `main()` into handlers** (cli.py) — maintainability
5. **Add correlation truncation signal** (archive_index.py) — correctness

### Top 5 Priority New Features

1. **Live memory diff view in GUI** — most impactful for active research
2. **Hex editor integration** — immediate practical value
3. **Plugin/hook system** — extensibility without core changes
4. **Archive entry preview in GUI** — bridges the correlation→inspection gap
5. **Game version auto-detection** — removes manual bookkeeping

---

*End of report.*
