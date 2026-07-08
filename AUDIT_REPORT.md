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

## Audit Update — July 7, 2026 (Second Pass)

**Scope:** re-audit after the GUI/CLI work shipped since the first audit (added DMM, archive correlation truncation, archive cache preflight, GUI refactor into sub-widgets, schema validation, archive index, sample-pack decoder fallback, settings profile helpers, GUI diagnostics/rollback, hotkey capture widget, embedded terminal commands, format analyzer hints, repeat-run rollups, focused selected-file correlation, GUI correlation previews, archive match extraction).

**Verdict on prior findings:** most of the original 15 weaknesses are still open or have only partially landed. Three were fully resolved (2.5 archive truncation, 2.10 optional deps, 2.15 JSON schema validation). One was confirmed stale (2.4 SQL LIMIT before Python filter). One was confirmed deferred by design (2.6 structured logging — accepted-but-deferred in the maintainer follow-up).

The new findings below cover DMM module O(n²) reporting, a markdown append-header bug, GUI IPC missing the auth token flagged in the roadmap, hotkey polling clamping `--interval` without documentation, manifest sanitization hardcoding only `pid`, and 14 other items.

### Original Findings — Re-Verified

| # | Finding | Status | Evidence |
|---|---|---|---|
| 2.1 | `gui.py` 3,233-line god object | **Partially resolved** | `HotkeyLineEdit`, `SettingsDialog`, `TerminalPanel`, `WindowPickerDialog`, `CaptureWorker`, `ArchiveTaskWorker` extracted (lines 367/454/781/809/851/1061). `MainWindow` still at ~2,955 lines. Roadmap 3.3 keeps the refactor open. |
| 2.2 | `cli.py` 664-line `main()` | **Still open (deferred)** | `main()` now 508 lines (cli.py:280-787), with 8 inline dispatch blocks for `gui_command`, `gui`, `list_windows`, `dmm_export`, `dmm_check`, `archive_index`, `archive_list/extract`, `correlate_archive`, `correlate_files`, `search`, capture modes. Maintainer follow-up already deferred this until CLI stabilizes. |
| 2.3 | `core.py` missing type annotations | **Still open** | `search_payload_values`, `search_flattened_hits`, `search_capture_file`, `search_capture_directory`, `flatten_hits`, `build_manifest` still lack full annotations on parameters/return. |
| 2.4 | SQL `LIMIT` before Python filter | **Confirmed stale** | `select_archive_entries` (archive_index.py:251-271) builds SQL **without** a `LIMIT` clause. Python pattern matching applies before the in-memory `if len(selected) >= limit: break`. Maintainer follow-up correctly identified this; no SQL `LIMIT` exists. |
| 2.5 | Silent early exit in archive correlation | **Resolved** | `correlate_capture_to_archive` (archive_index.py:337-401) now emits `raw_match_limit`, `pre_limit_match_count`, `truncated`, `truncated_at_raw_match_count`. |
| 2.6 | No structured logging | **Deferred by design** | Maintainer follow-up deferred. `log_message` (core.py:666) still uses `print()` with conditional branches. Roadmap 3.5 touches validation polish only. |
| 2.7 | IPC file-based port collision | **Partially resolved** | `pid` is now written to the state file (ipc.py:56), but `send_gui_command` (ipc.py:114-139) never verifies the PID is alive. Stale state files from crashed GUIs cause silent connect-refused cycles. Roadmap 3.2 adds a session token but does not add PID liveness. |
| 2.8 | `read_memory` no retry | **Still open** | windows.py:126-138 unchanged — single attempt, no retry. PAGE_GUARD correctly skipped. |
| 2.9 | Default keywords case mismatch | **Still open** | core.py:25-32 default gate keywords use title-case (`"Mission Dispatch"`); config.py defaults still include `"pailuneoperation"`/`"reoccupation"` etc. lowercase. README does not document this. |
| 2.10 | Optional deps not declared | **Resolved** | pyproject.toml:17-21 now declares `gui`, `unpack`, `schema`, `full` extras. |
| 2.11 | `flatten_hits` redundant `isinstance` | **Still open (cosmetic)** | core.py:300-303 still has `if isinstance(module, dict)` despite `module = region.get("module") or {}` already guaranteeing a dict. |
| 2.12 | Silent exception in `handle_client` | **Still open** | ipc.py:107-111 still swallows OSError silently on `sendall` failure. |
| 2.13 | Synchronous `tasklist` per launch | **Still open** | core.py:38-60 `find_pid_by_name` still shells out per call. `resolve_pid` may call it again on process-name fallback. |
| 2.14 | Zero-size region handling | **Still open (theoretical)** | windows.py zero-size break behavior unchanged; `c_void_p` conversion not re-audited. |
| 2.15 | Missing JSON schema validation | **Resolved** | `--validate-schemas` flag and `CDSNIFFER_VALIDATE_SCHEMAS=1` env var both implemented (schema_validation.py:10-23). Wired into `validate_result_if_requested` for all five schema names. **Caveat:** tests `test_schema_validation_accepts_archive_index_report` and `test_schema_validation_rejects_invalid_payload` fail in any venv where `rpds-py` is broken (see new finding N7). |

### New Findings

#### N1. Markdown `write_rendered_snapshot` re-emits the header on every append
**Severity:** Low-Medium
**File:** `cd_sniffer/core.py:649-663`

`write_rendered_snapshot` strips the CSV header on append (line 653-654) but the markdown branch (line 658-661) has no equivalent logic. `render_markdown_snapshot` (line 620) emits a fresh `# CDSniffer Snapshot` heading, `- Timestamp:` block, and full table header on every call. Appending N captures produces a file with N heading blocks and a single malformed table (the table rows from capture 2 sit below the table header from capture 1, but the separator row from capture 1 sits between rows from capture 1 and 2 — actually a different table). Result: concatenated output is valid markdown but visually broken.

**Fix:** add the same `splitlines(True)[1:]` strip to markdown (after the separator row, since markdown tables need `| --- |` removed too), or write each snapshot as its own file under `--timestamp-output`.

#### N2. Manifest sanitizer hardcodes only `"pid"`
**Severity:** Low (security/privacy)
**File:** `cd_sniffer/core.py:248-257`

`sanitize_manifest_value` excludes exactly one key (`pid`) when serializing `vars(args)` into `build_manifest`. Any future settings field that should not appear in manifests (credentials, debug paths) must be added by hand. The function name suggests it does general sanitization; in reality it only protects one field.

**Fix:** rename to `redact_pid` and accept a configurable `_REDACT_KEYS` set, or move redaction into a per-arg explicit allow-list driven by the CLI parser.

#### N3. `write_snapshot` silently overwrites vs appends based on a flag
**Severity:** Low (correctness surprise)
**File:** `cd_sniffer/core.py:157-163`

`write_snapshot(output_path, payload, fmt)` writes JSON as an overwrite and JSONL/anything-else as an append (mode `"a"`). The function name does not disclose this; callers passing `fmt="json"` to an existing path silently destroy prior content. Both `write_snapshot` and `write_rendered_snapshot` have this asymmetry.

**Fix:** split into `write_snapshot_overwrite` / `append_snapshot`, or make the mode an explicit `mode="overwrite|append"` kwarg.

#### N4. GUI IPC has no session token — roadmap 3.2 is the right fix
**Severity:** Medium
**File:** `cd_sniffer/ipc.py:114-139`

Roadmap 3.2 already flags this: any local process can connect to the GUI's localhost socket and issue `start`, `stop`, `apply-settings`, etc. The PID-liveness check from audit point 2.7 was *not* implemented (PID is written but never verified). Combined, this means:
- A crashed GUI leaves a stale state file (no PID check).
- Any other process can read the state file and control the GUI (no token).

**Fix:** add a 32-byte random token to the state file; `send_gui_command` must include it in the request body; GUI ignores requests with a missing/wrong token. Roadmap 3.2 already specifies this.

#### N5. Hotkey polling silently clamps `--interval`
**Severity:** Low-Medium
**File:** `cd_sniffer/cli.py:772, 782`

In hotkey mode, `time.sleep(max(0.05, min(args.interval, 0.25)))` caps `--interval` at 0.25 seconds without telling the user. A user setting `--interval 5.0 --mode hotkey` for "slower polling" gets a 4Hz poll loop instead of the expected 0.2Hz. Loop mode honors `--interval` exactly.

**Fix:** either remove the cap, log a warning at startup (`"Hotkey polling interval clamped from 5.0 to 0.25s"`), or rename the relevant knob to `--hotkey-poll-interval`.

#### N6. `resolve_pid` re-enumerates all windows on process-name fallback
**Severity:** Low
**File:** `cd_sniffer/core.py:87-93`

If `find_pids_by_process_name` returns nothing, lines 87-93 iterate `enum_windows()` again and for each window match against `process_name.lower() in title.lower()`. Since the first lookup already considered process name, this is a second pass over the same window list doing the same lower-case substring match. With many windows open, this adds visible latency on cold-start.

**Fix:** collect windows once, then run both PID lookup strategies in a single pass.

#### N7. `rpds-py 0.30.0` failure breaks `jsonschema` import — schema tests fail silently
**Severity:** Medium (test infrastructure)
**Files:** `tests/test_scanner.py` (schema validation tests), `cd_sniffer/schema_validation.py:28-30`

In any venv where `rpds-py==0.30.0` is installed but its native wheel is broken for the platform/Python combo, `import jsonschema` raises `ModuleNotFoundError: No module named 'rpds.rpds'`. `schema_validation.validate_payload_schema` then raises `RuntimeError("Schema validation requires ... pip install jsonschema")` — which is *misleading* because jsonschema IS installed; rpds is the missing dep. Two tests fail (`test_schema_validation_accepts_archive_index_report`, `test_schema_validation_rejects_invalid_payload`) but the error message points the user at the wrong package.

**Fix:** `validate_payload_schema` should catch `ImportError` from the chained `referencing`/`rpds` import chain and surface the real missing module name. Add a CI matrix for `rpds-py` versions, or pin `rpds-py>=0.20` in `[project.optional-dependencies.schema]`.

#### N8. Interactive PID prompt fires unconditionally on TTY with no opt-out
**Severity:** Low
**File:** `cd_sniffer/cli.py:684-685`

If `resolve_pid` returns None and stdin is a TTY, the CLI calls `prompt_for_window` even when the user didn't pass `--pick-window`. A wrapper script that wants non-interactive failure (e.g., a scheduled task that polls until the game launches) has to redirect stdin from `< /dev/null`, which works on Unix but is awkward on Windows.

**Fix:** add `--no-interactive` / `--no-prompt` flag that suppresses the TTY prompt and returns None (or errors) instead.

#### N9. `build_dmm_conflict_report` is O(n²) and has no scaling guard
**Severity:** Low
**File:** `cd_sniffer/dmm.py:147-181`

Both loops (candidate vs against-records, and candidate-internal) are nested with no grouping. For 500 candidate changes × 50 against-mods × 100 changes each = 2.5M comparisons; still fast on modern CPUs but the function does no early termination on `game_file` mismatch.

**Fix:** index `against_records` by `game_file` first; only compare candidates whose `game_file` is in the against-index. Same for internal.

#### N10. DMM patch draft always emits `"patched": ""`
**Severity:** Low-Medium
**File:** `cd_sniffer/dmm.py:64-71`

`build_dmm_patch_draft` puts `patched_placeholder` (default `""`) into every patch's `patched` field. The modinfo warning acknowledges this, but every draft is non-functional until a human fills in values. No CLI flag derives `patched` from a baseline-capture vs target-capture diff (which would work: byte at offset X in capture A is `original`, byte at offset X in capture B is `patched`).

**Fix:** add `--dmm-auto-fill-from <baseline>` that uses `correlate_capture_to_files` with a baseline to fill `patched` with the corresponding bytes from the baseline capture.

#### N11. CLI `main()` still repeats 5 copy-pasted render+write blocks
**Severity:** Low
**File:** `cd_sniffer/cli.py:401-414, 464-477, 522-535, 601-614, 648-661`

Every command branch has the same `if fmt == csv: render_csv ... elif markdown: ... else json: ...` + `if output_path: write_text else print` pattern, five times. Adding a new output format requires editing each block.

**Fix:** extract `render_payload(payload, fmt, schema_name)` and `emit_or_write(content, output_path)` helpers; let `main()` dispatch to command-specific handlers that return `(payload, schema_name)`.

#### N12. CLI `main()` repeats path-validation logic 4 times
**Severity:** Low
**File:** `cd_sniffer/cli.py:381-432, 552-571`

`archive_roots`/`paz_dir`/`capture_path` existence checks are duplicated across `archive_index`, `archive_list/extract`, and `correlate_files` branches. A new command that needs the same validations would copy them again.

**Fix:** extract `validate_archive_inputs(roots, paz_dir) -> None` and `validate_capture_inputs(capture, baseline, repeats) -> None`.

#### N13. `read_memory` returns partial buffer without flagging partial reads
**Severity:** Cosmetic
**File:** `cd_sniffer/windows.py:126-138`

`ReadProcessMemory` can succeed with `bytes_read.value < size` (e.g., at a region boundary). The function returns `bytes(buffer[: bytes_read.value])` — callers cannot distinguish "full read of N bytes" from "partial read of N bytes when M were requested".

**Fix:** add a `MemoryReadResult` dataclass with `data`, `requested_size`, `actual_size`, `partial: bool`. Update callers to surface partial-read cases in capture metadata.

#### N14. Env-var typo on `CDSNIFFER_VALIDATE_SCHEMAS` is silent
**Severity:** Cosmetic
**File:** `cd_sniffer/schema_validation.py:21-23`

`CDSNIFFER_VALDIATE_SCHEMAS=1` (typo) is silently ignored — the env var name is just a string lookup, no warning. Users debugging why validation is not running have to read the source to confirm the exact spelling.

**Fix:** log a warning at CLI startup if the env var name is set with an unrecognized value (already covered by current logic for `0`/`false`); also accept a fuzzy match against the var name and warn.

#### N15. `correlator.py` and `format_analyzers.py` not directly re-audited
**Severity:** N/A
**Files:** `cd_sniffer/correlator.py` (802 lines), `cd_sniffer/format_analyzers.py` (481 lines)

Both modules were not exhaustively re-reviewed in this pass. The first audit's high-level notes still apply: confidence scoring is principled, but no new tests were added for the format analyzer "domain paths" / "nearby sequence labels" hints introduced since the first audit. Recommend a focused third pass with `test_format_analyzers.py` coverage.

#### N16. `paz_archive.py` sample-pack fallback safety net is intentionally narrow
**Severity:** Low (design note)
**File:** `cd_sniffer/paz_archive.py`, `cd_sniffer/archive_index.py:323`

Sample-pack fallback is exact-match only — if a future game update changes even one byte of the compressed payload, the sample does not match and decoding fails. Roadmap 3.6 acknowledges this. Worth adding a CLI flag to surface which sample pack (if any) decoded each entry so users can identify gaps early.

#### N17. Hotkey capture widget + capture worker — read-races on shared state
**Severity:** Low (cosmetic)
**File:** `cd_sniffer/gui.py:851-1058` (`CaptureWorker`)

The capture worker thread reads `MainWindow` settings on every snapshot via signals/slots. If the user edits settings mid-capture, the worker uses a snapshot of settings from when the signal was emitted. Documented as expected behavior, but the "Capture in progress" indicator doesn't reflect a settings edit that arrived mid-capture. Not a bug, but worth a hover-tip note.

### New Features Worth Adding

#### F1. PID liveness + auth token for GUI IPC (consolidates roadmap 3.2)
**Priority:** High
Combines audit point 2.7 + roadmap 3.2 into one change. 32-byte token in state file; PID check via `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION`; reject stale state file at first IPC connect.

#### F2. Markdown snapshot append consistency
**Priority:** Medium
Strip heading + metadata block on markdown append like CSV does for its header. Or write a fresh `.md` per snapshot when `--timestamp-output` is set.

#### F3. DMM auto-fill from baseline
**Priority:** Medium
New `--dmm-auto-fill-from <baseline-capture>` that derives `patched` from baseline capture bytes at the same offset. Removes the empty-placeholder problem (N10).

#### F4. GUI settings → manifest redaction registry
**Priority:** Medium
Replace hardcoded `{"pid"}` exclusion in `sanitize_manifest_value` with an explicit redaction registry on the argparse parser. Settings that hold paths, credentials, or PII register themselves for redaction.

#### F5. Capture metadata for partial reads
**Priority:** Low
Surface partial `ReadProcessMemory` cases so the GUI can warn the user when a region was unreadable at the moment of capture (transient guard pages, copy-on-write init, etc.).

#### F6. Format analyzer test coverage
**Priority:** Medium
Add `tests/test_format_analyzers.py` covering domain path detection, mission/quest JSON records, PASEQ timing values, sequence labels, and CRC/hash candidates. Roadmap 3.6 mentions this indirectly.

#### F7. Capture-gate case-insensitivity documentation + PascalCase keyword aliases
**Priority:** Low
Add README note about case behavior. Optionally ship PascalCase variants of the default mission-gate keywords in `core.py:CAMP_MISSION_GATE_KEYWORDS` so they match in-memory `Quest_Node_*` strings.

#### F8. `--no-interactive` CLI flag
**Priority:** Low
Suppress TTY PID prompt; fail with a clear error code instead. Useful for scheduled-task wrappers and CI.

#### F9. CLI handler extraction
**Priority:** Low
Extract each `if args.foo:` branch in `main()` into `handle_<command>(args) -> int`. Audit point 2.2 maintainer-deferred; revisit after schema/CLI behavior settles.

#### F10. DMM report streaming output
**Priority:** Low
For very large `--dmm-against` lists, stream the conflict report rather than materializing the full `conflicts` + `internal_conflicts` lists in memory. Index by `game_file` first (N9).

#### F11. GUI capture settings preview freshness
**Priority:** Low
When settings change mid-capture, surface a "settings will apply on next snapshot" hint instead of letting the indicator silently disagree with reality (N17).

#### F12. `correlator.py` and `format_analyzers.py` focused third-pass audit
**Priority:** Low
These two modules grew substantially (correlator: 802 lines, format_analyzers: 481 lines) since the first audit. A focused third pass with new test coverage would surface any regressions.

### Updated Top-5 Priority Improvements (post-update)

1. **GUI IPC auth token + PID liveness** (N4, roadmap 3.2, audit 2.7) — security
2. **Markdown append consistency** (N1) — correctness, easy fix
3. **CLI handler extraction** (N11, N12, audit 2.2) — maintainability
4. **Manifest redaction registry** (N2) — privacy/forward-compat
5. **rpds-py / jsonschema test infra** (N7) — test reliability

### Updated Top-5 Priority New Features (post-update)

1. **DMM auto-fill from baseline** (F3) — biggest practical win for DMM users
2. **GUI IPC auth token + PID check** (F1, N4) — security foundation
3. **Format analyzer test coverage** (F6) — protects growing analyzer surface
4. **Capture metadata for partial reads** (F5) — diagnostic depth
5. **Build/release script** (roadmap 3.1) — unlocks shipping

---

## Audit Update — July 8, 2026 (Codex Verification)

**Scope:** verified the MiniMax-M3 second-pass audit against current `main` after the archive path fix and the hotkey/archive-progress fix. This pass focused on whether the findings are still accurate, which findings should move up the backlog, and which notes need correction before another agent uses this report as a handoff.

**Verification run:** `python -m unittest discover -s tests` passed 63 tests. `jsonschema==4.26.0` imports successfully in the current environment, and `rpds` also imports successfully. Current approximate file sizes are `gui.py` 4,129 lines, `cli.py` 791 lines, and `tests/test_scanner.py` 1,084 lines.

### Codex Verdict On MiniMax-M3 Findings

MiniMax-M3's audit is high-signal and should be treated as the active backlog foundation. The strongest confirmed findings are:

- **N4 / F1 GUI IPC auth token + PID liveness:** confirmed and now the highest-priority hardening item. `ipc.py` writes `pid`, but `send_gui_command()` still does not verify that PID or authenticate requests.
- **N1 Markdown snapshot append consistency:** confirmed. The current markdown writer appends a complete snapshot document each time. This is readable as repeated sections, but not a clean session table or session report. Fix should define the intended markdown append format explicitly.
- **N2 Manifest redaction registry:** confirmed. `sanitize_manifest_value()` currently redacts only `pid`; a named redaction set or explicit manifest allow-list would age better.
- **N9 DMM conflict scaling:** confirmed with a nuance. `_dmm_overlap()` does early-return on `game_file` mismatch, but every candidate/existing pair is still visited. Indexing records by normalized `game_file` is still the right fix.
- **N10 DMM patched placeholders:** confirmed. The current draft generator is honest about requiring review, but practical DMM workflows would benefit from a baseline/target auto-fill path.
- **N8 `--no-interactive`:** confirmed. The CLI still prompts on TTY when auto PID detection fails; a non-interactive flag would help scripts and scheduled runs.
- **N11/N12 CLI handler and validation extraction:** confirmed, but should happen after the near-term security and DMM workflow fixes.

### Corrections And Stale Items

- **Original 2.3 type annotations:** mostly stale. The specific functions MiniMax lists (`search_payload_values`, `search_flattened_hits`, `search_capture_file`, `search_capture_directory`, `flatten_hits`, `build_manifest`) already have parameter and return annotations. The remaining improvement is richer typed payload models instead of broad `dict[str, Any]`, not "missing annotations."
- **N5 hotkey polling:** partially stale after `7645e45 fix: improve hotkey capture and archive progress`. GUI and CLI now use `is_key_triggered()` (`GetAsyncKeyState & 0x8001`) so quick taps are less likely to be missed. The interval clamp is still real and should be documented or split into an explicit hotkey poll interval.
- **Archive index progress:** addressed after the MiniMax pass. `build_archive_index()` now accepts a progress callback, and the GUI worker emits indexed-entry progress updates. Keep this off the open-findings list unless real use testing shows progress is too noisy or too sparse.
- **N7 `rpds-py` schema failure:** not reproduced here. The current environment imports `jsonschema` and `rpds`, and the schema tests pass. The recommendation remains useful: if a transitive `jsonschema` dependency import fails, `validate_payload_schema()` should surface the real missing module rather than only suggesting `pip install jsonschema`.
- **N17 capture worker read-races:** current description is inaccurate. `CaptureWorker` receives a settings snapshot when capture starts and does not read `MainWindow` state on each snapshot. The real UX issue is that settings edits made through any path during an active capture will not affect that running worker until capture restarts.
- **N6 PID fallback latency:** valid as a performance concern, but the wording should be adjusted. The code does not re-enumerate the same window list after `tasklist`; it first shells out to `tasklist`, then falls back to `enum_windows()`. A native Windows process lookup would be cleaner than both.
- **N1 markdown "malformed table" wording:** the output is valid markdown with repeated snapshot sections, not necessarily a malformed single table. The issue is session readability and predictable append semantics.

### Codex Priority Recommendation

1. **GUI IPC auth token + PID liveness** - closes the only meaningful local-control/security gap.
2. **Markdown append semantics + explicit write mode naming** - small correctness fix with low blast radius.
3. **DMM baseline auto-fill + conflict indexing by file** - highest practical value for mod authors.
4. **Manifest redaction registry + schema transitive-import diagnostics** - improves future safety and supportability.
5. **Format analyzer coverage** - protect the growing binary/JSON hint surface before adding more heuristics.
6. **CLI handler extraction** - worthwhile cleanup once the above behavior is stable.

---

## Table of Contents

0. [Maintainer Follow-Up](#maintainer-follow-up)
0a. [Audit Update — July 7, 2026 (Second Pass)](#audit-update--july-7-2026-second-pass)
0b. [Audit Update — July 8, 2026 (Codex Verification)](#audit-update--july-8-2026-codex-verification)
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
