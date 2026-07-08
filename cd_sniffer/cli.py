from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any

from .archive_index import (
    build_archive_index,
    correlate_capture_to_archive,
    render_archive_correlation_csv,
    render_archive_correlation_markdown,
    render_archive_index_csv,
    render_archive_index_markdown,
)
from .correlator import (
    correlate_capture_to_files,
    render_correlation_csv,
    render_correlation_markdown,
)
from .core import (
    CAPTURE_GATE_MATCH_MODES,
    CAPTURE_GATE_MODES,
    build_comparison,
    build_keywords,
    build_manifest,
    capture_gate_matches,
    capture_once,
    close_handle,
    filter_payload_unique_hits,
    finalize_payload,
    list_windows,
    log_message,
    load_signature_pack,
    merge_signature_packs,
    open_process,
    prompt_for_window,
    print_summary,
    render_search_results_csv,
    render_search_results_markdown,
    search_capture_file,
    search_capture_directory,
    resolve_pid,
    timestamped_output_path,
    validate_regex_patterns,
    vk_from_name,
    write_manifest,
    write_rendered_snapshot,
    write_snapshot,
)
from .dmm import (
    build_dmm_conflict_report,
    load_correlation_result,
    render_dmm_conflict_csv,
    render_dmm_conflict_markdown,
    render_dmm_patch_draft,
)
from .ipc import send_gui_command
from .paz_archive import (
    build_archive_report,
    load_decoder_samples,
    extract_entries,
    filter_archive_entries,
    load_archive_entries,
    render_archive_csv,
    render_archive_markdown,
)
from .paths import project_logs_dir, project_root, resolve_project_path
from .schema_validation import schema_validation_requested, validate_payload_schema
from .windows import is_key_triggered


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CDSniffer - Crimson Desert runtime memory logger")
    parser.add_argument("--pid", type=int, help="Process ID to attach to")
    parser.add_argument("--gui", action="store_true", help="Launch the GUI instead of running a capture")
    parser.add_argument(
        "--gui-command",
        choices=["status", "show", "hide", "start", "stop", "open-settings", "refresh", "select-tab", "apply-settings"],
        help="Send a command to a running GUI",
    )
    parser.add_argument("--gui-tab", help="Tab name used with --gui-command select-tab")
    parser.add_argument("--gui-settings-file", help="JSON settings file used with --gui-command apply-settings")
    parser.add_argument("--process", default="Crimson Desert", help="Process name fragment to locate")
    parser.add_argument("--window-title", action="append", dest="window_titles", help="Window title fragment to locate")
    parser.add_argument("--window-filter-regex", action="append", dest="window_filter_patterns", help="Regex that must match the window title")
    parser.add_argument("--pick-window", action="store_true", help="Interactively choose from matching windows")
    parser.add_argument("--no-interactive", action="store_true", help="Do not prompt for a window when automatic PID detection fails")
    parser.add_argument("--list-windows", action="store_true", help="List matching windows and exit")
    parser.add_argument("--mode", choices=["once", "loop", "hotkey"], default="loop", help="Capture mode")
    parser.add_argument("--hotkey", default="F8", help="Polling hotkey for hotkey mode")
    parser.add_argument(
        "--hotkey-poll-interval",
        type=float,
        help="Seconds between hotkey state checks; defaults to --interval clamped between 0.05 and 0.25 seconds",
    )
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between loop captures")
    parser.add_argument("--captures", type=int, help="Stop after this many captures")
    parser.add_argument("--output", default="logs/cdsniffer.jsonl", help="Output file path")
    parser.add_argument("--timestamp-output", action="store_true", help="Append a UTC timestamp to the output filename")
    parser.add_argument("--session-name", default="cdsniffer", help="Base name used when timestamped output is enabled")
    parser.add_argument("--format", choices=["jsonl", "json", "csv", "markdown"], default="jsonl", help="Output format")
    parser.add_argument("--label", default="capture", help="Label to tag each snapshot")
    parser.add_argument("--game-version", default="", help="Optional game version metadata to store with the capture")
    parser.add_argument("--include-keyword", action="append", dest="include_keywords", help="Extra keyword to include")
    parser.add_argument("--exclude-keyword", action="append", dest="exclude_keywords", help="Keyword to exclude")
    parser.add_argument("--include-regex", action="append", dest="include_patterns", help="Regex that must match a hit")
    parser.add_argument("--exclude-regex", action="append", dest="exclude_patterns", help="Regex that removes a hit")
    parser.add_argument("--signature-pack", action="append", dest="signature_packs", help="Load extra filters from a file")
    parser.add_argument("--max-region-size", type=int, default=16 * 1024 * 1024, help="Skip regions larger than this many bytes")
    parser.add_argument("--max-regions", type=int, help="Stop after scanning this many matching regions")
    parser.add_argument("--max-hits-per-region", type=int, help="Stop after this many hits in a single region")
    parser.add_argument("--context-bytes", type=int, default=0, help="Capture this many bytes before and after each matched string")
    parser.add_argument("--decode-context-numbers", action="store_true", help="Decode nearby integer candidates inside captured byte context")
    parser.add_argument("--context-number-radius", type=int, default=16, help="Bytes around each hit to inspect for numeric candidates")
    parser.add_argument(
        "--capture-gate",
        choices=CAPTURE_GATE_MODES,
        default="off",
        help="Only capture when a memory sentinel is present; camp-mission waits for camp dispatch UI strings",
    )
    parser.add_argument(
        "--capture-gate-match",
        choices=CAPTURE_GATE_MATCH_MODES,
        default="any",
        help="Gate matching strategy for the selected capture gate",
    )
    parser.add_argument("--gate-keyword", action="append", dest="gate_keywords", help="Extra keyword used by the capture gate")
    parser.add_argument("--gate-regex", action="append", dest="gate_patterns", help="Regex used by the capture gate")
    parser.add_argument("--gate-max-regions", type=int, default=6, help="Maximum matching memory regions to inspect for the capture gate")
    parser.add_argument("--gate-max-hits-per-region", type=int, default=1, help="Maximum gate hits to read from each matching region")
    parser.add_argument("--unique-only", action="store_true", help="Only write new unique hit text values during this session")
    parser.add_argument("--summary", choices=["none", "top-hits"], default="none", help="Print a live capture summary")
    parser.add_argument("--summary-limit", type=int, default=10, help="How many top hits to show in summary mode")
    parser.add_argument("--compare-last", action="store_true", help="Show the diff from the previous capture")
    parser.add_argument("--compare-limit", type=int, default=20, help="How many added/removed strings to display")
    parser.add_argument("--export-manifest", action="store_true", help="Write session metadata next to the output file")
    parser.add_argument("--quiet", action="store_true", help="Reduce non-essential console output")
    parser.add_argument("--verbose", action="store_true", help="Print extra capture diagnostics")
    parser.add_argument("--watch-pattern", action="append", dest="watch_patterns", help="Regex that triggers an alert when matched")
    parser.add_argument("--note", action="append", dest="notes", help="Freeform note to save with the capture session")
    parser.add_argument("--search", help="Search an existing capture file and exit")
    parser.add_argument("--search-file", help="Capture file to search; defaults to --output")
    parser.add_argument("--search-dir", help="Search all capture files inside a directory and exit")
    parser.add_argument("--search-recursive", action="store_true", default=True, help="Recursively search subfolders when using --search-dir")
    parser.add_argument("--search-no-recursive", action="store_false", dest="search_recursive", help="Only search the top level when using --search-dir")
    parser.add_argument(
        "--search-glob",
        action="append",
        dest="search_globs",
        help="File glob to include when searching a directory; may be repeated",
    )
    parser.add_argument("--search-regex", action="store_true", help="Treat --search as a regular expression")
    parser.add_argument("--search-case-sensitive", action="store_true", help="Make --search case-sensitive")
    parser.add_argument("--search-limit", type=int, default=200, help="Maximum number of matches to return")
    parser.add_argument("--search-format", choices=["json", "csv", "markdown"], default="json", help="Format used for search results")
    parser.add_argument("--search-output", help="Optional file path to write search results instead of printing them")
    parser.add_argument("--correlate-capture", help="Capture JSON/JSONL file to correlate against unpacked files")
    parser.add_argument("--correlate-target", help="Target capture JSON/JSONL file for baseline-vs-target correlation")
    parser.add_argument("--correlate-baseline", help="Optional baseline capture JSON/JSONL file for diff correlation")
    parser.add_argument("--correlate-repeat", action="append", dest="correlate_repeats", help="Additional target capture JSON/JSONL file for repeat-run confidence rollups; may be repeated")
    parser.add_argument("--correlate-root", help="Root directory of unpacked/game files to scan")
    parser.add_argument("--correlate-file", action="append", dest="correlate_files", help="Specific unpacked/decoded file to scan; may be repeated")
    parser.add_argument("--correlate-recursive", action="store_true", default=True, help="Recursively scan subfolders for correlation")
    parser.add_argument("--correlate-no-recursive", action="store_false", dest="correlate_recursive", help="Only scan the top level for correlation")
    parser.add_argument("--correlate-glob", action="append", dest="correlate_globs", help="File glob to include during correlation; may be repeated")
    parser.add_argument("--correlate-max-file-size", type=int, default=64 * 1024 * 1024, help="Skip files larger than this many bytes during correlation")
    parser.add_argument("--correlate-max-matches", type=int, default=500, help="Maximum total correlation matches to return")
    parser.add_argument("--correlate-max-matches-per-evidence", type=int, default=20, help="Maximum file offsets per evidence item")
    parser.add_argument("--correlate-no-numeric", action="store_false", dest="correlate_numeric", default=True, help="Do not correlate decoded numeric candidate bytes")
    parser.add_argument("--correlate-context-bytes", type=int, default=16, help="Bytes around each file match to include in correlation output")
    parser.add_argument("--correlate-no-format-hints", action="store_false", dest="correlate_format_hints", default=True, help="Skip JSON/text/binary format hints during correlation")
    parser.add_argument("--correlate-format", choices=["json", "csv", "markdown"], default="json", help="Format used for correlation results")
    parser.add_argument("--correlate-output", help="Optional file path to write correlation results instead of printing them")
    parser.add_argument("--dmm-export", help="Correlation JSON report to convert into a DMM byte-patch draft")
    parser.add_argument("--dmm-output", help="Output path for --dmm-export")
    parser.add_argument("--dmm-title", default="CDSniffer Patch Draft", help="DMM draft mod title")
    parser.add_argument("--dmm-version", default="0.1.0", help="DMM draft mod version")
    parser.add_argument("--dmm-author", default="CDSniffer", help="DMM draft mod author")
    parser.add_argument("--dmm-patched-placeholder", default="", help="Placeholder hex string for each DMM patched value")
    parser.add_argument("--dmm-check", help="DMM JSON draft/mod to check for byte-range conflicts")
    parser.add_argument("--dmm-against", action="append", dest="dmm_against", help="Existing DMM JSON mod to check against; may be repeated")
    parser.add_argument("--dmm-check-format", choices=["json", "csv", "markdown"], default="json", help="Format used for DMM conflict reports")
    parser.add_argument("--dmm-check-output", help="Optional file path to write DMM conflict report")
    parser.add_argument("--correlate-archive", help="Capture JSON/JSONL file to correlate against indexed PAMT/PAZ archive entries")
    parser.add_argument("--correlate-archive-index", help="Archive index database to use; defaults to --archive-index-db")
    parser.add_argument("--correlate-archive-cache", default=str(project_logs_dir() / "archive-cache"), help="Decoded archive cache directory for archive correlation")
    parser.add_argument("--correlate-archive-glob", action="append", dest="correlate_archive_globs", help="Archive entry glob to include during archive correlation; may be repeated")
    parser.add_argument("--correlate-archive-term", action="append", dest="correlate_archive_terms", help="Archive path substring to include during archive correlation; may be repeated")
    parser.add_argument("--correlate-archive-max-entries", type=int, default=2000, help="Maximum indexed archive entries to decode during archive correlation")
    parser.add_argument("--correlate-archive-no-decrypt", action="store_true", help="Do not decrypt XML entries while correlating against archive entries")
    parser.add_argument("--archive-root", action="append", dest="archive_roots", help="Game/archive root or .pamt file to inspect; may be repeated")
    parser.add_argument("--archive-paz-dir", help="Directory containing .paz files when --archive-root is a standalone .pamt")
    parser.add_argument("--archive-list", action="store_true", help="List PAMT/PAZ entries using the built-in parser")
    parser.add_argument("--archive-extract", action="store_true", help="Extract matching PAMT/PAZ entries using the built-in unpacker")
    parser.add_argument("--archive-index", action="store_true", help="Build a reusable SQLite index of PAMT/PAZ archive entries")
    parser.add_argument("--archive-index-db", default=str(project_logs_dir() / "cdsniffer-archive-index.sqlite"), help="SQLite database path used by --archive-index and archive correlation")
    parser.add_argument("--archive-filter", action="append", dest="archive_filters", help="Archive entry glob or substring filter; may be repeated")
    parser.add_argument("--archive-limit", type=int, help="Maximum archive entries to list or extract")
    parser.add_argument("--archive-all", action="store_true", help="Allow extracting all matched entries when no filter or limit is supplied")
    parser.add_argument("--archive-output", help="Output directory for --archive-extract")
    parser.add_argument("--archive-report-output", help="Optional file path to write archive list/extract report")
    parser.add_argument("--archive-format", choices=["json", "csv", "markdown"], default="json", help="Format used for archive reports")
    parser.add_argument("--archive-no-decrypt", action="store_true", help="Do not decrypt XML entries during archive extraction")
    parser.add_argument("--archive-dry-run", action="store_true", help="Show what would be extracted without writing files")
    parser.add_argument("--archive-validate", action="store_true", help="Read, decrypt, and decode matching archive entries without writing files")
    parser.add_argument(
        "--decoder-sample",
        action="append",
        dest="decoder_samples",
        help="Decoder sample manifest or folder used as an exact-match fallback for future PAZ compression payloads",
    )
    parser.add_argument("--validate-schemas", action="store_true", help="Validate generated JSON payloads against bundled schemas before writing or printing")
    return parser.parse_args()


def validate_result_if_requested(args: argparse.Namespace, schema_name: str, payload: dict[str, Any]) -> None:
    if schema_validation_requested(bool(getattr(args, "validate_schemas", False))):
        validate_payload_schema(payload, schema_name)


def load_optional_decoder_samples(args: argparse.Namespace) -> list[Any]:
    sample_roots = [Path(item) for item in getattr(args, "decoder_samples", []) or []]
    if not sample_roots:
        return []
    for sample_root in sample_roots:
        if not sample_root.exists():
            raise FileNotFoundError(f"Decoder sample path not found: {sample_root}")
    return load_decoder_samples(sample_roots)


def prepare_capture_payload(
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

    if args.unique_only:
        payload = filter_payload_unique_hits(payload, seen_texts)
        if payload.get("hit_count", 0) <= 0:
            return None, "No new unique hits; snapshot skipped."

    return finalize_payload(payload, args, output_path, previous_payload), None


def write_and_report_payload(args: argparse.Namespace, output_path: Path, payload: dict[str, Any]) -> None:
    validate_result_if_requested(args, "capture", payload)
    if args.format in {"csv", "markdown"}:
        write_rendered_snapshot(output_path, payload, args.format)
    else:
        write_snapshot(output_path, payload, args.format)
    print_summary(args, payload, args.summary, args.summary_limit)
    if payload.get("watch_hits"):
        log_message(args, f"Watch hit: {', '.join(payload['watch_hits'])}")
    if args.compare_last and "comparison" in payload:
        comparison = payload["comparison"]
        log_message(
            args,
            f"Compare-last: +{comparison['added_count']} / -{comparison['removed_count']}",
            verbose_only=True,
        )
        if args.verbose:
            added = ", ".join(comparison["added"])
            removed = ", ".join(comparison["removed"])
            if added:
                log_message(args, f"  Added: {added}", verbose_only=True)
            if removed:
                log_message(args, f"  Removed: {removed}", verbose_only=True)


def main() -> int:
    args = parse_args()
    decoder_samples: list[Any] | None = None

    def get_decoder_samples() -> list[Any]:
        nonlocal decoder_samples
        if decoder_samples is None:
            decoder_samples = load_optional_decoder_samples(args)
        return decoder_samples

    if args.gui_command:
        payload: dict[str, Any] | None = None
        if args.gui_command == "select-tab":
            payload = {"tab": args.gui_tab}
        elif args.gui_command == "apply-settings":
            if not args.gui_settings_file:
                print("--gui-settings-file is required with --gui-command apply-settings")
                return 1
            try:
                settings_data = Path(args.gui_settings_file).read_text(encoding="utf-8")
                payload = {"settings": json.loads(settings_data)}
            except Exception as exc:
                print(f"Failed to load GUI settings file: {exc}")
                return 1
        result = send_gui_command(args.gui_command, payload)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.gui:
        from .gui import main as gui_main

        return gui_main()

    if args.list_windows:
        return list_windows(args)

    if args.dmm_export:
        source_path = Path(args.dmm_export)
        if not source_path.exists():
            print(f"Correlation report not found: {source_path}")
            return 1
        try:
            result = load_correlation_result(source_path)
            rendered = render_dmm_patch_draft(
                result,
                title=args.dmm_title,
                version=args.dmm_version,
                author=args.dmm_author,
                patched_placeholder=args.dmm_patched_placeholder,
            )
        except Exception as exc:
            print(f"DMM export failed: {exc}")
            return 1
        if args.dmm_output:
            out_path = Path(args.dmm_output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
            print(json.dumps({"written": str(out_path), "format": "dmm-draft"}, ensure_ascii=False, indent=2))
        else:
            print(rendered, end="")
        return 0

    if args.dmm_check:
        candidate_path = Path(args.dmm_check)
        against_paths = [Path(item) for item in args.dmm_against or []]
        if not candidate_path.exists():
            print(f"DMM candidate file not found: {candidate_path}")
            return 1
        for path in against_paths:
            if not path.exists():
                print(f"DMM comparison file not found: {path}")
                return 1
        try:
            result = build_dmm_conflict_report(candidate_path, against_paths)
        except Exception as exc:
            print(f"DMM conflict check failed: {exc}")
            return 1
        if args.dmm_check_format == "csv":
            rendered = render_dmm_conflict_csv(result)
        elif args.dmm_check_format == "markdown":
            rendered = render_dmm_conflict_markdown(result)
        else:
            rendered = json.dumps(result, ensure_ascii=False, indent=2)
        if args.dmm_check_output:
            out_path = Path(args.dmm_check_output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
            print(json.dumps({"written": str(out_path), "format": args.dmm_check_format, "has_conflicts": result["has_conflicts"]}, ensure_ascii=False, indent=2))
        else:
            print(rendered, end="" if rendered.endswith("\n") else "\n")
        return 2 if result["has_conflicts"] else 0

    if args.archive_index:
        if not args.archive_roots:
            print("--archive-root is required with --archive-index")
            return 1
        if args.archive_limit is not None and args.archive_limit < 1:
            print("--archive-limit must be at least 1")
            return 1
        archive_roots = [Path(item) for item in args.archive_roots]
        paz_dir = Path(args.archive_paz_dir) if args.archive_paz_dir else None
        for archive_root in archive_roots:
            if not archive_root.exists():
                print(f"Archive root not found: {archive_root}")
                return 1
        if paz_dir is not None and not paz_dir.exists():
            print(f"Archive PAZ directory not found: {paz_dir}")
            return 1
        try:
            index_db = resolve_project_path(args.archive_index_db, base_dir=project_root())
            result = build_archive_index(
                index_db,
                archive_roots,
                paz_dir=paz_dir,
                patterns=args.archive_filters,
                limit=args.archive_limit,
            )
        except Exception as exc:
            print(f"Archive index failed: {exc}")
            return 1

        validate_result_if_requested(args, "archive-index", result)
        if args.archive_format == "csv":
            rendered = render_archive_index_csv(result)
        elif args.archive_format == "markdown":
            rendered = render_archive_index_markdown(result)
        else:
            rendered = json.dumps(result, ensure_ascii=False, indent=2)
        if args.archive_report_output:
            out_path = resolve_project_path(args.archive_report_output, base_dir=project_root())
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
            print(json.dumps({"written": str(out_path), "format": args.archive_format}, ensure_ascii=False, indent=2))
        else:
            print(rendered)
        return 0

    if args.archive_list or args.archive_extract:
        if not args.archive_roots:
            print("--archive-root is required with --archive-list or --archive-extract")
            return 1
        if args.archive_limit is not None and args.archive_limit < 1:
            print("--archive-limit must be at least 1")
            return 1
        archive_roots = [Path(item) for item in args.archive_roots]
        paz_dir = Path(args.archive_paz_dir) if args.archive_paz_dir else None
        for archive_root in archive_roots:
            if not archive_root.exists():
                print(f"Archive root not found: {archive_root}")
                return 1
        if paz_dir is not None and not paz_dir.exists():
            print(f"Archive PAZ directory not found: {paz_dir}")
            return 1
        try:
            if args.archive_extract:
                if not args.archive_output and not (args.archive_dry_run or args.archive_validate):
                    print("--archive-output is required with --archive-extract")
                    return 1
                if not args.archive_filters and args.archive_limit is None and not args.archive_all:
                    print("--archive-extract without a filter or limit requires --archive-all")
                    return 1
                entries = load_archive_entries(archive_roots, paz_dir=paz_dir)
                entries = filter_archive_entries(entries, patterns=args.archive_filters, limit=args.archive_limit)
                result = extract_entries(
                    entries,
                    resolve_project_path(args.archive_output or ".", base_dir=project_root()),
                    decrypt_xml=not args.archive_no_decrypt,
                    dry_run=args.archive_dry_run or args.archive_validate,
                    validate_only=args.archive_validate,
                    decoder_samples=get_decoder_samples(),
                )
                result["roots"] = [str(root) for root in archive_roots]
                result["patterns"] = args.archive_filters or ["*"]
            else:
                result = build_archive_report(
                    archive_roots,
                    paz_dir=paz_dir,
                    patterns=args.archive_filters,
                    limit=args.archive_limit,
                )
        except Exception as exc:
            print(f"Archive operation failed: {exc}")
            return 1

        validate_result_if_requested(args, "archive", result)
        if args.archive_format == "csv":
            rendered = render_archive_csv(result)
        elif args.archive_format == "markdown":
            rendered = render_archive_markdown(result)
        else:
            rendered = json.dumps(result, ensure_ascii=False, indent=2)
        if args.archive_report_output:
            out_path = resolve_project_path(args.archive_report_output, base_dir=project_root())
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
            print(json.dumps({"written": str(out_path), "format": args.archive_format}, ensure_ascii=False, indent=2))
        else:
            print(rendered)
        return 0

    if args.correlate_archive:
        capture_path = Path(args.correlate_archive)
        index_path = resolve_project_path(args.correlate_archive_index or args.archive_index_db, base_dir=project_root())
        cache_path = resolve_project_path(args.correlate_archive_cache, base_dir=project_root())
        if not capture_path.exists():
            print(f"Capture file not found: {capture_path}")
            return 1
        if not index_path.exists():
            print(f"Archive index not found: {index_path}. Build it first with --archive-index.")
            return 1
        if args.correlate_archive_max_entries < 1:
            print("--correlate-archive-max-entries must be at least 1")
            return 1
        if args.correlate_max_matches < 1:
            print("--correlate-max-matches must be at least 1")
            return 1
        if args.correlate_max_matches_per_evidence < 1:
            print("--correlate-max-matches-per-evidence must be at least 1")
            return 1
        if args.correlate_context_bytes < 0:
            print("--correlate-context-bytes cannot be negative")
            return 1
        try:
            result = correlate_capture_to_archive(
                capture_path,
                index_path,
                cache_path,
                patterns=args.correlate_archive_globs,
                path_terms=args.correlate_archive_terms,
                max_entries=args.correlate_archive_max_entries,
                max_matches_per_evidence=args.correlate_max_matches_per_evidence,
                max_total_matches=args.correlate_max_matches,
                include_numeric=args.correlate_numeric,
                context_bytes=args.correlate_context_bytes,
                include_format_hints=args.correlate_format_hints,
                decrypt_xml=not args.correlate_archive_no_decrypt,
                decoder_samples=get_decoder_samples(),
            )
        except Exception as exc:
            print(f"Archive correlation failed: {exc}")
            return 1

        validate_result_if_requested(args, "archive-correlation", result)
        if args.correlate_format == "csv":
            rendered = render_archive_correlation_csv(result)
        elif args.correlate_format == "markdown":
            rendered = render_archive_correlation_markdown(result)
        else:
            rendered = json.dumps(result, ensure_ascii=False, indent=2)
        if args.correlate_output:
            out_path = Path(args.correlate_output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
            print(json.dumps({"written": str(out_path), "format": args.correlate_format}, ensure_ascii=False, indent=2))
        else:
            print(rendered)
        return 0

    target_capture_arg = args.correlate_target or args.correlate_capture
    if args.correlate_baseline and not target_capture_arg:
        print("--correlate-capture or --correlate-target is required with --correlate-baseline")
        return 1

    if target_capture_arg:
        if not args.correlate_root and not args.correlate_files:
            print("--correlate-root or --correlate-file is required with --correlate-capture or --correlate-target")
            return 1
        capture_path = Path(target_capture_arg)
        baseline_capture_path = Path(args.correlate_baseline) if args.correlate_baseline else None
        repeat_capture_paths = [Path(item) for item in args.correlate_repeats or []]
        selected_files = [Path(item) for item in args.correlate_files or []]
        root_path = Path(args.correlate_root) if args.correlate_root else selected_files[0].parent
        if not capture_path.exists():
            print(f"Capture file not found: {capture_path}")
            return 1
        if baseline_capture_path is not None and not baseline_capture_path.exists():
            print(f"Baseline capture file not found: {baseline_capture_path}")
            return 1
        for repeat_capture_path in repeat_capture_paths:
            if not repeat_capture_path.exists():
                print(f"Repeat capture file not found: {repeat_capture_path}")
                return 1
        for selected_file in selected_files:
            if not selected_file.exists() or not selected_file.is_file():
                print(f"Correlation file not found: {selected_file}")
                return 1
        if not root_path.exists() or not root_path.is_dir():
            print(f"Correlation root directory not found: {root_path}")
            return 1
        if args.correlate_max_file_size < 0:
            print("--correlate-max-file-size cannot be negative")
            return 1
        if args.correlate_max_matches < 1:
            print("--correlate-max-matches must be at least 1")
            return 1
        if args.correlate_max_matches_per_evidence < 1:
            print("--correlate-max-matches-per-evidence must be at least 1")
            return 1
        if args.correlate_context_bytes < 0:
            print("--correlate-context-bytes cannot be negative")
            return 1
        try:
            result = correlate_capture_to_files(
                capture_path,
                root_path,
                baseline_capture_path=baseline_capture_path,
                repeat_capture_paths=repeat_capture_paths,
                selected_files=selected_files or None,
                recursive=args.correlate_recursive,
                patterns=args.correlate_globs,
                max_file_size=args.correlate_max_file_size,
                max_matches_per_evidence=args.correlate_max_matches_per_evidence,
                max_total_matches=args.correlate_max_matches,
                include_numeric=args.correlate_numeric,
                context_bytes=args.correlate_context_bytes,
                include_format_hints=args.correlate_format_hints,
            )
        except Exception as exc:
            print(f"Correlation failed: {exc}")
            return 1

        validate_result_if_requested(args, "correlation", result)
        if args.correlate_format == "csv":
            rendered = render_correlation_csv(result)
        elif args.correlate_format == "markdown":
            rendered = render_correlation_markdown(result)
        else:
            rendered = json.dumps(result, ensure_ascii=False, indent=2)
        if args.correlate_output:
            out_path = Path(args.correlate_output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
            print(json.dumps({"written": str(out_path), "format": args.correlate_format}, ensure_ascii=False, indent=2))
        else:
            print(rendered)
        return 0

    if args.search:
        try:
            if args.search_dir:
                search_root = Path(args.search_dir)
                if not search_root.exists():
                    print(f"Search directory not found: {search_root}")
                    return 1
                result = search_capture_directory(
                    search_root,
                    args.search,
                    regex=args.search_regex,
                    case_sensitive=args.search_case_sensitive,
                    limit=args.search_limit,
                    recursive=args.search_recursive,
                    patterns=args.search_globs,
                )
            else:
                search_path = Path(args.search_file or args.output)
                if not search_path.exists():
                    print(f"Search file not found: {search_path}")
                    return 1
                result = search_capture_file(
                    search_path,
                    args.search,
                    regex=args.search_regex,
                    case_sensitive=args.search_case_sensitive,
                    limit=args.search_limit,
                )
        except Exception as exc:
            print(f"Search failed: {exc}")
            return 1
        rendered: str
        if args.search_format == "csv":
            rendered = render_search_results_csv(result)
        elif args.search_format == "markdown":
            rendered = render_search_results_markdown(result)
        else:
            rendered = json.dumps(result, ensure_ascii=False, indent=2)
        if args.search_output:
            out_path = Path(args.search_output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
            print(json.dumps({"written": str(out_path), "format": args.search_format}, ensure_ascii=False, indent=2))
        else:
            print(rendered)
        return 0

    merge_signature_packs(args)
    try:
        if args.context_bytes < 0:
            raise ValueError("--context-bytes cannot be negative")
        if args.context_number_radius < 0:
            raise ValueError("--context-number-radius cannot be negative")
        if args.hotkey_poll_interval is not None and args.hotkey_poll_interval <= 0:
            raise ValueError("--hotkey-poll-interval must be greater than 0")
        validate_regex_patterns(args.include_patterns, "--include-regex")
        validate_regex_patterns(args.exclude_patterns, "--exclude-regex")
        validate_regex_patterns(args.window_filter_patterns, "--window-filter-regex")
        validate_regex_patterns(args.watch_patterns, "--watch-pattern")
        validate_regex_patterns(args.gate_patterns, "--gate-regex")
    except ValueError as exc:
        print(str(exc))
        return 1

    pid = resolve_pid(args)
    prompted = False
    if not pid and args.pick_window:
        pid = prompt_for_window(args)
        prompted = True
    if not pid and sys.stdin.isatty() and not prompted and not args.no_interactive:
        pid = prompt_for_window(args)
    if not pid:
        print(f"Could not find process matching: {args.process}")
        return 1

    handle = open_process(pid)
    output_path = timestamped_output_path(args.output, args.session_name) if args.timestamp_output else Path(args.output)
    log_message(args, f"Game detected: attached to PID {pid}. Logging to {output_path}")
    if args.mode == "hotkey":
        log_message(args, f"Press {args.hotkey} to capture a snapshot. Ctrl+C to stop.")
    hotkey_poll_interval = args.hotkey_poll_interval
    if hotkey_poll_interval is None:
        hotkey_poll_interval = max(0.05, min(args.interval, 0.25))
        if args.mode == "hotkey" and hotkey_poll_interval != args.interval:
            log_message(args, f"Hotkey polling interval derived from --interval and clamped to {hotkey_poll_interval:.2f}s.", verbose_only=True)
    try:
        hotkey_vk = vk_from_name(args.hotkey)
    except ValueError as exc:
        close_handle(handle)
        print(str(exc))
        return 1

    if args.export_manifest:
        manifest = build_manifest(args, pid, output_path)
        manifest_path = write_manifest(output_path, manifest)
        log_message(args, f"Wrote manifest to {manifest_path}", verbose_only=True)

    try:
        include_keywords, exclude_keywords = build_keywords(args)
        previous_payload: dict[str, Any] | None = None
        seen_texts: set[str] = set()
        if args.mode == "once":
            payload, skip_message = prepare_capture_payload(
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
                log_message(args, skip_message or "Capture skipped.")
                return 0
            write_and_report_payload(args, output_path, payload)
            log_message(args, "Capture complete.")
            return 0

        if args.mode == "loop":
            captures = 0
            while True:
                payload, skip_message = prepare_capture_payload(
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
                    log_message(args, skip_message or "Capture skipped.", verbose_only=True)
                    time.sleep(args.interval)
                    continue
                write_and_report_payload(args, output_path, payload)
                previous_payload = payload
                captures += 1
                if args.captures is not None and captures >= args.captures:
                    log_message(args, "Capture limit reached.")
                    return 0
                time.sleep(args.interval)

        captures = 0
        last_hotkey_state = False
        while True:
            current_state = is_key_triggered(hotkey_vk)
            if current_state and not last_hotkey_state:
                payload, skip_message = prepare_capture_payload(
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
                    log_message(args, skip_message or "Capture skipped.")
                    last_hotkey_state = current_state
                    time.sleep(hotkey_poll_interval)
                    continue
                write_and_report_payload(args, output_path, payload)
                previous_payload = payload
                log_message(args, "Captured snapshot.")
                captures += 1
                if args.captures is not None and captures >= args.captures:
                    log_message(args, "Capture limit reached.")
                    return 0
            last_hotkey_state = current_state
            time.sleep(hotkey_poll_interval)
    except KeyboardInterrupt:
        log_message(args, "Stopped.")
    finally:
        close_handle(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
