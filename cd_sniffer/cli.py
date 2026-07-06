from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any

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
from .ipc import send_gui_command
from .windows import is_key_down


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
    parser.add_argument("--list-windows", action="store_true", help="List matching windows and exit")
    parser.add_argument("--mode", choices=["once", "loop", "hotkey"], default="loop", help="Capture mode")
    parser.add_argument("--hotkey", default="F8", help="Polling hotkey for hotkey mode")
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
    parser.add_argument("--correlate-root", help="Root directory of unpacked/game files to scan")
    parser.add_argument("--correlate-recursive", action="store_true", default=True, help="Recursively scan subfolders for correlation")
    parser.add_argument("--correlate-no-recursive", action="store_false", dest="correlate_recursive", help="Only scan the top level for correlation")
    parser.add_argument("--correlate-glob", action="append", dest="correlate_globs", help="File glob to include during correlation; may be repeated")
    parser.add_argument("--correlate-max-file-size", type=int, default=64 * 1024 * 1024, help="Skip files larger than this many bytes during correlation")
    parser.add_argument("--correlate-max-matches", type=int, default=500, help="Maximum total correlation matches to return")
    parser.add_argument("--correlate-max-matches-per-evidence", type=int, default=20, help="Maximum file offsets per evidence item")
    parser.add_argument("--correlate-no-numeric", action="store_false", dest="correlate_numeric", default=True, help="Do not correlate decoded numeric candidate bytes")
    parser.add_argument("--correlate-context-bytes", type=int, default=16, help="Bytes around each file match to include in correlation output")
    parser.add_argument("--correlate-format", choices=["json", "csv", "markdown"], default="json", help="Format used for correlation results")
    parser.add_argument("--correlate-output", help="Optional file path to write correlation results instead of printing them")
    return parser.parse_args()


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

    target_capture_arg = args.correlate_target or args.correlate_capture
    if args.correlate_baseline and not target_capture_arg:
        print("--correlate-capture or --correlate-target is required with --correlate-baseline")
        return 1

    if target_capture_arg:
        if not args.correlate_root:
            print("--correlate-root is required with --correlate-capture or --correlate-target")
            return 1
        capture_path = Path(target_capture_arg)
        baseline_capture_path = Path(args.correlate_baseline) if args.correlate_baseline else None
        root_path = Path(args.correlate_root)
        if not capture_path.exists():
            print(f"Capture file not found: {capture_path}")
            return 1
        if baseline_capture_path is not None and not baseline_capture_path.exists():
            print(f"Baseline capture file not found: {baseline_capture_path}")
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
                recursive=args.correlate_recursive,
                patterns=args.correlate_globs,
                max_file_size=args.correlate_max_file_size,
                max_matches_per_evidence=args.correlate_max_matches_per_evidence,
                max_total_matches=args.correlate_max_matches,
                include_numeric=args.correlate_numeric,
                context_bytes=args.correlate_context_bytes,
            )
        except Exception as exc:
            print(f"Correlation failed: {exc}")
            return 1

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
    if not pid and sys.stdin.isatty() and not prompted:
        pid = prompt_for_window(args)
    if not pid:
        print(f"Could not find process matching: {args.process}")
        return 1

    handle = open_process(pid)
    output_path = timestamped_output_path(args.output, args.session_name) if args.timestamp_output else Path(args.output)
    log_message(args, f"Game detected: attached to PID {pid}. Logging to {output_path}")
    if args.mode == "hotkey":
        log_message(args, f"Press {args.hotkey} to capture a snapshot. Ctrl+C to stop.")
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
            current_state = is_key_down(hotkey_vk)
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
                    time.sleep(max(0.05, min(args.interval, 0.25)))
                    continue
                write_and_report_payload(args, output_path, payload)
                previous_payload = payload
                log_message(args, "Captured snapshot.")
                captures += 1
                if args.captures is not None and captures >= args.captures:
                    log_message(args, "Capture limit reached.")
                    return 0
            last_hotkey_state = current_state
            time.sleep(max(0.05, min(args.interval, 0.25)))
    except KeyboardInterrupt:
        log_message(args, "Stopped.")
    finally:
        close_handle(handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
