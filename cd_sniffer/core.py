from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import DEFAULT_KEYWORDS
from .scanner import scan_to_json
from .windows import (
    close_handle,
    find_pids_by_window_title,
    get_window_pid,
    is_key_down,
    is_pid_running,
    open_process,
    vk_from_name,
)


def find_pid_by_name(process_name: str) -> int | None:
    try:
        result = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return None

    needle = process_name.lower()
    for line in result.stdout.splitlines():
        parts = [part.strip('"') for part in line.split('","')]
        if len(parts) < 2:
            continue
        image_name = parts[0].lower()
        if needle in image_name:
            try:
                return int(parts[1])
            except ValueError:
                continue
    return None


def resolve_pid(args: argparse.Namespace) -> int | None:
    if getattr(args, "pid", None):
        if is_pid_running(args.pid):
            return args.pid

    if getattr(args, "window_titles", None):
        for title in args.window_titles:
            pids = find_pids_by_window_title(title)
            if pids:
                return pids[0]

    pid = find_pid_by_name(getattr(args, "process", "Crimson Desert"))
    if pid:
        return pid

    return None


def collect_matching_windows(args: argparse.Namespace) -> list[tuple[int, int | None, str]]:
    from .windows import enum_windows

    title_fragments = [fragment.lower() for fragment in (args.window_titles or [])]
    regexes = [re.compile(pattern, re.IGNORECASE) for pattern in (args.window_filter_patterns or [])]
    matches: list[tuple[int, int | None, str]] = []
    for hwnd, title in enum_windows():
        lowered = title.lower()
        if title_fragments and not any(fragment in lowered for fragment in title_fragments):
            continue
        if regexes and not any(pattern.search(title) for pattern in regexes):
            continue
        matches.append((hwnd, get_window_pid(hwnd), title))
    return matches


def list_windows(args: argparse.Namespace) -> int:
    matches = collect_matching_windows(args)
    if not matches:
        print("No matching windows found.")
        return 1
    for index, (hwnd, pid, title) in enumerate(matches, start=1):
        pid_text = f"PID {pid:<6}" if pid is not None else "PID unknown"
        print(f"{index:>2}. 0x{hwnd:08X}  {pid_text}  {title}")
    return 0


def prompt_for_window(args: argparse.Namespace) -> int | None:
    matches = collect_matching_windows(args)
    if not matches:
        print("No matching windows found.")
        return None
    print("Select a window:")
    for index, (hwnd, pid, title) in enumerate(matches, start=1):
        pid_text = f"PID {pid:<6}" if pid is not None else "PID unknown"
        print(f"{index:>2}. 0x{hwnd:08X}  {pid_text}  {title}")
    while True:
        choice = input("Choose a number or press Enter to cancel: ").strip()
        if not choice:
            return None
        try:
            selected = int(choice)
        except ValueError:
            print("Please enter a valid number.")
            continue
        if 1 <= selected <= len(matches):
            hwnd, pid, _title = matches[selected - 1]
            return pid or get_window_pid(hwnd)
        print("Choice out of range.")


def write_snapshot(output_path: Path, payload: dict, fmt: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return
    with output_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


def timestamped_output_path(output: str, session_name: str) -> Path:
    base_path = Path(output)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = base_path.stem or session_name
    suffix = base_path.suffix or ".jsonl"
    stamped_name = f"{stem}-{stamp}{suffix}"
    if base_path.parent == Path(".") and base_path.name == output:
        return Path(stamped_name)
    return base_path.with_name(stamped_name)


def load_signature_pack(path: str) -> dict[str, list[str]]:
    pack_path = Path(path)
    text = pack_path.read_text(encoding="utf-8")
    include_keywords: list[str] = []
    exclude_keywords: list[str] = []
    include_patterns: list[str] = []
    exclude_patterns: list[str] = []

    if pack_path.suffix.lower() == ".json":
        data = json.loads(text)
        include_keywords.extend(data.get("include_keywords", []))
        exclude_keywords.extend(data.get("exclude_keywords", []))
        include_patterns.extend(data.get("include_patterns", []))
        exclude_patterns.extend(data.get("exclude_patterns", []))
        return {
            "include_keywords": include_keywords,
            "exclude_keywords": exclude_keywords,
            "include_patterns": include_patterns,
            "exclude_patterns": exclude_patterns,
        }

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!r:"):
            exclude_patterns.append(line[3:].strip())
        elif line.startswith("r:"):
            include_patterns.append(line[2:].strip())
        elif line.startswith("-"):
            exclude_keywords.append(line[1:].strip())
        else:
            include_keywords.append(line)
    return {
        "include_keywords": include_keywords,
        "exclude_keywords": exclude_keywords,
        "include_patterns": include_patterns,
        "exclude_patterns": exclude_patterns,
    }


def merge_signature_packs(args: argparse.Namespace) -> None:
    packs = list(args.signature_packs or [])
    if not packs:
        return
    merged = {
        "include_keywords": list(args.include_keywords or []),
        "exclude_keywords": list(args.exclude_keywords or []),
        "include_patterns": list(args.include_patterns or []),
        "exclude_patterns": list(args.exclude_patterns or []),
    }
    for pack in packs:
        data = load_signature_pack(pack)
        merged["include_keywords"].extend(data["include_keywords"])
        merged["exclude_keywords"].extend(data["exclude_keywords"])
        merged["include_patterns"].extend(data["include_patterns"])
        merged["exclude_patterns"].extend(data["exclude_patterns"])
    args.include_keywords = merged["include_keywords"]
    args.exclude_keywords = merged["exclude_keywords"]
    args.include_patterns = merged["include_patterns"]
    args.exclude_patterns = merged["exclude_patterns"]


def validate_regex_patterns(patterns: list[str] | None, context: str) -> None:
    for pattern in patterns or []:
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid regex in {context}: {pattern!r} ({exc})") from exc


def sanitize_manifest_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [sanitize_manifest_value(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_manifest_value(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_manifest_value(item) for key, item in value.items() if key not in {"pid"}}
    return value


def build_manifest(args: argparse.Namespace, pid: int, output_path: Path) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "output_path": str(output_path),
        "pid": pid,
        "settings": sanitize_manifest_value(vars(args)),
    }


def write_manifest(output_path: Path, manifest: dict[str, Any]) -> Path:
    manifest_path = output_path.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest_path


def flatten_hits(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    capture_meta = {
        "timestamp": payload.get("timestamp"),
        "pid": payload.get("pid"),
        "process": payload.get("process"),
        "mode": payload.get("mode"),
        "label": payload.get("label"),
        "game_version": payload.get("game_version"),
        "session_name": payload.get("session_name"),
        "output_path": payload.get("output_path"),
    }
    for region in payload.get("regions", []):
        for hit in region.get("hits", []):
            rows.append(
                {
                    **capture_meta,
                    "base_address": region.get("base_address"),
                    "region_size": region.get("region_size"),
                    "address": hit.get("address"),
                    "encoding": hit.get("encoding"),
                    "text": hit.get("text"),
                }
            )
    return rows


def build_search_pattern(query: str, *, regex: bool = False, case_sensitive: bool = False) -> re.Pattern[str]:
    if not query:
        raise ValueError("Search query cannot be empty.")
    expression = query if regex else re.escape(query)
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(expression, flags)


def search_payload_values(
    payload: Any,
    query: str,
    *,
    regex: bool = False,
    case_sensitive: bool = False,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    pattern = build_search_pattern(query, regex=regex, case_sensitive=case_sensitive)
    matches: list[dict[str, Any]] = []

    def walk(value: Any, path: str) -> None:
        if limit is not None and len(matches) >= limit:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                next_path = f"{path}.{key}" if path else str(key)
                walk(child, next_path)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                next_path = f"{path}[{index}]" if path else f"[{index}]"
                walk(child, next_path)
            return

        text = str(value)
        if pattern.search(text):
            matches.append({"path": path or "$", "value": text})

    walk(payload, "")
    return matches


def search_flattened_hits(
    payload: dict[str, Any],
    query: str,
    *,
    regex: bool = False,
    case_sensitive: bool = False,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    pattern = build_search_pattern(query, regex=regex, case_sensitive=case_sensitive)
    rows = flatten_hits(payload)
    matches: list[dict[str, Any]] = []
    for row in rows:
        haystack = " | ".join(str(row.get(field, "")) for field in row)
        if pattern.search(haystack):
            matches.append(row)
            if limit is not None and len(matches) >= limit:
                break
    return matches


def search_capture_file(
    path: Path,
    query: str,
    *,
    regex: bool = False,
    case_sensitive: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    pattern = build_search_pattern(query, regex=regex, case_sensitive=case_sensitive)
    suffix = path.suffix.lower()
    results: list[dict[str, Any]] = []
    snapshot_count = 0

    def add_match(*, snapshot_index: int | None, payload_index: int | None, path_text: str, value: str) -> None:
        results.append(
            {
                "snapshot_index": snapshot_index,
                "payload_index": payload_index,
                "path": path_text,
                "value": value,
            }
        )

    if suffix == ".jsonl" or suffix == ".ndjson":
        for snapshot_index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            snapshot_count += 1
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                if pattern.search(line):
                    add_match(snapshot_index=snapshot_index, payload_index=None, path_text="$raw", value=line)
                continue
            if not isinstance(payload, dict):
                continue
            for payload_match in search_payload_values(payload, query, regex=regex, case_sensitive=case_sensitive, limit=limit):
                add_match(
                    snapshot_index=snapshot_index,
                    payload_index=None,
                    path_text=str(payload_match["path"]),
                    value=str(payload_match["value"]),
                )
                if limit is not None and len(results) >= limit:
                    break
            if limit is not None and len(results) >= limit:
                break
    elif suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        payloads = data if isinstance(data, list) else [data]
        snapshot_count = len(payloads)
        for payload_index, payload in enumerate(payloads, start=1):
            if not isinstance(payload, dict):
                continue
            for payload_match in search_payload_values(payload, query, regex=regex, case_sensitive=case_sensitive, limit=limit):
                add_match(
                    snapshot_index=payload_index,
                    payload_index=payload_index,
                    path_text=str(payload_match["path"]),
                    value=str(payload_match["value"]),
                )
                if limit is not None and len(results) >= limit:
                    break
            if limit is not None and len(results) >= limit:
                break
    else:
        raw_text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(raw_text.splitlines(), start=1):
            if pattern.search(line):
                add_match(snapshot_index=None, payload_index=line_number, path_text=f"line:{line_number}", value=line)
                if limit is not None and len(results) >= limit:
                    break

    return {
        "path": str(path),
        "query": query,
        "regex": regex,
        "case_sensitive": case_sensitive,
        "snapshot_count": snapshot_count,
        "match_count": len(results),
        "matches": results,
    }


def search_capture_directory(
    root: Path,
    query: str,
    *,
    regex: bool = False,
    case_sensitive: bool = False,
    limit: int | None = None,
    recursive: bool = True,
    patterns: list[str] | None = None,
) -> dict[str, Any]:
    glob_patterns = patterns or ["*.jsonl", "*.ndjson", "*.json", "*.csv", "*.markdown", "*.md", "*.txt"]
    file_paths: list[Path] = []
    for pattern in glob_patterns:
        iterator = root.rglob(pattern) if recursive else root.glob(pattern)
        for path in iterator:
            if path.is_file():
                file_paths.append(path)
    file_paths = sorted(dict.fromkeys(file_paths))

    file_results: list[dict[str, Any]] = []
    total_matches = 0
    for path in file_paths:
        if limit is not None and total_matches >= limit:
            break
        remaining = None if limit is None else max(0, limit - total_matches)
        if remaining == 0:
            break
        result = search_capture_file(
            path,
            query,
            regex=regex,
            case_sensitive=case_sensitive,
            limit=remaining,
        )
        if result["match_count"]:
            file_results.append(result)
            total_matches += int(result["match_count"])

    return {
        "path": str(root),
        "query": query,
        "regex": regex,
        "case_sensitive": case_sensitive,
        "recursive": recursive,
        "file_count": len(file_paths),
        "match_count": total_matches,
        "files": file_results,
    }


def flatten_search_results(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for file_result in result.get("files", []):
        file_path = file_result.get("path", "")
        for match in file_result.get("matches", []):
            rows.append(
                {
                    "file": file_path,
                    "snapshot_index": file_result.get("snapshot_count"),
                    "match_path": match.get("path"),
                    "value": match.get("value"),
                    "snapshot_index_match": match.get("snapshot_index"),
                    "payload_index": match.get("payload_index"),
                }
            )
    if not rows and result.get("matches"):
        for match in result.get("matches", []):
            rows.append(
                {
                    "file": result.get("path", ""),
                    "snapshot_index": result.get("snapshot_count"),
                    "match_path": match.get("path"),
                    "value": match.get("value"),
                    "snapshot_index_match": match.get("snapshot_index"),
                    "payload_index": match.get("payload_index"),
                }
            )
    return rows


def render_search_results_csv(result: dict[str, Any]) -> str:
    import csv
    from io import StringIO

    rows = flatten_search_results(result)
    buffer = StringIO()
    fieldnames = ["file", "snapshot_index", "match_path", "value", "snapshot_index_match", "payload_index"]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def render_search_results_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# CDSniffer Search Results",
        "",
        f"- Query: `{result.get('query', '')}`",
        f"- Path: `{result.get('path', '')}`",
        f"- Matches: `{result.get('match_count', 0)}`",
        "",
        "| File | Match Path | Value |",
        "| --- | --- | --- |",
    ]
    rows = flatten_search_results(result)
    if not rows:
        lines.append("| - | - | No matches |")
        return "\n".join(lines) + "\n"
    for row in rows:
        file_path = str(row.get("file", "")).replace("|", "\\|")
        match_path = str(row.get("match_path", "")).replace("|", "\\|")
        value = str(row.get("value", "")).replace("|", "\\|")
        lines.append(f"| {file_path} | {match_path} | {value} |")
    return "\n".join(lines) + "\n"


def render_csv_snapshot(payload: dict[str, Any]) -> str:
    import csv
    from io import StringIO

    rows = flatten_hits(payload)
    buffer = StringIO()
    fieldnames = [
        "timestamp",
        "pid",
        "process",
        "mode",
        "label",
        "game_version",
        "session_name",
        "output_path",
        "base_address",
        "region_size",
        "address",
        "encoding",
        "text",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def render_markdown_snapshot(payload: dict[str, Any]) -> str:
    lines = [
        "# CDSniffer Snapshot",
        "",
        f"- Timestamp: `{payload.get('timestamp', '')}`",
        f"- PID: `{payload.get('pid', '')}`",
        f"- Process: `{payload.get('process', '')}`",
        f"- Mode: `{payload.get('mode', '')}`",
        f"- Label: `{payload.get('label', '')}`",
        f"- Game Version: `{payload.get('game_version', '')}`",
        f"- Session: `{payload.get('session_name', '')}`",
        "",
        "| Base Address | Region Size | Address | Encoding | Text |",
        "| --- | ---: | ---: | --- | --- |",
    ]
    rows = flatten_hits(payload)
    if not rows:
        lines.append("| - | -: | -: | - | No hits |")
        return "\n".join(lines) + "\n"
    for row in rows:
        lines.append(
            f"| 0x{int(row['base_address']):X} | {int(row['region_size'])} | 0x{int(row['address']):X} | {row['encoding']} | {str(row['text']).replace('|', '\\|')} |"
        )
    return "\n".join(lines) + "\n"


def write_rendered_snapshot(output_path: Path, payload: dict[str, Any], fmt: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "csv":
        rendered = render_csv_snapshot(payload)
        if output_path.exists() and output_path.stat().st_size > 0:
            rendered = "".join(rendered.splitlines(True)[1:])
        with output_path.open("a", encoding="utf-8", newline="") as fh:
            fh.write(rendered)
        return
    if fmt == "markdown":
        rendered = render_markdown_snapshot(payload)
        with output_path.open("a", encoding="utf-8") as fh:
            fh.write(rendered)
        return
    write_snapshot(output_path, payload, fmt)


def log_message(args: argparse.Namespace, message: str, *, verbose_only: bool = False) -> None:
    if args.quiet and not verbose_only:
        return
    if verbose_only and not args.verbose:
        return
    print(message)


def build_comparison(current_payload: dict[str, Any], previous_payload: dict[str, Any], limit: int) -> dict[str, Any]:
    current_texts = {hit["text"] for region in current_payload.get("regions", []) for hit in region.get("hits", [])}
    previous_texts = {hit["text"] for region in previous_payload.get("regions", []) for hit in region.get("hits", [])}
    added = sorted(current_texts - previous_texts)[:limit]
    removed = sorted(previous_texts - current_texts)[:limit]
    return {
        "previous_timestamp": previous_payload.get("timestamp"),
        "added_count": max(0, len(current_texts - previous_texts)),
        "removed_count": max(0, len(previous_texts - current_texts)),
        "added": added,
        "removed": removed,
    }


def collect_watch_hits(payload: dict[str, Any], patterns: list[str] | None) -> list[str]:
    regexes = [re.compile(pattern, re.IGNORECASE) for pattern in (patterns or [])]
    if not regexes:
        return []
    matches: list[str] = []
    for region in payload.get("regions", []):
        for hit in region.get("hits", []):
            text = str(hit.get("text", ""))
            if any(pattern.search(text) for pattern in regexes) and text not in matches:
                matches.append(text)
    return matches


def finalize_payload(
    payload: dict[str, Any],
    args: argparse.Namespace,
    output_path: Path,
    previous_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    payload["output_path"] = str(output_path)
    if args.compare_last and previous_payload is not None:
        payload["comparison"] = build_comparison(payload, previous_payload, args.compare_limit)
    payload["watch_hits"] = collect_watch_hits(payload, args.watch_patterns)
    return payload


def build_keywords(args: argparse.Namespace) -> tuple[list[str], list[str]]:
    include_keywords = list(DEFAULT_KEYWORDS)
    include_keywords.extend(args.include_keywords or [])
    exclude_keywords = list(args.exclude_keywords or [])
    return include_keywords, exclude_keywords


def capture_once(handle: int, pid: int, args: argparse.Namespace, include_keywords: list[str], exclude_keywords: list[str]) -> dict:
    payload = scan_to_json(
        handle,
        include_keywords=include_keywords,
        exclude_keywords=exclude_keywords,
        include_patterns=args.include_patterns,
        exclude_patterns=args.exclude_patterns,
        max_region_size=args.max_region_size,
        max_regions=args.max_regions,
        max_hits_per_region=args.max_hits_per_region,
    )
    payload["pid"] = pid
    payload["process"] = args.process
    payload["mode"] = args.mode
    payload["label"] = args.label
    payload["game_version"] = args.game_version
    payload["session_name"] = args.session_name
    payload["settings"] = {
        "include_keywords": include_keywords,
        "exclude_keywords": exclude_keywords,
        "include_patterns": args.include_patterns,
        "exclude_patterns": args.exclude_patterns,
        "watch_patterns": args.watch_patterns,
        "notes": args.notes,
        "summary": args.summary,
        "summary_limit": args.summary_limit,
        "compare_last": args.compare_last,
        "compare_limit": args.compare_limit,
        "max_region_size": args.max_region_size,
        "max_regions": args.max_regions,
        "max_hits_per_region": args.max_hits_per_region,
    }
    if args.notes:
        payload["notes"] = args.notes
    return payload


def print_summary(args: argparse.Namespace, payload: dict, summary_mode: str, summary_limit: int) -> None:
    if summary_mode == "none":
        return
    if summary_mode == "top-hits":
        print(f"Summary for PID {payload.get('pid')} ({payload.get('process')}):")
        for item in payload.get("top_hits", [])[:summary_limit]:
            print(f"  {item['count']:>4}x {item['encoding']:<8} 0x{int(item['first_address']):X}  {item['text']}")
