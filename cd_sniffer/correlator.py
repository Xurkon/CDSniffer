from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Iterable

from .format_analyzers import analyze_match_format, summarize_format_hints


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source: str
    value: str
    data: bytes
    snapshot_index: int | None
    hit_index: int | None
    hit_text: str
    encoding: str | None
    address: int | None
    module_rva: int | None
    weight: float


def parse_hex_bytes(value: str | None) -> bytes:
    if not value:
        return b""
    cleaned = "".join(char for char in value if char in "0123456789abcdefABCDEF")
    if len(cleaned) < 2 or len(cleaned) % 2:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def encode_text_evidence(text: str, encoding: str | None) -> list[tuple[str, bytes]]:
    if not text:
        return []
    encodings = [encoding] if encoding in {"ascii", "utf16le"} else ["ascii", "utf16le"]
    encoded: list[tuple[str, bytes]] = []
    for item in encodings:
        try:
            if item == "utf16le":
                data = text.encode("utf-16le")
            else:
                data = text.encode("ascii")
        except UnicodeEncodeError:
            continue
        if len(data) >= 4:
            encoded.append((item, data))
    return encoded


def iter_capture_payloads(path: Path) -> Iterable[tuple[int | None, dict[str, Any]]]:
    suffix = path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                yield index, data
        return

    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        for index, payload in enumerate(data, start=1):
            if isinstance(payload, dict):
                yield index, payload
    elif isinstance(data, dict):
        yield 1, data


def extract_evidence_from_capture(path: Path, *, include_numeric: bool = True) -> list[Evidence]:
    evidence: list[Evidence] = []
    seen: set[tuple[str, bytes, int | None, int | None]] = set()
    for snapshot_index, payload in iter_capture_payloads(path):
        hit_counter = 0
        for region in payload.get("regions", []):
            for hit in region.get("hits", []):
                hit_counter += 1
                text = str(hit.get("text", ""))
                encoding = hit.get("encoding")
                address = _int_or_none(hit.get("address"))
                module_rva = _int_or_none(hit.get("module_rva"))
                context = hit.get("context") if isinstance(hit.get("context"), dict) else {}
                hit_bytes = parse_hex_bytes(str(context.get("hit_bytes", "")))

                for text_encoding, data in encode_text_evidence(text, str(encoding) if encoding else None):
                    key = (f"text:{text_encoding}", data, snapshot_index, hit_counter)
                    if key not in seen:
                        seen.add(key)
                        evidence.append(
                            Evidence(
                                evidence_id=f"s{snapshot_index or 0}:h{hit_counter}:text:{text_encoding}",
                                source=f"text:{text_encoding}",
                                value=text,
                                data=data,
                                snapshot_index=snapshot_index,
                                hit_index=hit_counter,
                                hit_text=text,
                                encoding=text_encoding,
                                address=address,
                                module_rva=module_rva,
                                weight=0.82 if text_encoding == encoding else 0.7,
                            )
                        )

                if hit_bytes:
                    key = ("hit-bytes", hit_bytes, snapshot_index, hit_counter)
                    if key not in seen:
                        seen.add(key)
                        evidence.append(
                            Evidence(
                                evidence_id=f"s{snapshot_index or 0}:h{hit_counter}:hit-bytes",
                                source="hit-bytes",
                                value=hit_bytes.hex(" "),
                                data=hit_bytes,
                                snapshot_index=snapshot_index,
                                hit_index=hit_counter,
                                hit_text=text,
                                encoding=str(encoding) if encoding else None,
                                address=address,
                                module_rva=module_rva,
                                weight=0.95,
                            )
                        )

                if include_numeric:
                    for candidate_index, candidate in enumerate(context.get("numeric_candidates", []) or [], start=1):
                        if not isinstance(candidate, dict):
                            continue
                        raw = parse_hex_bytes(str(candidate.get("hex", "")))
                        if not raw or len(raw) < 2:
                            continue
                        key = (f"numeric:{candidate.get('size')}:{candidate.get('endian')}", raw, snapshot_index, hit_counter)
                        if key in seen:
                            continue
                        seen.add(key)
                        evidence.append(
                            Evidence(
                                evidence_id=f"s{snapshot_index or 0}:h{hit_counter}:num{candidate_index}",
                                source=f"numeric:{candidate.get('size')}:{candidate.get('endian')}",
                                value=str(candidate.get("value", "")),
                                data=raw,
                                snapshot_index=snapshot_index,
                                hit_index=hit_counter,
                                hit_text=text,
                                encoding=str(encoding) if encoding else None,
                                address=_int_or_none(candidate.get("address")) or address,
                                module_rva=module_rva,
                                weight=0.55,
                            )
                        )
    return evidence


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def iter_candidate_files(
    root: Path,
    *,
    recursive: bool = True,
    patterns: list[str] | None = None,
    max_file_size: int = 64 * 1024 * 1024,
) -> list[Path]:
    glob_patterns = patterns or ["*"]
    paths: list[Path] = []
    for pattern in glob_patterns:
        iterator = root.rglob(pattern) if recursive else root.glob(pattern)
        for path in iterator:
            if not path.is_file():
                continue
            try:
                if max_file_size > 0 and path.stat().st_size > max_file_size:
                    continue
            except OSError:
                continue
            paths.append(path)
    return sorted(dict.fromkeys(paths))


def find_all_offsets(blob: bytes, needle: bytes, limit: int | None = None) -> list[int]:
    if not needle:
        return []
    offsets: list[int] = []
    start = 0
    while True:
        found = blob.find(needle, start)
        if found < 0:
            break
        offsets.append(found)
        if limit is not None and len(offsets) >= limit:
            break
        start = found + 1
    return offsets


def _confidence_for_match(evidence: Evidence, file_match_count: int, file_size: int) -> float:
    confidence = evidence.weight
    if evidence.source == "hit-bytes":
        confidence += 0.1
    if evidence.module_rva is not None:
        confidence += 0.03
    if file_match_count == 1:
        confidence += 0.08
    elif file_match_count > 8:
        confidence -= 0.12
    if len(evidence.data) >= 16:
        confidence += 0.05
    elif len(evidence.data) <= 3:
        confidence -= 0.15
    if file_size and len(evidence.data) / max(1, file_size) > 0.001:
        confidence += 0.02
    return round(max(0.0, min(1.0, confidence)), 3)


def _raw_match_limit(max_total_matches: int) -> int:
    return max_total_matches * 4


def _collect_raw_matches(
    evidence_items: list[Evidence],
    files: list[Path],
    root: Path,
    *,
    max_matches_per_evidence: int,
    max_total_matches: int,
    context_bytes: int,
    include_format_hints: bool,
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    raw_limit = _raw_match_limit(max_total_matches)
    for file_path in files:
        if len(matches) >= raw_limit:
            break
        try:
            blob = file_path.read_bytes()
        except OSError:
            continue
        for evidence in evidence_items:
            if len(matches) >= raw_limit:
                break
            offsets = find_all_offsets(blob, evidence.data, limit=max_matches_per_evidence)
            if not offsets:
                continue
            for offset in offsets:
                start = max(0, offset - context_bytes)
                end = min(len(blob), offset + len(evidence.data) + context_bytes)
                original = blob[offset : offset + len(evidence.data)]
                relative_file = str(file_path.relative_to(root)) if _is_relative_to(file_path, root) else str(file_path)
                format_info = (
                    analyze_match_format(file_path, blob, offset, original, evidence.value, evidence.hit_text)
                    if include_format_hints
                    else {"file_format": file_path.suffix.lower().lstrip(".") or "binary", "format_confidence_bonus": 0.0, "format_hints": []}
                )
                matches.append(
                    {
                        "file": str(file_path),
                        "relative_file": relative_file,
                        "offset": offset,
                        "offset_hex": f"0x{offset:X}",
                        "match_type": evidence.source,
                        "evidence_id": evidence.evidence_id,
                        "evidence_value": evidence.value,
                        "hit_text": evidence.hit_text,
                        "snapshot_index": evidence.snapshot_index,
                        "hit_index": evidence.hit_index,
                        "runtime_address": evidence.address,
                        "runtime_address_hex": f"0x{evidence.address:X}" if evidence.address is not None else None,
                        "module_rva": evidence.module_rva,
                        "module_rva_hex": f"0x{evidence.module_rva:X}" if evidence.module_rva is not None else None,
                        "original_bytes": original.hex(" "),
                        "context_hex": blob[start:end].hex(" "),
                        "file_format": format_info["file_format"],
                        "format_confidence_bonus": format_info["format_confidence_bonus"],
                        "format_hints": format_info["format_hints"],
                        "confidence": _confidence_for_match(evidence, len(offsets), len(blob)),
                        "patch_skeleton": {
                            "type": "bytes",
                            "file": relative_file,
                            "offset": offset,
                            "original": original.hex(" "),
                            "replacement": "",
                        },
                    }
                )
                if len(matches) >= raw_limit:
                    break
    return matches


def _append_unique(values: list[Any], value: Any) -> None:
    if value is not None and value not in values:
        values.append(value)


def _evidence_entry(match: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_id": match.get("evidence_id"),
        "match_type": match.get("match_type"),
        "evidence_value": match.get("evidence_value"),
        "hit_text": match.get("hit_text"),
        "snapshot_index": match.get("snapshot_index"),
        "hit_index": match.get("hit_index"),
        "runtime_address": match.get("runtime_address"),
        "runtime_address_hex": match.get("runtime_address_hex"),
        "module_rva": match.get("module_rva"),
        "module_rva_hex": match.get("module_rva_hex"),
        "confidence": match.get("confidence"),
        "file_format": match.get("file_format"),
        "format_hints": match.get("format_hints", []),
    }


def _aggregate_confidence(group: dict[str, Any]) -> tuple[float, list[str]]:
    evidence = group.get("evidence", [])
    match_types = list(group.get("match_types", []))
    snapshots = [item for item in group.get("snapshots", []) if item is not None]
    scores = [float(item.get("confidence", 0.0) or 0.0) for item in evidence if isinstance(item, dict)]
    confidence = max(scores or [0.0])
    reasons: list[str] = []

    if len(evidence) > 1:
        confidence += min(0.12, 0.04 * (len(evidence) - 1))
        reasons.append("multiple-evidence")
    if "hit-bytes" in match_types:
        confidence += 0.03
        reasons.append("exact-hit-bytes")
    if "hit-bytes" in match_types and any(str(item).startswith("text:") for item in match_types):
        confidence += 0.04
        reasons.append("text-and-bytes")
    if any(str(item).startswith("numeric:") for item in match_types):
        confidence += 0.03
        reasons.append("nearby-numeric")
    if len(set(snapshots)) > 1:
        confidence += 0.04
        reasons.append("repeated-snapshots")
    if any(item.get("module_rva") is not None for item in evidence if isinstance(item, dict)):
        reasons.append("module-rva")
    format_bonus = float(group.get("format_confidence_bonus", 0.0) or 0.0)
    if format_bonus:
        confidence += format_bonus
        hint_kinds = {str(item.get("kind", "")) for item in group.get("format_hints", []) if item.get("kind")}
        if "json-record" in hint_kinds:
            reasons.append("json-structure")
        if "paseq-binary" in hint_kinds:
            reasons.append("paseq-binary")
        if {"little-endian-context", "matched-integer"} & hint_kinds:
            reasons.append("little-endian-context")
        if hint_kinds and "format-context" not in reasons:
            reasons.append("format-context")

    return round(max(0.0, min(1.0, confidence)), 3), reasons


def _hint_key(hint: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(hint.get("kind", "")),
        str(hint.get("summary", "")),
        str(hint.get("path", "")),
        str(hint.get("value", "")),
    )


def _merge_format_hints(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> None:
    seen = {_hint_key(item) for item in existing}
    for hint in incoming:
        key = _hint_key(hint)
        if key in seen:
            continue
        seen.add(key)
        existing.append(hint)
        if len(existing) >= 12:
            break


def aggregate_correlation_matches(raw_matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, int, str], dict[str, Any]] = {}
    for match in raw_matches:
        key = (
            str(match.get("relative_file") or match.get("file") or ""),
            int(match.get("offset", 0) or 0),
            str(match.get("original_bytes", "")),
        )
        if key not in grouped:
            grouped[key] = {
                "file": match.get("file"),
                "relative_file": match.get("relative_file"),
                "offset": match.get("offset"),
                "offset_hex": match.get("offset_hex"),
                "match_type": match.get("match_type"),
                "evidence_id": match.get("evidence_id"),
                "evidence_value": match.get("evidence_value"),
                "hit_text": match.get("hit_text"),
                "snapshot_index": match.get("snapshot_index"),
                "hit_index": match.get("hit_index"),
                "runtime_address": match.get("runtime_address"),
                "runtime_address_hex": match.get("runtime_address_hex"),
                "module_rva": match.get("module_rva"),
                "module_rva_hex": match.get("module_rva_hex"),
                "original_bytes": match.get("original_bytes"),
                "context_hex": match.get("context_hex"),
                "file_format": match.get("file_format"),
                "format_confidence_bonus": 0.0,
                "format_hints": [],
                "patch_skeleton": match.get("patch_skeleton"),
                "diff_status": "uncompared",
                "evidence": [],
                "match_types": [],
                "evidence_values": [],
                "hit_texts": [],
                "snapshots": [],
            }

        group = grouped[key]
        group["evidence"].append(_evidence_entry(match))
        _append_unique(group["match_types"], match.get("match_type"))
        _append_unique(group["evidence_values"], match.get("evidence_value"))
        _append_unique(group["hit_texts"], match.get("hit_text"))
        _append_unique(group["snapshots"], match.get("snapshot_index"))
        group["format_confidence_bonus"] = max(
            float(group.get("format_confidence_bonus", 0.0) or 0.0),
            float(match.get("format_confidence_bonus", 0.0) or 0.0),
        )
        _merge_format_hints(group["format_hints"], list(match.get("format_hints", [])))

    matches: list[dict[str, Any]] = []
    for group in grouped.values():
        confidence, reasons = _aggregate_confidence(group)
        group["confidence"] = confidence
        group["confidence_reasons"] = reasons
        group["evidence_count"] = len(group["evidence"])
        group["match_type"] = ", ".join(str(item) for item in group["match_types"])
        group["evidence_value"] = ", ".join(str(item) for item in group["evidence_values"])
        group["hit_text"] = ", ".join(str(item) for item in group["hit_texts"])
        group["format_hint_summary"] = summarize_format_hints(group["format_hints"])
        matches.append(group)
    return matches


def _candidate_key(match: dict[str, Any]) -> tuple[str, int, str]:
    return (
        str(match.get("relative_file") or match.get("file") or ""),
        int(match.get("offset", 0) or 0),
        str(match.get("original_bytes", "")),
    )


def _apply_baseline_diff(matches: list[dict[str, Any]], baseline_matches: list[dict[str, Any]]) -> dict[str, int]:
    baseline_keys = {_candidate_key(match) for match in baseline_matches}
    target_only_count = 0
    shared_count = 0
    for match in matches:
        reasons = list(match.get("confidence_reasons", []))
        if _candidate_key(match) in baseline_keys:
            match["diff_status"] = "shared-with-baseline"
            shared_count += 1
            if "shared-with-baseline" not in reasons:
                reasons.append("shared-with-baseline")
            match["confidence"] = round(max(0.0, float(match.get("confidence", 0.0) or 0.0) - 0.03), 3)
        else:
            match["diff_status"] = "target-only"
            target_only_count += 1
            if "target-only" not in reasons:
                reasons.append("target-only")
            match["confidence"] = round(min(1.0, float(match.get("confidence", 0.0) or 0.0) + 0.08), 3)
        match["confidence_reasons"] = reasons
    return {"target_only_count": target_only_count, "shared_count": shared_count}


def correlate_capture_to_files(
    capture_path: Path,
    root: Path,
    *,
    baseline_capture_path: Path | None = None,
    recursive: bool = True,
    patterns: list[str] | None = None,
    max_file_size: int = 64 * 1024 * 1024,
    max_matches_per_evidence: int = 20,
    max_total_matches: int = 500,
    include_numeric: bool = True,
    context_bytes: int = 16,
    include_format_hints: bool = True,
) -> dict[str, Any]:
    max_matches_per_evidence = max(1, max_matches_per_evidence)
    max_total_matches = max(1, max_total_matches)
    context_bytes = max(0, context_bytes)
    max_file_size = max(0, max_file_size)
    evidence_items = extract_evidence_from_capture(capture_path, include_numeric=include_numeric)
    files = iter_candidate_files(root, recursive=recursive, patterns=patterns, max_file_size=max_file_size)

    raw_matches = _collect_raw_matches(
        evidence_items,
        files,
        root,
        max_matches_per_evidence=max_matches_per_evidence,
        max_total_matches=max_total_matches,
        context_bytes=context_bytes,
        include_format_hints=include_format_hints,
    )
    matches = aggregate_correlation_matches(raw_matches)
    baseline_evidence_count = 0
    baseline_match_count = 0
    target_only_count = 0
    shared_count = 0
    if baseline_capture_path is not None:
        baseline_evidence = extract_evidence_from_capture(baseline_capture_path, include_numeric=include_numeric)
        baseline_evidence_count = len(baseline_evidence)
        baseline_raw_matches = _collect_raw_matches(
            baseline_evidence,
            files,
            root,
            max_matches_per_evidence=max_matches_per_evidence,
            max_total_matches=max_total_matches,
            context_bytes=context_bytes,
            include_format_hints=include_format_hints,
        )
        baseline_matches = aggregate_correlation_matches(baseline_raw_matches)
        baseline_match_count = len(baseline_matches)
        diff_counts = _apply_baseline_diff(matches, baseline_matches)
        target_only_count = diff_counts["target_only_count"]
        shared_count = diff_counts["shared_count"]

    matches.sort(key=lambda item: (-float(item["confidence"]), str(item["relative_file"]), int(item["offset"])))
    matches = matches[:max_total_matches]
    if baseline_capture_path is not None:
        target_only_count = sum(1 for match in matches if match.get("diff_status") == "target-only")
        shared_count = sum(1 for match in matches if match.get("diff_status") == "shared-with-baseline")
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "capture_path": str(capture_path),
        "baseline_capture_path": str(baseline_capture_path) if baseline_capture_path is not None else None,
        "root": str(root),
        "recursive": recursive,
        "patterns": patterns or ["*"],
        "max_file_size": max_file_size,
        "evidence_count": len(evidence_items),
        "raw_match_count": len(raw_matches),
        "baseline_evidence_count": baseline_evidence_count,
        "baseline_match_count": baseline_match_count,
        "target_only_count": target_only_count,
        "shared_count": shared_count,
        "format_hint_count": sum(len(match.get("format_hints", [])) for match in matches),
        "file_count": len(files),
        "match_count": len(matches),
        "matches": matches,
    }


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def flatten_correlation_results(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "file": match.get("relative_file") or match.get("file"),
            "offset": match.get("offset"),
            "offset_hex": match.get("offset_hex"),
            "confidence": match.get("confidence"),
            "diff_status": match.get("diff_status"),
            "evidence_count": match.get("evidence_count"),
            "match_type": match.get("match_type"),
            "file_format": match.get("file_format"),
            "format_hint_summary": match.get("format_hint_summary"),
            "evidence_value": match.get("evidence_value"),
            "hit_text": match.get("hit_text"),
            "original_bytes": match.get("original_bytes"),
            "module_rva_hex": match.get("module_rva_hex"),
            "confidence_reasons": ", ".join(str(item) for item in match.get("confidence_reasons", [])),
        }
        for match in result.get("matches", [])
    ]


def render_correlation_csv(result: dict[str, Any]) -> str:
    rows = flatten_correlation_results(result)
    buffer = StringIO()
    fieldnames = [
        "file",
        "offset",
        "offset_hex",
        "confidence",
        "diff_status",
        "evidence_count",
        "match_type",
        "file_format",
        "format_hint_summary",
        "evidence_value",
        "hit_text",
        "original_bytes",
        "module_rva_hex",
        "confidence_reasons",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def render_correlation_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# CDSniffer Correlation Results",
        "",
        f"- Capture: `{result.get('capture_path', '')}`",
        f"- Root: `{result.get('root', '')}`",
        f"- Evidence: `{result.get('evidence_count', 0)}`",
        f"- Files scanned: `{result.get('file_count', 0)}`",
        f"- Matches: `{result.get('match_count', 0)}`",
        f"- Format hints: `{result.get('format_hint_count', 0)}`",
    ]
    if result.get("baseline_capture_path"):
        lines.extend(
            [
                f"- Baseline: `{result.get('baseline_capture_path', '')}`",
                f"- Target-only: `{result.get('target_only_count', 0)}`",
                f"- Shared with baseline: `{result.get('shared_count', 0)}`",
            ]
        )
    lines.extend(
        [
            "",
            "| Confidence | Diff | File | Offset | Type | Format | Evidence | Count | Reasons | Format Hints | Original Bytes |",
            "| ---: | --- | --- | ---: | --- | --- | --- | ---: | --- | --- | --- |",
        ]
    )
    rows = flatten_correlation_results(result)
    if not rows:
        lines.append("| - | - | - | - | - | - | No matches | - | - | - | - |")
        return "\n".join(lines) + "\n"
    for row in rows:
        file_path = str(row.get("file", "")).replace("|", "\\|")
        evidence = str(row.get("evidence_value", "")).replace("|", "\\|")
        original = str(row.get("original_bytes", "")).replace("|", "\\|")
        reasons = str(row.get("confidence_reasons", "")).replace("|", "\\|")
        format_hints = str(row.get("format_hint_summary", "")).replace("|", "\\|")
        lines.append(
            f"| {row.get('confidence', '')} | {row.get('diff_status', '')} | {file_path} | `{row.get('offset_hex', '')}` | {row.get('match_type', '')} | {row.get('file_format', '')} | {evidence} | {row.get('evidence_count', '')} | {reasons} | {format_hints} | `{original}` |"
        )
    return "\n".join(lines) + "\n"
