from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Iterable


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


def correlate_capture_to_files(
    capture_path: Path,
    root: Path,
    *,
    recursive: bool = True,
    patterns: list[str] | None = None,
    max_file_size: int = 64 * 1024 * 1024,
    max_matches_per_evidence: int = 20,
    max_total_matches: int = 500,
    include_numeric: bool = True,
    context_bytes: int = 16,
) -> dict[str, Any]:
    max_matches_per_evidence = max(1, max_matches_per_evidence)
    max_total_matches = max(1, max_total_matches)
    context_bytes = max(0, context_bytes)
    max_file_size = max(0, max_file_size)
    evidence_items = extract_evidence_from_capture(capture_path, include_numeric=include_numeric)
    files = iter_candidate_files(root, recursive=recursive, patterns=patterns, max_file_size=max_file_size)
    matches: list[dict[str, Any]] = []

    for file_path in files:
        if len(matches) >= max_total_matches:
            break
        try:
            blob = file_path.read_bytes()
        except OSError:
            continue
        for evidence in evidence_items:
            if len(matches) >= max_total_matches:
                break
            offsets = find_all_offsets(blob, evidence.data, limit=max_matches_per_evidence)
            if not offsets:
                continue
            for offset in offsets:
                start = max(0, offset - context_bytes)
                end = min(len(blob), offset + len(evidence.data) + context_bytes)
                original = blob[offset : offset + len(evidence.data)]
                matches.append(
                    {
                        "file": str(file_path),
                        "relative_file": str(file_path.relative_to(root)) if _is_relative_to(file_path, root) else str(file_path),
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
                        "confidence": _confidence_for_match(evidence, len(offsets), len(blob)),
                        "patch_skeleton": {
                            "type": "bytes",
                            "file": str(file_path.relative_to(root)) if _is_relative_to(file_path, root) else str(file_path),
                            "offset": offset,
                            "original": original.hex(" "),
                            "replacement": "",
                        },
                    }
                )
                if len(matches) >= max_total_matches:
                    break

    matches.sort(key=lambda item: (-float(item["confidence"]), str(item["relative_file"]), int(item["offset"])))
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "capture_path": str(capture_path),
        "root": str(root),
        "recursive": recursive,
        "patterns": patterns or ["*"],
        "max_file_size": max_file_size,
        "evidence_count": len(evidence_items),
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
            "match_type": match.get("match_type"),
            "evidence_value": match.get("evidence_value"),
            "hit_text": match.get("hit_text"),
            "original_bytes": match.get("original_bytes"),
            "module_rva_hex": match.get("module_rva_hex"),
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
        "match_type",
        "evidence_value",
        "hit_text",
        "original_bytes",
        "module_rva_hex",
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
        "",
        "| Confidence | File | Offset | Type | Evidence | Original Bytes |",
        "| ---: | --- | ---: | --- | --- | --- |",
    ]
    rows = flatten_correlation_results(result)
    if not rows:
        lines.append("| - | - | - | - | No matches | - |")
        return "\n".join(lines) + "\n"
    for row in rows:
        file_path = str(row.get("file", "")).replace("|", "\\|")
        evidence = str(row.get("evidence_value", "")).replace("|", "\\|")
        original = str(row.get("original_bytes", "")).replace("|", "\\|")
        lines.append(
            f"| {row.get('confidence', '')} | {file_path} | `{row.get('offset_hex', '')}` | {row.get('match_type', '')} | {evidence} | `{original}` |"
        )
    return "\n".join(lines) + "\n"
