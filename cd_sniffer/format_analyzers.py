from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


TEXT_SUFFIXES = {".json", ".jsonl", ".ndjson", ".txt", ".csv", ".tsv", ".xml", ".yml", ".yaml"}
STRUCTURED_SUFFIXES = {".json", ".jsonl", ".ndjson"}
PASEQ_SUFFIXES = {".paseq"}
IDENTIFIER_KEYS = {
    "id",
    "key",
    "index",
    "name",
    "internal_name",
    "internal name",
    "display_name",
    "display name",
    "mission",
    "quest",
    "node",
}


def analyze_match_format(
    file_path: Path,
    blob: bytes,
    offset: int,
    original: bytes,
    evidence_value: str,
    hit_text: str,
) -> dict[str, Any]:
    suffix = file_path.suffix.lower()
    file_format = _file_format(file_path, blob)
    hints: list[dict[str, Any]] = []

    if suffix in STRUCTURED_SUFFIXES:
        hints.extend(_json_hints(blob, offset, evidence_value, hit_text))
    elif _looks_like_text(blob):
        hints.extend(_text_hints(blob, offset))

    if suffix in PASEQ_SUFFIXES:
        hints.append(
            {
                "kind": "paseq-binary",
                "summary": "PASEQ binary candidate",
                "confidence_bonus": 0.02,
                "details": {"suffix": suffix},
            }
        )

    if file_format in {"binary", "paseq"}:
        hints.extend(_binary_hints(blob, offset, original))
    confidence_bonus = min(0.12, sum(float(item.get("confidence_bonus", 0.0) or 0.0) for item in hints))
    return {
        "file_format": file_format,
        "format_confidence_bonus": round(confidence_bonus, 3),
        "format_hints": hints[:8],
    }


def summarize_format_hints(hints: list[dict[str, Any]]) -> str:
    summaries: list[str] = []
    for hint in hints:
        summary = str(hint.get("summary", "")).strip()
        if summary and summary not in summaries:
            summaries.append(summary)
    return "; ".join(summaries)


def _file_format(file_path: Path, blob: bytes) -> str:
    suffix = file_path.suffix.lower().lstrip(".")
    if file_path.suffix.lower() in PASEQ_SUFFIXES:
        return "paseq"
    if suffix:
        return suffix
    if _looks_like_text(blob):
        return "text"
    return "binary"


def _looks_like_text(blob: bytes) -> bool:
    sample = blob[:4096]
    if not sample:
        return False
    printable = sum(1 for byte in sample if byte in b"\r\n\t" or 32 <= byte < 127)
    return printable / max(1, len(sample)) > 0.85


def _decode_text(blob: bytes) -> str | None:
    for encoding in ("utf-8-sig", "utf-16le", "latin-1"):
        try:
            text = blob.decode(encoding)
        except UnicodeDecodeError:
            continue
        if text:
            return text
    return None


def _line_column(text: str, offset: int) -> tuple[int, int]:
    prefix = text[:offset]
    line = prefix.count("\n") + 1
    last_newline = prefix.rfind("\n")
    column = offset + 1 if last_newline < 0 else offset - last_newline
    return line, column


def _json_hints(blob: bytes, offset: int, evidence_value: str, hit_text: str) -> list[dict[str, Any]]:
    text = _decode_text(blob)
    if text is None:
        return []

    line, column = _line_column(text, min(offset, len(text)))
    hints: list[dict[str, Any]] = [
        {
            "kind": "text-location",
            "summary": f"line {line}, column {column}",
            "confidence_bonus": 0.01,
            "line": line,
            "column": column,
        }
    ]

    parsed_items = _parse_json_payloads(text)
    if not parsed_items:
        return hints

    needles = [item for item in {evidence_value, hit_text} if item]
    for payload_index, payload in enumerate(parsed_items, start=1):
        for match in _walk_json(payload, needles):
            summary = _json_summary(match, payload_index)
            hints.append(
                {
                    "kind": "json-record",
                    "summary": summary,
                    "confidence_bonus": 0.05 if match.get("record_keys") else 0.035,
                    "path": match["path"],
                    "value": match["value"],
                    "details": {
                        "payload_index": payload_index,
                        "record_keys": match.get("record_keys", {}),
                    },
                }
            )
            if len(hints) >= 8:
                return hints
    return hints


def _parse_json_payloads(text: str) -> list[Any]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        return [json.loads(stripped)]
    except json.JSONDecodeError:
        payloads: list[Any] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                payloads.append(json.loads(line))
            except json.JSONDecodeError:
                return []
        return payloads


def _walk_json(payload: Any, needles: list[str], path: str = "$", record: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        current_record = payload if _looks_like_record(payload) else record
        for key, value in payload.items():
            child_path = f"{path}.{_safe_json_key(str(key))}"
            matches.extend(_walk_json(value, needles, child_path, current_record))
        return matches
    if isinstance(payload, list):
        for index, value in enumerate(payload):
            matches.extend(_walk_json(value, needles, f"{path}[{index}]", record))
        return matches

    value_text = str(payload)
    if any(needle and needle in value_text for needle in needles):
        matches.append(
            {
                "path": path,
                "value": value_text,
                "record_keys": _record_keys(record or {}),
            }
        )
    return matches


def _looks_like_record(payload: dict[str, Any]) -> bool:
    lowered = {str(key).replace("_", " ").lower() for key in payload.keys()}
    return bool(lowered & IDENTIFIER_KEYS) or len(payload) >= 3


def _record_keys(record: dict[str, Any]) -> dict[str, str]:
    keys: dict[str, str] = {}
    for key, value in record.items():
        normalized = str(key).replace("_", " ").lower()
        if normalized in IDENTIFIER_KEYS and not isinstance(value, (dict, list)):
            keys[str(key)] = str(value)
        if len(keys) >= 6:
            break
    return keys


def _json_summary(match: dict[str, Any], payload_index: int) -> str:
    record_keys = match.get("record_keys", {})
    if record_keys:
        preview = ", ".join(f"{key}={value}" for key, value in record_keys.items())
        return f"JSON record {payload_index}: {preview}"
    return f"JSON path {match['path']}"


def _safe_json_key(key: str) -> str:
    return key if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) else json.dumps(key)


def _text_hints(blob: bytes, offset: int) -> list[dict[str, Any]]:
    text = _decode_text(blob)
    if text is None:
        return []
    line, column = _line_column(text, min(offset, len(text)))
    return [
        {
            "kind": "text-location",
            "summary": f"line {line}, column {column}",
            "confidence_bonus": 0.01,
            "line": line,
            "column": column,
        }
    ]


def _binary_hints(blob: bytes, offset: int, original: bytes) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    number_candidates = _little_endian_candidates(blob, offset)
    if number_candidates:
        hints.append(
            {
                "kind": "little-endian-context",
                "summary": "nearby little-endian integers",
                "confidence_bonus": 0.025,
                "details": {"candidates": number_candidates[:8]},
            }
        )
    if len(original) in {2, 4, 8}:
        hints.append(
            {
                "kind": "matched-integer",
                "summary": f"matched {len(original) * 8}-bit little-endian value {int.from_bytes(original, 'little')}",
                "confidence_bonus": 0.025,
                "value": str(int.from_bytes(original, "little")),
                "details": {"size": len(original), "endian": "little"},
            }
        )
    neighbor_strings = _neighbor_strings(blob, offset)
    if neighbor_strings:
        hints.append(
            {
                "kind": "neighbor-strings",
                "summary": "nearby printable strings",
                "confidence_bonus": 0.015,
                "details": {"strings": neighbor_strings[:6]},
            }
        )
    return hints


def _little_endian_candidates(blob: bytes, offset: int, radius: int = 16) -> list[dict[str, Any]]:
    start = max(0, offset - radius)
    end = min(len(blob), offset + radius)
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    for size in (2, 4, 8):
        for pos in range(start, max(start, end - size + 1)):
            raw = blob[pos : pos + size]
            value = int.from_bytes(raw, "little")
            if value in {0, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}:
                continue
            if not (1 <= value <= 10_000_000):
                continue
            key = (pos, size)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({"offset": pos, "offset_hex": f"0x{pos:X}", "size": size, "value": value, "hex": raw.hex(" ")})
    return candidates[:24]


def _neighbor_strings(blob: bytes, offset: int, radius: int = 96) -> list[str]:
    window = blob[max(0, offset - radius) : min(len(blob), offset + radius)]
    strings: list[str] = []
    current: list[int] = []
    for byte in window:
        if 32 <= byte < 127:
            current.append(byte)
            continue
        if len(current) >= 4:
            value = bytes(current).decode("ascii", errors="ignore")
            if value not in strings:
                strings.append(value)
        current = []
    if len(current) >= 4:
        value = bytes(current).decode("ascii", errors="ignore")
        if value not in strings:
            strings.append(value)
    return strings
