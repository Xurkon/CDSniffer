from __future__ import annotations

import csv
import fnmatch
import hashlib
import json
import shutil
import sqlite3
from collections import Counter
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Iterable

from .correlator import (
    Evidence,
    _aggregate_confidence,
    _append_unique,
    _confidence_for_match,
    _evidence_entry,
    _merge_format_hints,
    extract_evidence_from_capture,
    find_all_offsets,
)
from .format_analyzers import analyze_match_format, summarize_format_hints
from .paz_archive import PazDecoderSample, PazEntry, decode_entry_bytes, filter_archive_entries, load_archive_entries


ARCHIVE_INDEX_SCHEMA_VERSION = 1
DEFAULT_ARCHIVE_CORRELATION_PATTERNS = ["*.paseq", "*.json", "*.jsonl", "*.xml", "*.pac_xml", "*.app_xml"]


@dataclass(frozen=True)
class IndexedArchiveEntry:
    id: int | None
    root: str
    path: str
    extension: str
    pamt_file: str
    paz_file: str
    offset: int
    comp_size: int
    orig_size: int
    flags: int
    paz_index: int
    compression_type: int
    compression_name: str
    encrypted: bool
    stored_size_differs: bool
    needs_decompression: bool
    paz_mtime_ns: int | None
    paz_size: int | None

    def to_paz_entry(self) -> PazEntry:
        return PazEntry(
            path=self.path,
            paz_file=self.paz_file,
            offset=self.offset,
            comp_size=self.comp_size,
            orig_size=self.orig_size,
            flags=self.flags,
            paz_index=self.paz_index,
            pamt_file=self.pamt_file,
        )

    def cache_key(self) -> str:
        identity = "|".join(
            [
                self.path,
                self.paz_file,
                str(self.offset),
                str(self.comp_size),
                str(self.orig_size),
                str(self.flags),
                str(self.paz_mtime_ns or ""),
                str(self.paz_size or ""),
            ]
        )
        return hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()


    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "root": self.root,
            "path": self.path,
            "extension": self.extension,
            "pamt_file": self.pamt_file,
            "paz_file": self.paz_file,
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:X}",
            "comp_size": self.comp_size,
            "orig_size": self.orig_size,
            "flags": self.flags,
            "flags_hex": f"0x{self.flags:X}",
            "paz_index": self.paz_index,
            "compression_type": self.compression_type,
            "compression_name": self.compression_name,
            "encrypted": self.encrypted,
            "stored_size_differs": self.stored_size_differs,
            "needs_decompression": self.needs_decompression,
            "paz_mtime_ns": self.paz_mtime_ns,
            "paz_size": self.paz_size,
            "cache_key": self.cache_key(),
        }


def archive_match_output_path(output_dir: Path, archive_path: str, fallback_name: str) -> Path:
    normalized = archive_path.replace("\\", "/").strip()
    raw_parts = [part.strip() for part in normalized.split("/") if part.strip() and part.strip() not in {".", ".."}]
    if any(":" in part for part in raw_parts):
        raise ValueError(f"Archive path contains an unsafe drive or stream marker: {archive_path}")
    safe_parts = raw_parts
    if not safe_parts:
        safe_parts = [fallback_name or "decoded-entry.bin"]
    target = output_dir.joinpath(*safe_parts)
    output_root = output_dir.resolve()
    resolved_target = target.resolve()
    if output_root != resolved_target and output_root not in resolved_target.parents:
        raise ValueError(f"Archive path would escape output directory: {archive_path}")
    return target


def export_cached_archive_match(match: dict[str, Any], output_dir: Path, *, overwrite: bool = True) -> dict[str, Any]:
    cache_text = str(match.get("cache_path") or "").strip()
    if not cache_text:
        raise ValueError("Selected match does not include a decoded cache path")
    cache_path = Path(cache_text)
    if not cache_path.exists() or not cache_path.is_file():
        raise FileNotFoundError(f"Decoded cache file not found: {cache_path}")
    archive_path = str(match.get("archive_path") or cache_path.name)
    target_path = archive_match_output_path(output_dir, archive_path, cache_path.name)
    if target_path.exists() and not overwrite:
        raise FileExistsError(f"Output file already exists: {target_path}")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(cache_path, target_path)
    sidecar_path = target_path.with_suffix(target_path.suffix + ".cdsniffer.json")
    metadata = {
        "source": "archive-correlation-cache",
        "archive_path": archive_path,
        "cache_path": str(cache_path),
        "output_path": str(target_path),
        "decoded_offset": match.get("decoded_offset"),
        "decoded_offset_hex": match.get("decoded_offset_hex"),
        "archive_offset": match.get("archive_offset"),
        "archive_offset_hex": match.get("archive_offset_hex"),
        "paz_file": match.get("paz_file"),
        "pamt_file": match.get("pamt_file"),
        "compression_name": match.get("compression_name"),
        "compression_decoder": match.get("compression_decoder"),
        "decrypted": match.get("decrypted"),
        "decompressed": match.get("decompressed"),
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }
    sidecar_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"output_path": str(target_path), "metadata_path": str(sidecar_path), "archive_path": archive_path}


def build_archive_index(
    db_path: Path,
    roots: list[Path],
    *,
    paz_dir: Path | None = None,
    patterns: list[str] | None = None,
    limit: int | None = None,
    replace: bool = True,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    entries = load_archive_entries(roots, paz_dir=paz_dir)
    entries = filter_archive_entries(entries, patterns=patterns, limit=limit)
    indexed_entries: list[IndexedArchiveEntry] = []
    total = len(entries)
    if progress_callback is not None:
        progress_callback(0, total, None)
    step = max(1, total // 20) if total else 1
    for index, entry in enumerate(entries, start=1):
        indexed_entries.append(_indexed_entry_from_paz(entry, roots))
        if progress_callback is not None and (index == 1 or index == total or index % step == 0):
            progress_callback(index, total, entry.path)

    with closing(sqlite3.connect(db_path)) as conn:
        if replace:
            conn.execute("DROP TABLE IF EXISTS entries")
            conn.execute("DROP TABLE IF EXISTS metadata")
        _init_db(conn)
        conn.executemany(
            """
            INSERT INTO entries (
                root, path, extension, pamt_file, paz_file, offset, comp_size, orig_size,
                flags, paz_index, compression_type, compression_name, encrypted,
                stored_size_differs, needs_decompression, paz_mtime_ns, paz_size, cache_key
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [_entry_insert_row(entry) for entry in indexed_entries],
        )
        metadata = {
            "schema_version": str(ARCHIVE_INDEX_SCHEMA_VERSION),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "roots": json.dumps([str(root) for root in roots], ensure_ascii=False),
            "patterns": json.dumps(patterns or ["*"], ensure_ascii=False),
        }
        conn.executemany("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)", metadata.items())
        conn.commit()

    compression_counts = Counter(entry.compression_name for entry in indexed_entries)
    extension_counts = Counter(entry.extension or "<none>" for entry in indexed_entries)
    return {
        "schema_version": ARCHIVE_INDEX_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "db_path": str(db_path),
        "roots": [str(root) for root in roots],
        "patterns": patterns or ["*"],
        "indexed_count": len(indexed_entries),
        "compression_counts": dict(sorted(compression_counts.items())),
        "extension_counts": dict(extension_counts.most_common(25)),
    }


def select_archive_entries(
    db_path: Path,
    *,
    patterns: list[str] | None = None,
    extensions: list[str] | None = None,
    path_terms: list[str] | None = None,
    limit: int | None = None,
) -> list[IndexedArchiveEntry]:
    if not db_path.exists():
        raise FileNotFoundError(f"Archive index not found: {db_path}")
    normalized_extensions = _normalize_extensions(extensions) or _extensions_from_patterns(patterns)
    where: list[str] = []
    params: list[Any] = []
    if normalized_extensions:
        placeholders = ", ".join("?" for _ in normalized_extensions)
        where.append(f"extension IN ({placeholders})")
        params.extend(normalized_extensions)
    if path_terms:
        term_clauses = []
        for term in path_terms:
            cleaned = term.strip().lower()
            if not cleaned:
                continue
            term_clauses.append("lower(path) LIKE ?")
            params.append(f"%{cleaned}%")
        if term_clauses:
            where.append("(" + " OR ".join(term_clauses) + ")")

    sql = "SELECT * FROM entries"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY path"

    selected: list[IndexedArchiveEntry] = []
    lowered_patterns = [pattern.lower() for pattern in patterns or []]
    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(sql, params)
        try:
            for row in cursor:
                entry = _indexed_entry_from_row(row)
                if lowered_patterns and not _matches_any_pattern(entry.path, lowered_patterns):
                    continue
                selected.append(entry)
                if limit is not None and len(selected) >= limit:
                    break
        finally:
            cursor.close()
    return selected


def cache_decoded_entry(
    entry: IndexedArchiveEntry,
    cache_dir: Path,
    *,
    decrypt_xml: bool = True,
    decoder_samples: list[PazDecoderSample] | None = None,
) -> tuple[Path, bytes, dict[str, Any]]:
    key = entry.cache_key()
    suffix = _cache_suffix(entry.path)
    cache_path = cache_dir / "decoded" / key[:2] / f"{key}{suffix}"
    metadata_path = cache_path.with_suffix(cache_path.suffix + ".json")
    if cache_path.exists():
        data = cache_path.read_bytes()
        metadata = _read_cache_metadata(metadata_path)
        metadata.update({"from_cache": True, "cache_path": str(cache_path), "size": len(data)})
        return cache_path, data, metadata

    data, decode_info = decode_entry_bytes(
        entry.to_paz_entry(),
        decrypt_xml=decrypt_xml,
        decoder_samples=decoder_samples,
    )
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(data)
    metadata = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "from_cache": False,
        "cache_path": str(cache_path),
        "archive_entry": entry.to_dict(),
        **decode_info,
    }
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    return cache_path, data, metadata


def correlate_capture_to_archive(
    capture_path: Path,
    index_db: Path,
    cache_dir: Path,
    *,
    patterns: list[str] | None = None,
    path_terms: list[str] | None = None,
    max_entries: int = 2000,
    max_matches_per_evidence: int = 20,
    max_total_matches: int = 500,
    include_numeric: bool = True,
    context_bytes: int = 16,
    include_format_hints: bool = True,
    decrypt_xml: bool = True,
    decoder_samples: list[PazDecoderSample] | None = None,
) -> dict[str, Any]:
    max_entries = max(1, max_entries)
    max_matches_per_evidence = max(1, max_matches_per_evidence)
    max_total_matches = max(1, max_total_matches)
    context_bytes = max(0, context_bytes)
    active_patterns = patterns or DEFAULT_ARCHIVE_CORRELATION_PATTERNS
    evidence_items = extract_evidence_from_capture(capture_path, include_numeric=include_numeric)
    entries = select_archive_entries(index_db, patterns=active_patterns, path_terms=path_terms, limit=max_entries)

    raw_matches: list[dict[str, Any]] = []
    decode_errors: list[dict[str, str]] = []
    decoded_count = 0
    cache_hit_count = 0
    raw_limit = max_total_matches * 4
    truncated = False
    for entry in entries:
        if len(raw_matches) >= raw_limit:
            truncated = True
            break
        try:
            cache_path, blob, cache_info = cache_decoded_entry(
                entry,
                cache_dir,
                decrypt_xml=decrypt_xml,
                decoder_samples=decoder_samples,
            )
            decoded_count += 1
            if cache_info.get("from_cache"):
                cache_hit_count += 1
        except Exception as exc:
            decode_errors.append({"path": entry.path, "error": str(exc)})
            continue

        raw_matches.extend(
            _collect_archive_entry_matches(
                entry,
                cache_path,
                blob,
                evidence_items,
                cache_info,
                max_matches_per_evidence=max_matches_per_evidence,
                max_total_matches=raw_limit - len(raw_matches),
                context_bytes=context_bytes,
                include_format_hints=include_format_hints,
            )
        )
        if len(raw_matches) >= raw_limit:
            truncated = True

    matches = aggregate_archive_correlation_matches(raw_matches)
    matches.sort(key=lambda item: (-float(item["confidence"]), str(item["archive_path"]), int(item["decoded_offset"])))
    pre_limit_match_count = len(matches)
    if pre_limit_match_count > max_total_matches:
        truncated = True
    matches = matches[:max_total_matches]
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "capture_path": str(capture_path),
        "index_db": str(index_db),
        "cache_dir": str(cache_dir),
        "patterns": active_patterns,
        "path_terms": path_terms or [],
        "evidence_count": len(evidence_items),
        "candidate_entry_count": len(entries),
        "decoded_entry_count": decoded_count,
        "cache_hit_count": cache_hit_count,
        "decode_error_count": len(decode_errors),
        "raw_match_count": len(raw_matches),
        "raw_match_limit": raw_limit,
        "pre_limit_match_count": pre_limit_match_count,
        "truncated": truncated,
        "truncated_at_raw_match_count": len(raw_matches) if truncated else None,
        "format_hint_count": sum(len(match.get("format_hints", [])) for match in matches),
        "match_count": len(matches),
        "matches": matches,
        "decode_errors": decode_errors[:100],
    }


def aggregate_archive_correlation_matches(raw_matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, int, str], dict[str, Any]] = {}
    for match in raw_matches:
        key = (
            str(match.get("archive_path", "")),
            int(match.get("decoded_offset", 0) or 0),
            str(match.get("original_bytes", "")),
        )
        if key not in grouped:
            grouped[key] = {
                "file": match.get("file"),
                "relative_file": match.get("relative_file"),
                "archive_path": match.get("archive_path"),
                "cache_path": match.get("cache_path"),
                "decoded_offset": match.get("decoded_offset"),
                "decoded_offset_hex": match.get("decoded_offset_hex"),
                "paz_file": match.get("paz_file"),
                "pamt_file": match.get("pamt_file"),
                "archive_offset": match.get("archive_offset"),
                "archive_offset_hex": match.get("archive_offset_hex"),
                "compression_name": match.get("compression_name"),
                "compression_decoder": match.get("compression_decoder"),
                "decrypted": match.get("decrypted"),
                "decompressed": match.get("decompressed"),
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


def render_archive_index_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# CDSniffer Archive Index",
        "",
        f"- Database: `{report.get('db_path', '')}`",
        f"- Indexed entries: `{report.get('indexed_count', 0)}`",
        f"- Roots: `{', '.join(report.get('roots', []))}`",
        "",
        "## Compression",
    ]
    for name, count in report.get("compression_counts", {}).items():
        lines.append(f"- `{name}`: `{count}`")
    lines.extend(["", "## Top Extensions"])
    for extension, count in report.get("extension_counts", {}).items():
        lines.append(f"- `{extension}`: `{count}`")
    return "\n".join(lines) + "\n"


def render_archive_index_csv(report: dict[str, Any]) -> str:
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=["category", "name", "count"])
    writer.writeheader()
    writer.writerow({"category": "summary", "name": "indexed_count", "count": report.get("indexed_count", 0)})
    for name, count in report.get("compression_counts", {}).items():
        writer.writerow({"category": "compression", "name": name, "count": count})
    for extension, count in report.get("extension_counts", {}).items():
        writer.writerow({"category": "extension", "name": extension, "count": count})
    return buffer.getvalue()


def render_archive_correlation_csv(result: dict[str, Any]) -> str:
    rows = flatten_archive_correlation_results(result)
    buffer = StringIO()
    fieldnames = [
        "archive_path",
        "decoded_offset_hex",
        "confidence",
        "evidence_count",
        "match_type",
        "file_format",
        "compression_name",
        "compression_decoder",
        "evidence_value",
        "hit_text",
        "original_bytes",
        "paz_file",
        "cache_path",
        "confidence_reasons",
        "format_hint_summary",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def render_archive_correlation_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# CDSniffer Archive Correlation Results",
        "",
        f"- Capture: `{result.get('capture_path', '')}`",
        f"- Index: `{result.get('index_db', '')}`",
        f"- Cache: `{result.get('cache_dir', '')}`",
        f"- Evidence: `{result.get('evidence_count', 0)}`",
        f"- Candidate entries: `{result.get('candidate_entry_count', 0)}`",
        f"- Decoded entries: `{result.get('decoded_entry_count', 0)}`",
        f"- Cache hits: `{result.get('cache_hit_count', 0)}`",
        f"- Decode errors: `{result.get('decode_error_count', 0)}`",
        f"- Matches: `{result.get('match_count', 0)}`",
        "",
        "| Confidence | Archive Path | Offset | Type | Format | Decoder | Evidence | Count | Reasons | Format Hints | Original Bytes |",
        "| ---: | --- | ---: | --- | --- | --- | --- | ---: | --- | --- | --- |",
    ]
    rows = flatten_archive_correlation_results(result)
    if not rows:
        lines.append("| - | No matches | - | - | - | - | - | - | - | - | - |")
        return "\n".join(lines) + "\n"
    for row in rows:
        archive_path = str(row.get("archive_path", "")).replace("|", "\\|")
        evidence = str(row.get("evidence_value", "")).replace("|", "\\|")
        reasons = str(row.get("confidence_reasons", "")).replace("|", "\\|")
        format_hints = str(row.get("format_hint_summary", "")).replace("|", "\\|")
        original = str(row.get("original_bytes", "")).replace("|", "\\|")
        lines.append(
            f"| {row.get('confidence', '')} | {archive_path} | `{row.get('decoded_offset_hex', '')}` | {row.get('match_type', '')} | {row.get('file_format', '')} | {row.get('compression_decoder', '')} | {evidence} | {row.get('evidence_count', '')} | {reasons} | {format_hints} | `{original}` |"
        )
    return "\n".join(lines) + "\n"


def flatten_archive_correlation_results(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "archive_path": match.get("archive_path"),
            "decoded_offset_hex": match.get("decoded_offset_hex"),
            "confidence": match.get("confidence"),
            "evidence_count": match.get("evidence_count"),
            "match_type": match.get("match_type"),
            "file_format": match.get("file_format"),
            "compression_name": match.get("compression_name"),
            "compression_decoder": match.get("compression_decoder"),
            "evidence_value": match.get("evidence_value"),
            "hit_text": match.get("hit_text"),
            "original_bytes": match.get("original_bytes"),
            "paz_file": Path(str(match.get("paz_file", ""))).name,
            "cache_path": match.get("cache_path"),
            "confidence_reasons": ", ".join(str(item) for item in match.get("confidence_reasons", [])),
            "format_hint_summary": match.get("format_hint_summary"),
        }
        for match in result.get("matches", [])
    ]


def _collect_archive_entry_matches(
    entry: IndexedArchiveEntry,
    cache_path: Path,
    blob: bytes,
    evidence_items: list[Evidence],
    cache_info: dict[str, Any],
    *,
    max_matches_per_evidence: int,
    max_total_matches: int,
    context_bytes: int,
    include_format_hints: bool,
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
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
            format_info = (
                analyze_match_format(cache_path, blob, offset, original, evidence.value, evidence.hit_text)
                if include_format_hints
                else {"file_format": cache_path.suffix.lower().lstrip(".") or "binary", "format_confidence_bonus": 0.0, "format_hints": []}
            )
            matches.append(
                {
                    "file": str(cache_path),
                    "relative_file": entry.path,
                    "archive_path": entry.path,
                    "cache_path": str(cache_path),
                    "decoded_offset": offset,
                    "decoded_offset_hex": f"0x{offset:X}",
                    "offset": offset,
                    "offset_hex": f"0x{offset:X}",
                    "paz_file": entry.paz_file,
                    "pamt_file": entry.pamt_file,
                    "archive_offset": entry.offset,
                    "archive_offset_hex": f"0x{entry.offset:X}",
                    "compression_name": entry.compression_name,
                    "compression_decoder": cache_info.get("compression_decoder"),
                    "decrypted": bool(cache_info.get("decrypted")),
                    "decompressed": bool(cache_info.get("decompressed")),
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
                        "file": entry.path,
                        "offset": offset,
                        "original": original.hex(" "),
                        "replacement": "",
                    },
                }
            )
            if len(matches) >= max_total_matches:
                break
    return matches


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            root TEXT NOT NULL,
            path TEXT NOT NULL,
            extension TEXT NOT NULL,
            pamt_file TEXT NOT NULL,
            paz_file TEXT NOT NULL,
            offset INTEGER NOT NULL,
            comp_size INTEGER NOT NULL,
            orig_size INTEGER NOT NULL,
            flags INTEGER NOT NULL,
            paz_index INTEGER NOT NULL,
            compression_type INTEGER NOT NULL,
            compression_name TEXT NOT NULL,
            encrypted INTEGER NOT NULL,
            stored_size_differs INTEGER NOT NULL,
            needs_decompression INTEGER NOT NULL,
            paz_mtime_ns INTEGER,
            paz_size INTEGER,
            cache_key TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_path ON entries(path)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_extension ON entries(extension)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_compression ON entries(compression_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_cache_key ON entries(cache_key)")
    conn.execute(f"PRAGMA user_version = {ARCHIVE_INDEX_SCHEMA_VERSION}")


def _indexed_entry_from_paz(entry: PazEntry, roots: list[Path]) -> IndexedArchiveEntry:
    paz_stat = _path_stat(Path(entry.paz_file))
    return IndexedArchiveEntry(
        id=None,
        root=_best_root_for_entry(entry, roots),
        path=entry.path,
        extension=Path(entry.path).suffix.lower(),
        pamt_file=entry.pamt_file,
        paz_file=entry.paz_file,
        offset=entry.offset,
        comp_size=entry.comp_size,
        orig_size=entry.orig_size,
        flags=entry.flags,
        paz_index=entry.paz_index,
        compression_type=entry.compression_type,
        compression_name=entry.to_dict()["compression_name"],
        encrypted=entry.encrypted,
        stored_size_differs=entry.stored_size_differs,
        needs_decompression=entry.needs_decompression,
        paz_mtime_ns=paz_stat[0],
        paz_size=paz_stat[1],
    )


def _indexed_entry_from_row(row: sqlite3.Row) -> IndexedArchiveEntry:
    return IndexedArchiveEntry(
        id=int(row["id"]),
        root=str(row["root"]),
        path=str(row["path"]),
        extension=str(row["extension"]),
        pamt_file=str(row["pamt_file"]),
        paz_file=str(row["paz_file"]),
        offset=int(row["offset"]),
        comp_size=int(row["comp_size"]),
        orig_size=int(row["orig_size"]),
        flags=int(row["flags"]),
        paz_index=int(row["paz_index"]),
        compression_type=int(row["compression_type"]),
        compression_name=str(row["compression_name"]),
        encrypted=bool(row["encrypted"]),
        stored_size_differs=bool(row["stored_size_differs"]),
        needs_decompression=bool(row["needs_decompression"]),
        paz_mtime_ns=int(row["paz_mtime_ns"]) if row["paz_mtime_ns"] is not None else None,
        paz_size=int(row["paz_size"]) if row["paz_size"] is not None else None,
    )


def _entry_insert_row(entry: IndexedArchiveEntry) -> tuple[Any, ...]:
    return (
        entry.root,
        entry.path,
        entry.extension,
        entry.pamt_file,
        entry.paz_file,
        entry.offset,
        entry.comp_size,
        entry.orig_size,
        entry.flags,
        entry.paz_index,
        entry.compression_type,
        entry.compression_name,
        int(entry.encrypted),
        int(entry.stored_size_differs),
        int(entry.needs_decompression),
        entry.paz_mtime_ns,
        entry.paz_size,
        entry.cache_key(),
    )


def _path_stat(path: Path) -> tuple[int | None, int | None]:
    try:
        stat = path.stat()
    except OSError:
        return None, None
    return stat.st_mtime_ns, stat.st_size


def _best_root_for_entry(entry: PazEntry, roots: list[Path]) -> str:
    pamt_path = Path(entry.pamt_file)
    for root in roots:
        try:
            pamt_path.relative_to(root)
            return str(root)
        except ValueError:
            continue
    return str(pamt_path.parent)


def _matches_any_pattern(path: str, lowered_patterns: list[str]) -> bool:
    lowered = path.lower()
    name = Path(path).name.lower()
    return any(fnmatch.fnmatch(lowered, pattern) or fnmatch.fnmatch(name, pattern) or pattern in lowered for pattern in lowered_patterns)


def _normalize_extensions(extensions: Iterable[str] | None) -> list[str]:
    normalized: list[str] = []
    for extension in extensions or []:
        item = extension.strip().lower()
        if not item:
            continue
        if not item.startswith("."):
            item = "." + item
        if item not in normalized:
            normalized.append(item)
    return normalized


def _extensions_from_patterns(patterns: list[str] | None) -> list[str]:
    extensions: list[str] = []
    for pattern in patterns or []:
        cleaned = pattern.strip().lower()
        if cleaned.startswith("*.") and cleaned.count("*") == 1 and "?" not in cleaned and "/" not in cleaned and "\\" not in cleaned:
            extension = cleaned[1:]
            if extension not in extensions:
                extensions.append(extension)
    return extensions


def _cache_suffix(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if not suffix or len(suffix) > 24:
        return ".bin"
    safe = "".join(char for char in suffix if char.isalnum() or char in {"_", ".", "-"})
    return safe or ".bin"


def _read_cache_metadata(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}
