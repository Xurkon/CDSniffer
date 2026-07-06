from __future__ import annotations

import csv
import fnmatch
import json
import os
import struct
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any


HASH_INITVAL = 0x000C5EDE
IV_XOR = 0x60616263
XOR_DELTAS = (
    0x00000000,
    0x0A0A0A0A,
    0x0C0C0C0C,
    0x06060606,
    0x0E0E0E0E,
    0x0A0A0A0A,
    0x06060606,
    0x02020202,
)


class ArchiveError(RuntimeError):
    pass


class MissingArchiveDependency(ArchiveError):
    pass


class UnsupportedCompression(ArchiveError):
    pass


@dataclass(frozen=True)
class PazEntry:
    path: str
    paz_file: str
    offset: int
    comp_size: int
    orig_size: int
    flags: int
    paz_index: int
    pamt_file: str

    @property
    def compressed(self) -> bool:
        return self.comp_size != self.orig_size

    @property
    def compression_type(self) -> int:
        return (self.flags >> 16) & 0x0F

    @property
    def encrypted(self) -> bool:
        return self.path.lower().endswith(".xml")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "paz_file": self.paz_file,
            "pamt_file": self.pamt_file,
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:X}",
            "comp_size": self.comp_size,
            "orig_size": self.orig_size,
            "flags": self.flags,
            "flags_hex": f"0x{self.flags:X}",
            "paz_index": self.paz_index,
            "compressed": self.compressed,
            "compression_type": self.compression_type,
            "compression_name": compression_name(self.compression_type),
            "encrypted": self.encrypted,
        }


def compression_name(value: int) -> str:
    return {0: "none", 2: "lz4", 3: "custom", 4: "zlib"}.get(value, f"unknown-{value}")


def discover_pamt_files(root: Path) -> list[Path]:
    if root.is_file() and root.suffix.lower() == ".pamt":
        return [root]
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*.pamt") if path.is_file())


def parse_pamt(pamt_path: Path, paz_dir: Path | None = None) -> list[PazEntry]:
    data = pamt_path.read_bytes()
    if len(data) < 24:
        raise ArchiveError(f"PAMT file is too small: {pamt_path}")

    paz_dir = paz_dir or pamt_path.parent
    pamt_stem = pamt_path.stem
    offset = 0
    offset += 4
    paz_count = _unpack_u32(data, offset)
    offset += 4
    offset += 8

    for index in range(paz_count):
        offset += 8
        if index < paz_count - 1:
            offset += 4

    folder_size = _unpack_u32(data, offset)
    offset += 4
    folder_end = offset + folder_size
    folder_prefix = ""
    while offset < folder_end:
        parent = _unpack_u32(data, offset)
        name_len = data[offset + 4]
        name = data[offset + 5 : offset + 5 + name_len].decode("utf-8", errors="replace")
        if parent == 0xFFFFFFFF:
            folder_prefix = name
        offset += 5 + name_len

    node_size = _unpack_u32(data, offset)
    offset += 4
    node_start = offset
    nodes: dict[int, tuple[int, str]] = {}
    while offset < node_start + node_size:
        relative_offset = offset - node_start
        parent = _unpack_u32(data, offset)
        name_len = data[offset + 4]
        name = data[offset + 5 : offset + 5 + name_len].decode("utf-8", errors="replace")
        nodes[relative_offset] = (parent, name)
        offset += 5 + name_len

    folder_count = _unpack_u32(data, offset)
    offset += 8
    offset += folder_count * 16

    entries: list[PazEntry] = []
    while offset + 20 <= len(data):
        node_ref, paz_offset, comp_size, orig_size, flags = struct.unpack_from("<IIIII", data, offset)
        offset += 20
        paz_index = flags & 0xFF
        node_path = _build_path(nodes, node_ref)
        full_path = f"{folder_prefix}/{node_path}" if folder_prefix else node_path
        paz_num = int(pamt_stem) + paz_index if pamt_stem.isdigit() else paz_index
        entries.append(
            PazEntry(
                path=full_path,
                paz_file=str(paz_dir / f"{paz_num}.paz"),
                offset=paz_offset,
                comp_size=comp_size,
                orig_size=orig_size,
                flags=flags,
                paz_index=paz_index,
                pamt_file=str(pamt_path),
            )
        )
    return entries


def load_archive_entries(roots: list[Path], *, paz_dir: Path | None = None) -> list[PazEntry]:
    entries: list[PazEntry] = []
    for root in roots:
        for pamt_path in discover_pamt_files(root):
            entries.extend(parse_pamt(pamt_path, paz_dir=paz_dir or pamt_path.parent))
    return entries


def filter_archive_entries(entries: list[PazEntry], patterns: list[str] | None = None, limit: int | None = None) -> list[PazEntry]:
    filtered = entries
    if patterns:
        lowered_patterns = [pattern.lower() for pattern in patterns]
        filtered = [
            entry
            for entry in entries
            if any(
                fnmatch.fnmatch(entry.path.lower(), pattern)
                or fnmatch.fnmatch(Path(entry.path).name.lower(), pattern)
                or pattern in entry.path.lower()
                for pattern in lowered_patterns
            )
        ]
    if limit is not None:
        filtered = filtered[: max(0, limit)]
    return filtered


def build_archive_report(
    roots: list[Path],
    *,
    paz_dir: Path | None = None,
    patterns: list[str] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    entries = load_archive_entries(roots, paz_dir=paz_dir)
    filtered = filter_archive_entries(entries, patterns=patterns, limit=limit)
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "roots": [str(root) for root in roots],
        "patterns": patterns or ["*"],
        "total_entries": len(entries),
        "entry_count": len(filtered),
        "compressed_count": sum(1 for entry in filtered if entry.compressed),
        "encrypted_count": sum(1 for entry in filtered if entry.encrypted),
        "compression_counts": _compression_counts(filtered),
        "entries": [entry.to_dict() for entry in filtered],
    }


def extract_entries(
    entries: list[PazEntry],
    output_dir: Path,
    *,
    decrypt_xml: bool = True,
    dry_run: bool = False,
    overwrite: bool = True,
) -> dict[str, Any]:
    extracted: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    for entry in entries:
        try:
            if dry_run:
                result = {"entry": entry.to_dict(), "dry_run": True, "output_path": str(safe_output_path(output_dir, entry.path))}
            else:
                result = extract_entry(entry, output_dir, decrypt_xml=decrypt_xml, overwrite=overwrite)
            extracted.append(result)
        except Exception as exc:
            errors.append({"path": entry.path, "error": str(exc)})

    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "output_dir": str(output_dir),
        "entry_count": len(entries),
        "extracted_count": len(extracted),
        "error_count": len(errors),
        "decrypted_count": sum(1 for item in extracted if item.get("decrypted")),
        "decompressed_count": sum(1 for item in extracted if item.get("decompressed")),
        "dry_run": dry_run,
        "entries": extracted,
        "errors": errors,
    }


def extract_entry(entry: PazEntry, output_dir: Path, *, decrypt_xml: bool = True, overwrite: bool = True) -> dict[str, Any]:
    paz_path = Path(entry.paz_file)
    if not paz_path.exists():
        raise FileNotFoundError(f"PAZ file not found: {paz_path}")

    read_size = entry.comp_size if entry.comp_size > 0 else entry.orig_size
    with paz_path.open("rb") as handle:
        handle.seek(entry.offset)
        data = handle.read(read_size)
    if len(data) != read_size:
        raise ArchiveError(f"Short read for {entry.path}: expected {read_size}, got {len(data)}")

    decrypted = False
    decompressed = False
    if decrypt_xml and entry.encrypted:
        data = decrypt(data, Path(entry.path).name)
        decrypted = True

    if entry.compressed:
        data = decompress(data, entry.compression_type, entry.orig_size)
        decompressed = True

    out_path = safe_output_path(output_dir, entry.path)
    if out_path.exists() and not overwrite:
        raise FileExistsError(f"Output file already exists: {out_path}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)

    return {
        "entry": entry.to_dict(),
        "output_path": str(out_path),
        "size": len(data),
        "decrypted": decrypted,
        "decompressed": decompressed,
        "file_format": out_path.suffix.lower().lstrip(".") or "binary",
    }


def safe_output_path(output_dir: Path, entry_path: str) -> Path:
    normalized = entry_path.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part and part not in {".", ".."} and not part.endswith(":")]
    if not parts:
        raise ArchiveError(f"Invalid archive path: {entry_path}")
    return output_dir.joinpath(*parts)


def decrypt(data: bytes, filename: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    except ImportError as exc:
        raise MissingArchiveDependency("XML decryption requires cryptography. Install with: pip install .[unpack]") from exc

    key, iv = derive_key_iv(filename)
    cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None)
    return cipher.encryptor().update(data)


def decompress(data: bytes, compression_type: int, original_size: int) -> bytes:
    if compression_type == 0:
        return data
    if compression_type == 2:
        try:
            import lz4.block
        except ImportError as exc:
            raise MissingArchiveDependency("LZ4 decompression requires lz4. Install with: pip install .[unpack]") from exc
        return lz4.block.decompress(data, uncompressed_size=original_size)
    if compression_type == 4:
        return zlib.decompress(data)
    raise UnsupportedCompression(f"Unsupported PAZ compression type {compression_type} ({compression_name(compression_type)})")


def derive_key_iv(filename: str) -> tuple[bytes, bytes]:
    basename = os.path.basename(filename).lower()
    seed = hashlittle(basename.encode("utf-8"), HASH_INITVAL)
    iv = struct.pack("<I", seed) * 4
    key_base = seed ^ IV_XOR
    key = b"".join(struct.pack("<I", key_base ^ delta) for delta in XOR_DELTAS)
    return key, iv


def hashlittle(data: bytes, initval: int = 0) -> int:
    length = len(data)
    a = b = c = _add(0xDEADBEEF + length, initval)
    offset = 0

    while length > 12:
        a = _add(a, struct.unpack_from("<I", data, offset)[0])
        b = _add(b, struct.unpack_from("<I", data, offset + 4)[0])
        c = _add(c, struct.unpack_from("<I", data, offset + 8)[0])
        a = _sub(a, c)
        a ^= _rot(c, 4)
        c = _add(c, b)
        b = _sub(b, a)
        b ^= _rot(a, 6)
        a = _add(a, c)
        c = _sub(c, b)
        c ^= _rot(b, 8)
        b = _add(b, a)
        a = _sub(a, c)
        a ^= _rot(c, 16)
        c = _add(c, b)
        b = _sub(b, a)
        b ^= _rot(a, 19)
        a = _add(a, c)
        c = _sub(c, b)
        c ^= _rot(b, 4)
        b = _add(b, a)
        offset += 12
        length -= 12

    tail = data[offset:] + b"\x00" * 12
    if length >= 12:
        c = _add(c, struct.unpack_from("<I", tail, 8)[0])
    elif length >= 9:
        value = struct.unpack_from("<I", tail, 8)[0]
        c = _add(c, value & (0xFFFFFFFF >> (8 * (12 - length))))
    if length >= 8:
        b = _add(b, struct.unpack_from("<I", tail, 4)[0])
    elif length >= 5:
        value = struct.unpack_from("<I", tail, 4)[0]
        b = _add(b, value & (0xFFFFFFFF >> (8 * (8 - length))))
    if length >= 4:
        a = _add(a, struct.unpack_from("<I", tail, 0)[0])
    elif length >= 1:
        value = struct.unpack_from("<I", tail, 0)[0]
        a = _add(a, value & (0xFFFFFFFF >> (8 * (4 - length))))
    elif length == 0:
        return c

    c ^= b
    c = _sub(c, _rot(b, 14))
    a ^= c
    a = _sub(a, _rot(c, 11))
    b ^= a
    b = _sub(b, _rot(a, 25))
    c ^= b
    c = _sub(c, _rot(b, 16))
    a ^= c
    a = _sub(a, _rot(c, 4))
    b ^= a
    b = _sub(b, _rot(a, 14))
    c ^= b
    c = _sub(c, _rot(b, 24))
    return c


def render_archive_csv(report: dict[str, Any]) -> str:
    buffer = StringIO()
    fieldnames = [
        "path",
        "output_path",
        "size",
        "decrypted",
        "decompressed",
        "pamt_file",
        "paz_file",
        "offset_hex",
        "comp_size",
        "orig_size",
        "compression_name",
        "encrypted",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for item in report.get("entries", []):
        entry = item.get("entry", item) if isinstance(item, dict) else {}
        row = {field: entry.get(field, "") for field in fieldnames}
        if isinstance(item, dict) and "entry" in item:
            row.update(
                {
                    "output_path": item.get("output_path", ""),
                    "size": item.get("size", ""),
                    "decrypted": item.get("decrypted", ""),
                    "decompressed": item.get("decompressed", ""),
                }
            )
        writer.writerow(row)
    return buffer.getvalue()


def render_archive_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# CDSniffer Archive Report",
        "",
        f"- Roots: `{', '.join(report.get('roots', []))}`",
        f"- Total entries: `{report.get('total_entries', 0)}`",
        f"- Listed entries: `{report.get('entry_count', 0)}`",
        f"- Compressed: `{report.get('compressed_count', 0)}`",
        f"- Encrypted XML: `{report.get('encrypted_count', 0)}`",
        "",
        "| Path | PAZ | Offset | Stored | Original | Compression | Encrypted |",
        "| --- | --- | ---: | ---: | ---: | --- | --- |",
    ]
    entries = report.get("entries", [])
    if not entries:
        lines.append("| No entries | - | - | - | - | - | - |")
        return "\n".join(lines) + "\n"
    for item in entries:
        entry = item.get("entry", item) if isinstance(item, dict) else {}
        path = str(entry.get("path", "")).replace("|", "\\|")
        paz_file = Path(str(entry.get("paz_file", ""))).name
        lines.append(
            f"| {path} | {paz_file} | `{entry.get('offset_hex', '')}` | {entry.get('comp_size', '')} | {entry.get('orig_size', '')} | {entry.get('compression_name', '')} | {entry.get('encrypted', '')} |"
        )
    return "\n".join(lines) + "\n"


def _compression_counts(entries: list[PazEntry]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        name = compression_name(entry.compression_type)
        counts[name] = counts.get(name, 0) + 1
    return counts


def _build_path(nodes: dict[int, tuple[int, str]], node_ref: int) -> str:
    parts: list[str] = []
    current = node_ref
    while current != 0xFFFFFFFF and len(parts) < 256:
        if current not in nodes:
            break
        parent, name = nodes[current]
        parts.append(name)
        current = parent
    return "".join(reversed(parts))


def _unpack_u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise ArchiveError(f"Unexpected end of PAMT at offset 0x{offset:X}")
    return struct.unpack_from("<I", data, offset)[0]


def _rot(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def _add(left: int, right: int) -> int:
    return (left + right) & 0xFFFFFFFF


def _sub(left: int, right: int) -> int:
    return (left - right) & 0xFFFFFFFF
