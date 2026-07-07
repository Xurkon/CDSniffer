from __future__ import annotations

import csv
import fnmatch
import hashlib
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
PASSTHROUGH_COMPRESSION_TYPES = {0, 1}
KNOWN_DECODED_PREFIXES = (
    b"DDS ",
    b"PAR ",
    b"<?xml",
    b"<root",
    b"<",
    b"{",
    b"[",
    b"RIFF",
    b"BKHD",
    b"\x89PNG",
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
        return self.needs_decompression

    @property
    def stored_size_differs(self) -> bool:
        return self.comp_size != self.orig_size

    @property
    def compression_type(self) -> int:
        return (self.flags >> 16) & 0x0F

    @property
    def needs_decompression(self) -> bool:
        return self.compression_type not in PASSTHROUGH_COMPRESSION_TYPES

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
            "stored_size_differs": self.stored_size_differs,
            "needs_decompression": self.needs_decompression,
            "compression_type": self.compression_type,
            "compression_name": compression_name(self.compression_type),
            "encrypted": self.encrypted,
        }


@dataclass(frozen=True)
class PazDecoderSample:
    name: str
    compression_type: int
    compressed_sha256: str
    decoded_bytes: bytes
    source_manifest: str
    source_compressed: str
    source_decoded: str


def compression_name(value: int) -> str:
    return {0: "none", 1: "raw-asset", 2: "lz4", 3: "adaptive", 4: "zlib"}.get(value, f"unknown-{value}")


def load_decoder_samples(sample_roots: list[Path] | None) -> list[PazDecoderSample]:
    if not sample_roots:
        return []
    samples: list[PazDecoderSample] = []
    for root in sample_roots:
        manifest_path = _resolve_decoder_sample_manifest(Path(root))
        samples.extend(_load_decoder_samples_from_manifest(manifest_path))
    seen: dict[tuple[int, str], PazDecoderSample] = {}
    for sample in samples:
        key = (sample.compression_type, sample.compressed_sha256)
        existing = seen.get(key)
        if existing is not None and existing.decoded_bytes != sample.decoded_bytes:
            raise ArchiveError(
                "Conflicting decoder samples found for "
                f"type {sample.compression_type} and hash {sample.compressed_sha256}"
            )
        seen[key] = sample
    return list(seen.values())


def _resolve_decoder_sample_manifest(root: Path) -> Path:
    if root.is_file():
        if root.suffix.lower() != ".json":
            raise FileNotFoundError(f"Decoder sample manifest must be a JSON file or folder: {root}")
        if not root.exists():
            raise FileNotFoundError(f"Decoder sample manifest not found: {root}")
        return root
    if not root.exists():
        raise FileNotFoundError(f"Decoder sample root not found: {root}")
    if not root.is_dir():
        raise FileNotFoundError(f"Decoder sample root is not a folder: {root}")
    for candidate in (root / "decoder-samples.json", root / "paz-decoder-samples.json"):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"Decoder sample manifest not found in {root}. Expected decoder-samples.json or paz-decoder-samples.json."
    )


def _load_decoder_samples_from_manifest(manifest_path: Path) -> list[PazDecoderSample]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Decoder sample manifest must be a JSON object.")
    samples = payload.get("samples", [])
    if not isinstance(samples, list):
        raise ValueError("Decoder sample manifest samples must be a list.")
    decoded_samples: list[PazDecoderSample] = []
    for index, item in enumerate(samples):
        if not isinstance(item, dict):
            raise ValueError(f"Decoder sample #{index + 1} must be an object.")
        name = str(item.get("name", "")).strip()
        if not name:
            raise ValueError(f"Decoder sample #{index + 1} is missing a name.")
        compression_type = int(item.get("compression_type"))
        compressed_file = _resolve_sample_asset_path(manifest_path.parent, item, "compressed_file")
        decoded_file = _resolve_sample_asset_path(manifest_path.parent, item, "decoded_file")
        compressed_bytes = compressed_file.read_bytes()
        decoded_bytes = decoded_file.read_bytes()
        decoded_samples.append(
            PazDecoderSample(
                name=name,
                compression_type=compression_type,
                compressed_sha256=hashlib.sha256(compressed_bytes).hexdigest(),
                decoded_bytes=decoded_bytes,
                source_manifest=str(manifest_path),
                source_compressed=str(compressed_file),
                source_decoded=str(decoded_file),
            )
        )
    return decoded_samples


def _resolve_sample_asset_path(base_dir: Path, item: dict[str, Any], field: str) -> Path:
    raw = str(item.get(field, "")).strip()
    if not raw:
        raise ValueError(f"Decoder sample is missing {field}.")
    path = Path(raw)
    return path if path.is_absolute() else base_dir / path


def _match_decoder_sample(
    data: bytes,
    compression_type: int,
    decoder_samples: list[PazDecoderSample] | None,
) -> PazDecoderSample | None:
    if not decoder_samples:
        return None
    data_hash = hashlib.sha256(data).hexdigest()
    for sample in decoder_samples:
        if sample.compression_type == compression_type and sample.compressed_sha256 == data_hash:
            return sample
    return None


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
    validate_only: bool = False,
    overwrite: bool = True,
    decoder_samples: list[PazDecoderSample] | None = None,
) -> dict[str, Any]:
    dry_run = dry_run or validate_only
    extracted: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    for entry in entries:
        try:
            if dry_run and not validate_only:
                result = {"entry": entry.to_dict(), "dry_run": True, "output_path": str(safe_output_path(output_dir, entry.path))}
            else:
                result = extract_entry(
                    entry,
                    output_dir,
                    decrypt_xml=decrypt_xml,
                    overwrite=overwrite,
                    write_output=not dry_run,
                    decoder_samples=decoder_samples,
                )
                if dry_run:
                    result["dry_run"] = True
                    result["validated"] = True
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
        "validated_count": sum(1 for item in extracted if item.get("validated")),
        "dry_run": dry_run,
        "validation_only": validate_only,
        "entries": extracted,
        "errors": errors,
    }


def extract_entry(
    entry: PazEntry,
    output_dir: Path,
    *,
    decrypt_xml: bool = True,
    overwrite: bool = True,
    write_output: bool = True,
    decoder_samples: list[PazDecoderSample] | None = None,
) -> dict[str, Any]:
    paz_path = Path(entry.paz_file)
    if not paz_path.exists():
        raise FileNotFoundError(f"PAZ file not found: {paz_path}")

    read_size = entry.comp_size if entry.comp_size > 0 else entry.orig_size
    with paz_path.open("rb") as handle:
        handle.seek(entry.offset)
        data = handle.read(read_size)
    if len(data) != read_size:
        raise ArchiveError(f"Short read for {entry.path}: expected {read_size}, got {len(data)}")

    data, decode_info = decode_entry_bytes(entry, data, decrypt_xml=decrypt_xml, decoder_samples=decoder_samples)

    out_path = safe_output_path(output_dir, entry.path)
    if write_output and out_path.exists() and not overwrite:
        raise FileExistsError(f"Output file already exists: {out_path}")
    if write_output:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)

    return {
        "entry": entry.to_dict(),
        "output_path": str(out_path),
        "size": len(data),
        "decrypted": decode_info["decrypted"],
        "decompressed": decode_info["decompressed"],
        "compression_decoder": decode_info["compression_decoder"],
        "written": write_output,
        "file_format": out_path.suffix.lower().lstrip(".") or "binary",
    }


def read_entry_bytes(entry: PazEntry) -> bytes:
    paz_path = Path(entry.paz_file)
    if not paz_path.exists():
        raise FileNotFoundError(f"PAZ file not found: {paz_path}")

    read_size = entry.comp_size if entry.comp_size > 0 else entry.orig_size
    with paz_path.open("rb") as handle:
        handle.seek(entry.offset)
        data = handle.read(read_size)
    if len(data) != read_size:
        raise ArchiveError(f"Short read for {entry.path}: expected {read_size}, got {len(data)}")
    return data


def decode_entry_bytes(
    entry: PazEntry,
    data: bytes | None = None,
    *,
    decrypt_xml: bool = True,
    decoder_samples: list[PazDecoderSample] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    decoded = read_entry_bytes(entry) if data is None else data
    decrypted = False
    compression_decoder = "passthrough"

    if decrypt_xml and entry.encrypted:
        decoded = decrypt(decoded, Path(entry.path).name)
        decrypted = True

    if entry.needs_decompression:
        decoded, compression_decoder = decode_compression(
            decoded,
            entry.compression_type,
            entry.orig_size,
            decoder_samples=decoder_samples,
        )

    return decoded, {
        "size": len(decoded),
        "decrypted": decrypted,
        "decompressed": compression_decoder not in {"passthrough", "raw"},
        "compression_decoder": compression_decoder,
        "file_format": Path(entry.path).suffix.lower().lstrip(".") or "binary",
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


def decompress(
    data: bytes,
    compression_type: int,
    original_size: int,
    *,
    decoder_samples: list[PazDecoderSample] | None = None,
) -> bytes:
    return decode_compression(data, compression_type, original_size, decoder_samples=decoder_samples)[0]


def decode_compression(
    data: bytes,
    compression_type: int,
    original_size: int,
    *,
    decoder_samples: list[PazDecoderSample] | None = None,
) -> tuple[bytes, str]:
    if compression_type in PASSTHROUGH_COMPRESSION_TYPES:
        return data, "passthrough"
    if compression_type == 2:
        return _decode_lz4(data, original_size), "lz4"
    if compression_type == 3:
        try:
            return _decode_adaptive(data, original_size)
        except UnsupportedCompression:
            sample = _match_decoder_sample(data, compression_type, decoder_samples)
            if sample is not None:
                _validate_original_size(sample.decoded_bytes, original_size, f"sample:{sample.name}")
                return sample.decoded_bytes, f"sample:{sample.name}"
            raise
    if compression_type == 4:
        decoded = zlib.decompress(data)
        _validate_original_size(decoded, original_size, "zlib")
        return decoded, "zlib"
    sample = _match_decoder_sample(data, compression_type, decoder_samples)
    if sample is not None:
        _validate_original_size(sample.decoded_bytes, original_size, f"sample:{sample.name}")
        return sample.decoded_bytes, f"sample:{sample.name}"
    raise UnsupportedCompression(f"Unsupported PAZ compression type {compression_type} ({compression_name(compression_type)})")


def _decode_adaptive(data: bytes, original_size: int) -> tuple[bytes, str]:
    errors: list[str] = []
    if original_size == len(data) or _looks_decoded(data):
        return data, "raw"

    try:
        decoded = zlib.decompress(data)
        _validate_original_size(decoded, original_size, "adaptive-zlib")
        return decoded, "adaptive-zlib"
    except Exception as exc:
        errors.append(f"zlib: {exc}")

    try:
        return _decode_lz4(data, original_size), "adaptive-lz4"
    except Exception as exc:
        errors.append(f"lz4: {exc}")

    if _looks_decoded(data):
        return data, "raw"
    raise UnsupportedCompression(
        "Unsupported PAZ adaptive compression payload; tried raw, zlib, and LZ4. "
        + " | ".join(errors)
    )


def _decode_lz4(data: bytes, original_size: int) -> bytes:
    try:
        import lz4.block
    except ImportError as exc:
        raise MissingArchiveDependency("LZ4 decompression requires lz4. Install with: pip install .[unpack]") from exc
    decoded = lz4.block.decompress(data, uncompressed_size=original_size)
    _validate_original_size(decoded, original_size, "lz4")
    return decoded


def _validate_original_size(data: bytes, original_size: int, decoder: str) -> None:
    if original_size > 0 and len(data) != original_size:
        raise ArchiveError(f"{decoder} decoded size mismatch: expected {original_size}, got {len(data)}")


def _looks_decoded(data: bytes) -> bool:
    sample = data[:64].lstrip()
    if any(sample.startswith(prefix) for prefix in KNOWN_DECODED_PREFIXES):
        return True
    if not sample:
        return True
    printable = sum(1 for byte in sample if byte in b"\r\n\t" or 32 <= byte <= 126)
    return printable / len(sample) >= 0.85


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
