from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any

from .windows import (
    is_readable_region,
    iter_memory_regions,
    list_process_modules,
    memory_state_name,
    memory_type_name,
    protection_name,
    read_memory,
)

ASCII_RE = re.compile(rb"[ -~]{4,}")
UTF16_RE = re.compile(rb"(?:[ -~]\x00){4,}")


@dataclass(frozen=True)
class MemoryHit:
    address: int
    encoding: str
    text: str
    region_offset: int = 0
    module_rva: int | None = None
    raw_size: int = 0
    context: dict[str, Any] | None = None


@dataclass(frozen=True)
class RegionScan:
    base_address: int
    region_size: int
    hits: tuple[MemoryHit, ...]
    allocation_base: int | None = None
    allocation_protect: int | None = None
    allocation_protection: str | None = None
    state: int | None = None
    state_name: str | None = None
    protect: int | None = None
    protection: str | None = None
    type: int | None = None
    type_name: str | None = None
    module: dict[str, object] | None = None


def extract_strings(blob: bytes) -> list[tuple[int, str, str, int]]:
    hits: list[tuple[int, str, str, int]] = []
    for match in ASCII_RE.finditer(blob):
        raw = match.group(0)
        hits.append((match.start(), "ascii", raw.decode("ascii", "ignore"), len(raw)))
    for match in UTF16_RE.finditer(blob):
        raw = match.group(0)
        hits.append((match.start(), "utf16le", raw.decode("utf-16le", "ignore"), len(raw)))
    return hits


def _contains_any(text: str, keywords: list[str]) -> bool:
    lowered = text.lower()
    return any(keyword.lower() in lowered for keyword in keywords)


def _compile_patterns(patterns: list[str] | None) -> list[re.Pattern[str]]:
    return [re.compile(pattern, re.IGNORECASE) for pattern in (patterns or [])]


def _matches_any_pattern(text: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def filter_hits(
    strings: list[tuple[str, str]] | list[tuple[int, str, str]] | list[tuple[int, str, str, int]],
    include_keywords: list[str],
    exclude_keywords: list[str] | None = None,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> list[MemoryHit]:
    lowered_keywords = [keyword.lower() for keyword in include_keywords]
    lowered_excludes = [keyword.lower() for keyword in (exclude_keywords or [])]
    compiled_includes = _compile_patterns(include_patterns)
    compiled_excludes = _compile_patterns(exclude_patterns)
    filtered: list[MemoryHit] = []
    seen: set[tuple[str, str]] = set()
    for item in strings:
        if len(item) == 4:
            offset, encoding, text, raw_size = item
        elif len(item) == 3:
            offset, encoding, text = item
            raw_size = len(str(text).encode("utf-16le" if encoding == "utf16le" else "ascii", "ignore"))
        else:
            offset = 0
            encoding, text = item
            raw_size = len(str(text).encode("utf-16le" if encoding == "utf16le" else "ascii", "ignore"))
        normalized = text.strip()
        if not normalized:
            continue
        lowered = normalized.lower()
        if lowered_excludes and any(keyword in lowered for keyword in lowered_excludes):
            continue
        if compiled_excludes and _matches_any_pattern(normalized, compiled_excludes):
            continue
        include_match = False
        if lowered_keywords and any(keyword in lowered for keyword in lowered_keywords):
            include_match = True
        if compiled_includes and _matches_any_pattern(normalized, compiled_includes):
            include_match = True
        if not lowered_keywords and not compiled_includes:
            include_match = True
        if not include_match:
            continue
        key = (encoding, normalized)
        if key in seen:
            continue
        seen.add(key)
        filtered.append(
            MemoryHit(
                address=int(offset),
                region_offset=int(offset),
                module_rva=None,
                encoding=encoding,
                text=normalized,
                raw_size=raw_size,
            )
        )
    return filtered


def _printable_ascii(blob: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in blob)


def _decode_numeric_candidates(
    window: bytes,
    window_address: int,
    hit_offset: int,
    hit_size: int,
    radius: int,
) -> list[dict[str, object]]:
    if radius <= 0:
        return []
    start = max(0, hit_offset - radius)
    end = min(len(window), hit_offset + hit_size + radius)
    candidates: list[dict[str, object]] = []
    for offset in range(start, end):
        for size in (2, 4, 8):
            raw = window[offset : offset + size]
            if len(raw) != size:
                continue
            little = int.from_bytes(raw, "little", signed=False)
            big = int.from_bytes(raw, "big", signed=False)
            for endian, value in (("little", little), ("big", big)):
                if value == 0:
                    continue
                candidates.append(
                    {
                        "address": window_address + offset,
                        "relative_offset": offset - hit_offset,
                        "size": size,
                        "endian": endian,
                        "value": value,
                        "hex": raw.hex(" "),
                    }
                )
    return candidates


def build_hit_context(
    blob: bytes,
    base_address: int,
    offset: int,
    raw_size: int,
    context_bytes: int,
    *,
    decode_numbers: bool = False,
    number_radius: int = 16,
) -> dict[str, object] | None:
    if context_bytes <= 0:
        return None
    start = max(0, offset - context_bytes)
    end = min(len(blob), offset + raw_size + context_bytes)
    hit_start = offset - start
    hit_end = hit_start + raw_size
    window = blob[start:end]
    context: dict[str, object] = {
        "window_address": base_address + start,
        "window_size": len(window),
        "hit_offset": hit_start,
        "hit_size": raw_size,
        "bytes_before": blob[start:offset].hex(" "),
        "hit_bytes": blob[offset : offset + raw_size].hex(" "),
        "bytes_after": blob[offset + raw_size : end].hex(" "),
        "hex": window.hex(" "),
        "ascii": _printable_ascii(window),
    }
    if decode_numbers:
        context["numeric_candidates"] = _decode_numeric_candidates(
            window,
            base_address + start,
            hit_start,
            max(0, hit_end - hit_start),
            number_radius,
        )
    return context


def _module_for_address(modules: list[dict[str, object]], address: int) -> dict[str, object] | None:
    for module in modules:
        base = int(module.get("base_address", 0) or 0)
        end = int(module.get("end_address", 0) or 0)
        if base <= address < end:
            return module
    return None


def scan_process(
    handle: int,
    include_keywords: list[str],
    exclude_keywords: list[str] | None = None,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    max_region_size: int = 16 * 1024 * 1024,
    max_regions: int | None = None,
    max_hits_per_region: int | None = None,
    context_bytes: int = 0,
    decode_context_numbers: bool = False,
    context_number_radius: int = 16,
) -> list[RegionScan]:
    regions: list[RegionScan] = []
    compiled_includes = _compile_patterns(include_patterns)
    compiled_excludes = _compile_patterns(exclude_patterns)
    modules = list_process_modules(handle)
    for mbi in iter_memory_regions(handle):
        if not is_readable_region(mbi):
            continue
        if mbi.RegionSize > max_region_size:
            continue
        base = int(mbi.BaseAddress)
        size = int(mbi.RegionSize)
        blob = read_memory(handle, base, size)
        if not blob:
            continue
        hits: list[MemoryHit] = []
        region_module = _module_for_address(modules, base)
        for offset, encoding, text, raw_size in extract_strings(blob):
            if exclude_keywords and _contains_any(text, exclude_keywords):
                continue
            if compiled_excludes and _matches_any_pattern(text, compiled_excludes):
                continue
            include_match = False
            if include_keywords and _contains_any(text, include_keywords):
                include_match = True
            if compiled_includes and _matches_any_pattern(text, compiled_includes):
                include_match = True
            if not include_keywords and not compiled_includes:
                include_match = True
            if include_match:
                address = base + offset
                hit_module = region_module if region_module and int(region_module["base_address"]) <= address < int(region_module["end_address"]) else _module_for_address(modules, address)
                module_rva = address - int(hit_module["base_address"]) if hit_module else None
                hits.append(
                    MemoryHit(
                        address=address,
                        region_offset=offset,
                        module_rva=module_rva,
                        encoding=encoding,
                        text=text,
                        raw_size=raw_size,
                        context=build_hit_context(
                            blob,
                            base,
                            offset,
                            raw_size,
                            max(0, context_bytes),
                            decode_numbers=decode_context_numbers,
                            number_radius=max(0, context_number_radius),
                        ),
                    )
                )
            if max_hits_per_region is not None and len(hits) >= max_hits_per_region:
                break
        if hits:
            regions.append(
                RegionScan(
                    base_address=base,
                    region_size=size,
                    hits=tuple(hits),
                    allocation_base=int(ctypes_value(mbi.AllocationBase)),
                    allocation_protect=int(mbi.AllocationProtect),
                    allocation_protection=protection_name(int(mbi.AllocationProtect)),
                    state=int(mbi.State),
                    state_name=memory_state_name(int(mbi.State)),
                    protect=int(mbi.Protect),
                    protection=protection_name(int(mbi.Protect)),
                    type=int(mbi.Type),
                    type_name=memory_type_name(int(mbi.Type)),
                    module=region_module,
                )
            )
        if max_regions is not None and len(regions) >= max_regions:
            break
    return regions


def ctypes_value(value: object) -> int:
    return int(getattr(value, "value", value) or 0)


def summarize_regions(regions: list[RegionScan]) -> dict[str, int]:
    hit_count = sum(len(region.hits) for region in regions)
    unique_strings = {hit.text for region in regions for hit in region.hits}
    return {
        "region_count": len(regions),
        "hit_count": hit_count,
        "unique_hit_count": len(unique_strings),
    }


def summarize_top_hits(regions: list[RegionScan], limit: int = 10) -> list[dict[str, object]]:
    counter: Counter[tuple[str, str]] = Counter()
    first_address: dict[tuple[str, str], int] = {}
    for region in regions:
        for hit in region.hits:
            key = (hit.encoding, hit.text)
            counter[key] += 1
            first_address.setdefault(key, hit.address)

    top_hits: list[dict[str, object]] = []
    for (encoding, text), count in counter.most_common(limit):
        top_hits.append(
            {
                "encoding": encoding,
                "text": text,
                "count": count,
                "first_address": first_address[(encoding, text)],
            }
        )
    return top_hits


def scan_to_json(
    handle: int,
    include_keywords: list[str],
    exclude_keywords: list[str] | None = None,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    max_region_size: int = 16 * 1024 * 1024,
    max_regions: int | None = None,
    max_hits_per_region: int | None = None,
    context_bytes: int = 0,
    decode_context_numbers: bool = False,
    context_number_radius: int = 16,
) -> dict:
    regions = scan_process(
        handle,
        include_keywords=include_keywords,
        exclude_keywords=exclude_keywords,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
        max_region_size=max_region_size,
        max_regions=max_regions,
        max_hits_per_region=max_hits_per_region,
        context_bytes=context_bytes,
        decode_context_numbers=decode_context_numbers,
        context_number_radius=context_number_radius,
    )
    top_hits = summarize_top_hits(regions)
    return {
        "schema_version": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **summarize_regions(regions),
        "top_hits": top_hits,
        "regions": [
            asdict(region)
            for region in regions
        ],
    }
