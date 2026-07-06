from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

from .windows import is_readable_region, iter_memory_regions, read_memory

ASCII_RE = re.compile(rb"[ -~]{4,}")
UTF16_RE = re.compile(rb"(?:[ -~]\x00){4,}")


@dataclass(frozen=True)
class MemoryHit:
    address: int
    encoding: str
    text: str


@dataclass(frozen=True)
class RegionScan:
    base_address: int
    region_size: int
    hits: tuple[MemoryHit, ...]


def extract_strings(blob: bytes) -> list[tuple[int, str, str]]:
    hits: list[tuple[int, str, str]] = []
    for match in ASCII_RE.finditer(blob):
        hits.append((match.start(), "ascii", match.group(0).decode("ascii", "ignore")))
    for match in UTF16_RE.finditer(blob):
        raw = match.group(0)
        hits.append((match.start(), "utf16le", raw.decode("utf-16le", "ignore")))
    return hits


def _contains_any(text: str, keywords: list[str]) -> bool:
    lowered = text.lower()
    return any(keyword.lower() in lowered for keyword in keywords)


def _compile_patterns(patterns: list[str] | None) -> list[re.Pattern[str]]:
    return [re.compile(pattern, re.IGNORECASE) for pattern in (patterns or [])]


def _matches_any_pattern(text: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def filter_hits(
    strings: list[tuple[str, str]] | list[tuple[int, str, str]],
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
        if len(item) == 3:
            offset, encoding, text = item
        else:
            offset = 0
            encoding, text = item
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
        filtered.append(MemoryHit(address=int(offset), encoding=encoding, text=normalized))
    return filtered


def scan_process(
    handle: int,
    include_keywords: list[str],
    exclude_keywords: list[str] | None = None,
    include_patterns: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
    max_region_size: int = 16 * 1024 * 1024,
    max_regions: int | None = None,
    max_hits_per_region: int | None = None,
) -> list[RegionScan]:
    regions: list[RegionScan] = []
    compiled_includes = _compile_patterns(include_patterns)
    compiled_excludes = _compile_patterns(exclude_patterns)
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
        for offset, encoding, text in extract_strings(blob):
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
                hits.append(MemoryHit(address=base + offset, encoding=encoding, text=text))
            if max_hits_per_region is not None and len(hits) >= max_hits_per_region:
                break
        if hits:
            regions.append(RegionScan(base_address=base, region_size=size, hits=tuple(hits)))
        if max_regions is not None and len(regions) >= max_regions:
            break
    return regions


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
    )
    top_hits = summarize_top_hits(regions)
    return {
        "schema_version": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **summarize_regions(regions),
        "top_hits": top_hits,
        "regions": [
            {
                "base_address": region.base_address,
                "region_size": region.region_size,
                "hits": [asdict(hit) for hit in region.hits],
            }
            for region in regions
        ],
    }
