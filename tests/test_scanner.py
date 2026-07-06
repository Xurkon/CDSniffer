import argparse
import json
from pathlib import Path
import sys
import unittest
import tempfile
import struct
import zlib
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cd_sniffer.cli import build_comparison, load_signature_pack, timestamped_output_path
from cd_sniffer.correlator import (
    correlate_capture_to_files,
    extract_evidence_from_capture,
    render_correlation_csv,
    render_correlation_markdown,
)
from cd_sniffer.paz_archive import (
    build_archive_report,
    extract_entry,
    extract_entries,
    filter_archive_entries,
    hashlittle,
    parse_pamt,
    PazEntry,
)
from cd_sniffer.core import (
    build_capture_gate_filters,
    capture_gate_matches,
    filter_payload_unique_hits,
    render_search_results_csv,
    render_search_results_markdown,
    search_capture_directory,
    search_capture_file,
    search_flattened_hits,
    search_payload_values,
)
from cd_sniffer.scanner import RegionScan, MemoryHit, build_hit_context, extract_strings, filter_hits, summarize_top_hits
from cd_sniffer.windows import vk_from_name


class ScannerTests(unittest.TestCase):
    def test_extract_strings_finds_ascii_and_utf16le(self):
        blob = b"xxxxMission_DeepForestBeacon_Surroundyyyy" + "Quest_Node_Her_DeepForestBeacon_Normal".encode("utf-16le")
        strings = extract_strings(blob)
        texts = [text for _, _, text, _ in strings]
        self.assertTrue(any("Mission_DeepForestBeacon_Surround" in text for text in texts))
        self.assertTrue(any("Quest_Node_Her_DeepForestBeacon_Normal" in text for text in texts))
        ascii_hit = next(item for item in strings if item[1] == "ascii")
        utf16_hit = next(item for item in strings if item[1] == "utf16le")
        self.assertEqual(ascii_hit[0], 0)
        self.assertGreater(utf16_hit[0], ascii_hit[0])
        self.assertEqual(ascii_hit[3], len(ascii_hit[2].encode("ascii")))
        self.assertEqual(utf16_hit[3], len(utf16_hit[2].encode("utf-16le")))

    def test_filter_hits_matches_keywords(self):
        strings = [
            ("ascii", "Mission_Node_Her_DeepForestBeacon_Surround"),
            ("ascii", "Quest_Node_Del_DelesyiaCastle_Daily"),
            ("utf16le", "Quest_Node_Her_HellwoodSlaveCamp_Block"),
        ]
        hits = filter_hits(strings, ["deepforestbeacon", "hellwoodslavecamp"])
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0].text, "Mission_Node_Her_DeepForestBeacon_Surround")
        self.assertEqual(hits[1].text, "Quest_Node_Her_HellwoodSlaveCamp_Block")

    def test_filter_hits_supports_regex_filters(self):
        strings = [
            ("ascii", "Mission_Her_RoccaHillBanditCamp"),
            ("ascii", "Quest_Node_Her_DeepForestBeacon_Surround"),
            ("ascii", "Quest_Node_Her_DeepForestBeacon_Block"),
        ]
        hits = filter_hits(
            strings,
            include_keywords=[],
            include_patterns=[r"DeepForestBeacon_(Surround|Block)"],
            exclude_patterns=[r"Block$"],
        )
        self.assertEqual([hit.text for hit in hits], ["Quest_Node_Her_DeepForestBeacon_Surround"])

    def test_vk_from_name_supports_common_keys(self):
        self.assertEqual(vk_from_name("f8"), 0x77)
        self.assertEqual(vk_from_name("space"), 0x20)
        self.assertEqual(vk_from_name("a"), 0x41)

    def test_summarize_top_hits_counts_duplicates(self):
        regions = [
            RegionScan(
                base_address=0x1000,
                region_size=0x2000,
                hits=(
                    MemoryHit(address=0x1000, encoding="ascii", text="Mission_A"),
                    MemoryHit(address=0x1000, encoding="ascii", text="Mission_A"),
                    MemoryHit(address=0x1000, encoding="utf16le", text="Mission_B"),
                ),
            )
        ]
        top_hits = summarize_top_hits(regions, limit=2)
        self.assertEqual(top_hits[0]["text"], "Mission_A")
        self.assertEqual(top_hits[0]["count"], 2)
        self.assertEqual(top_hits[1]["text"], "Mission_B")
        self.assertEqual(top_hits[1]["first_address"], 0x1000)

    def test_build_hit_context_includes_hex_ascii_and_numbers(self):
        blob = b"\x00\x00\x39\x30\x00\x00Mission_A\xFF"
        offset = blob.index(b"Mission_A")
        context = build_hit_context(
            blob,
            0x1000,
            offset,
            len(b"Mission_A"),
            6,
            decode_numbers=True,
            number_radius=4,
        )
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(context["window_address"], 0x1000 + max(0, offset - 6))
        self.assertEqual(context["hit_bytes"], b"Mission_A".hex(" "))
        self.assertIn("Mission_A", context["ascii"])
        self.assertTrue(any(item["value"] == 12345 for item in context["numeric_candidates"]))

    def test_timestamped_output_path_adds_stamp(self):
        stamped = timestamped_output_path("logs/cdsniffer.jsonl", "cdsniffer")
        self.assertTrue(stamped.name.startswith("cdsniffer-"))
        self.assertTrue(stamped.name.endswith(".jsonl"))

    def test_load_signature_pack_parses_text_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pack.txt"
            path.write_text(
                "\n".join(
                    [
                        "# comment",
                        "camp",
                        "-quest",
                        r"r:DeepForestBeacon",
                        r"!r:Story",
                    ]
                ),
                encoding="utf-8",
            )
            data = load_signature_pack(str(path))
        self.assertEqual(data["include_keywords"], ["camp"])
        self.assertEqual(data["exclude_keywords"], ["quest"])
        self.assertEqual(data["include_patterns"], ["DeepForestBeacon"])
        self.assertEqual(data["exclude_patterns"], ["Story"])

    def test_load_signature_pack_parses_json_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pack.json"
            path.write_text(
                "{\"include_keywords\": [\"camp\"], \"exclude_keywords\": [\"quest\"], \"include_patterns\": [\"Beacon\"], \"exclude_patterns\": [\"Story\"]}",
                encoding="utf-8",
            )
            data = load_signature_pack(str(path))
        self.assertEqual(data["include_keywords"], ["camp"])
        self.assertEqual(data["exclude_keywords"], ["quest"])
        self.assertEqual(data["include_patterns"], ["Beacon"])
        self.assertEqual(data["exclude_patterns"], ["Story"])

    def test_build_comparison_tracks_added_and_removed(self):
        current = {
            "timestamp": "2026-01-01T00:00:00Z",
            "regions": [{"hits": [{"text": "A"}, {"text": "B"}]}],
        }
        previous = {
            "timestamp": "2025-12-31T23:59:00Z",
            "regions": [{"hits": [{"text": "B"}, {"text": "C"}]}],
        }
        comparison = build_comparison(current, previous, limit=10)
        self.assertEqual(comparison["added"], ["A"])
        self.assertEqual(comparison["removed"], ["C"])

    def test_capture_gate_filters_use_camp_sentinels_plus_custom_terms(self):
        args = argparse.Namespace(
            capture_gate="camp-mission",
            gate_keywords=["Camp Mission Detail"],
            gate_patterns=[r"Required\s+Members"],
        )
        keywords, patterns = build_capture_gate_filters(args)
        self.assertIn("Required Members", keywords)
        self.assertIn("Comrades Selected", keywords)
        self.assertIn("Camp Mission Detail", keywords)
        self.assertEqual(patterns, [r"Required\s+Members"])

    def test_capture_gate_matches_any_sentinel_from_scan_payload(self):
        args = argparse.Namespace(
            capture_gate="custom",
            capture_gate_match="any",
            gate_keywords=["Required Members"],
            gate_patterns=[],
            max_region_size=1024,
            gate_max_regions=2,
            gate_max_hits_per_region=1,
        )
        gate_payload = {
            "hit_count": 1,
            "region_count": 1,
            "regions": [{"hits": [{"text": "Required Members"}]}],
        }
        with patch("cd_sniffer.core.scan_to_json", return_value=gate_payload):
            matched, detail = capture_gate_matches(1234, args)
        self.assertTrue(matched)
        self.assertEqual(detail["mode"], "custom")
        self.assertEqual(detail["matched_texts"], ["Required Members"])

    def test_capture_gate_custom_mode_requires_filters(self):
        args = argparse.Namespace(capture_gate="custom", capture_gate_match="any", gate_keywords=[], gate_patterns=[])
        matched, detail = capture_gate_matches(1234, args)
        self.assertFalse(matched)
        self.assertIn("no keywords", detail["reason"])

    def test_filter_payload_unique_hits_keeps_only_new_session_text(self):
        payload = {
            "regions": [
                {
                    "base_address": 0x1000,
                    "region_size": 0x2000,
                    "hits": [
                        {"address": 0x1010, "encoding": "ascii", "text": "Mission_A"},
                        {"address": 0x1020, "encoding": "utf16le", "text": "Mission_A"},
                        {"address": 0x1030, "encoding": "ascii", "text": "Mission_B"},
                    ],
                }
            ],
            "hit_count": 3,
            "unique_hit_count": 2,
            "top_hits": [],
        }
        seen = {"Mission_B"}
        filtered = filter_payload_unique_hits(payload, seen)
        self.assertEqual(filtered["hit_count"], 1)
        self.assertEqual(filtered["unique_hit_count"], 1)
        self.assertEqual(filtered["regions"][0]["hits"][0]["text"], "Mission_A")
        self.assertEqual(filtered["top_hits"][0]["text"], "Mission_A")
        self.assertEqual(filtered["unique_filter"]["original_hit_count"], 3)
        self.assertEqual(filtered["unique_filter"]["skipped_hit_count"], 2)
        self.assertEqual(seen, {"Mission_A", "Mission_B"})

    def test_search_helpers_match_payload_fields(self):
        payload = {
            "timestamp": "2026-01-01T00:00:00Z",
            "regions": [
                {
                    "base_address": 0x1000,
                    "region_size": 0x2000,
                    "hits": [
                        {"address": 0x1000, "encoding": "ascii", "text": "Mission_DeepForestBeacon_Surround"},
                        {"address": 0x1000, "encoding": "utf16le", "text": "Quest_Node_Her_DeepForestBeacon_Normal"},
                    ],
                }
            ],
            "top_hits": [
                {"count": 2, "encoding": "ascii", "text": "Mission_DeepForestBeacon_Surround", "first_address": 0x1000}
            ],
        }
        flattened = search_flattened_hits(payload, "DeepForestBeacon")
        fields = search_payload_values(payload, "DeepForestBeacon")
        self.assertEqual(len(flattened), 2)
        self.assertTrue(any("regions[0].hits[0].text" == item["path"] for item in fields))

    def test_search_capture_file_reads_jsonl_snapshots(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "capture.jsonl"
            path.write_text(
                "\n".join(
                    [
                        "{\"timestamp\": \"2026-01-01T00:00:00Z\", \"regions\": [{\"hits\": [{\"address\": 4096, \"encoding\": \"ascii\", \"text\": \"Mission_DeepForestBeacon_Surround\"}]}]}",
                        "{\"timestamp\": \"2026-01-01T00:01:00Z\", \"regions\": [{\"hits\": [{\"address\": 8192, \"encoding\": \"ascii\", \"text\": \"Quest_Node_Her_RedCliffs\"}]}]}",
                    ]
                ),
                encoding="utf-8",
            )
            result = search_capture_file(path, "DeepForestBeacon")
        self.assertEqual(result["match_count"], 1)
        self.assertEqual(result["matches"][0]["path"], "regions[0].hits[0].text")

    def test_search_capture_directory_recurses_and_aggregates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "nested").mkdir()
            (root / "capture_a.jsonl").write_text(
                "{\"timestamp\": \"2026-01-01T00:00:00Z\", \"regions\": [{\"hits\": [{\"address\": 4096, \"encoding\": \"ascii\", \"text\": \"Mission_One\"}]}]}",
                encoding="utf-8",
            )
            (root / "nested" / "capture_b.jsonl").write_text(
                "{\"timestamp\": \"2026-01-01T00:01:00Z\", \"regions\": [{\"hits\": [{\"address\": 8192, \"encoding\": \"ascii\", \"text\": \"Mission_Two\"}]}]}",
                encoding="utf-8",
            )
            result = search_capture_directory(root, "Mission_", regex=False, case_sensitive=False)
        self.assertEqual(result["file_count"], 2)
        self.assertEqual(result["match_count"], 2)
        self.assertEqual(len(result["files"]), 2)

    def test_search_renderers_emit_csv_and_markdown(self):
        result = {
            "path": "logs",
            "query": "Mission",
            "match_count": 1,
            "files": [
                {
                    "path": "logs/capture.jsonl",
                    "snapshot_count": 1,
                    "matches": [{"path": "regions[0].hits[0].text", "value": "Mission_One"}],
                }
            ],
        }
        csv_text = render_search_results_csv(result)
        md_text = render_search_results_markdown(result)
        self.assertIn("file,snapshot_index,snapshot_count,match_path,value", csv_text)
        self.assertIn("capture.jsonl", csv_text)
        self.assertIn("# CDSniffer Search Results", md_text)
        self.assertIn("Mission_One", md_text)

    def test_correlator_finds_string_hit_bytes_and_numeric_candidates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            capture = root / "capture.jsonl"
            unpacked = root / "unpacked"
            unpacked.mkdir()
            target = unpacked / "mission_table.bin"
            target.write_bytes(b"xxxxMission_A\x39\x30yyyy")
            capture.write_text(
                json_line(
                    {
                        "schema_version": 1,
                        "timestamp": "2026-01-01T00:00:00Z",
                        "regions": [
                            {
                                "base_address": 0x1000,
                                "region_size": 0x2000,
                                "hits": [
                                    {
                                        "address": 0x1010,
                                        "module_rva": 0x10,
                                        "encoding": "ascii",
                                        "text": "Mission_A",
                                        "context": {
                                            "hit_bytes": b"Mission_A".hex(" "),
                                            "numeric_candidates": [
                                                {
                                                    "address": 0x1019,
                                                    "relative_offset": 9,
                                                    "size": 2,
                                                    "endian": "little",
                                                    "value": 12345,
                                                    "hex": b"\x39\x30".hex(" "),
                                                }
                                            ],
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            evidence = extract_evidence_from_capture(capture)
            result = correlate_capture_to_files(capture, unpacked, patterns=["*.bin"], max_total_matches=10)
            csv_text = render_correlation_csv(result)
            md_text = render_correlation_markdown(result)

        self.assertGreaterEqual(len(evidence), 3)
        self.assertGreaterEqual(result["raw_match_count"], 3)
        self.assertEqual(result["match_count"], 2)
        offsets = {match["offset"] for match in result["matches"]}
        self.assertIn(4, offsets)
        self.assertIn(13, offsets)
        grouped = next(match for match in result["matches"] if match["offset"] == 4)
        self.assertGreaterEqual(grouped["evidence_count"], 2)
        self.assertIn("text:ascii", grouped["match_types"])
        self.assertIn("hit-bytes", grouped["match_types"])
        self.assertIn("mission_table.bin", csv_text)
        self.assertIn("# CDSniffer Correlation Results", md_text)

    def test_correlator_marks_target_only_against_baseline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            unpacked = root / "unpacked"
            unpacked.mkdir()
            target = unpacked / "mission_table.bin"
            target.write_bytes(b"Mission_A----Mission_B")
            baseline_capture = root / "baseline.jsonl"
            target_capture = root / "target.jsonl"
            baseline_capture.write_text(json_line(capture_payload(["Mission_A"])), encoding="utf-8")
            target_capture.write_text(json_line(capture_payload(["Mission_A", "Mission_B"])), encoding="utf-8")

            result = correlate_capture_to_files(
                target_capture,
                unpacked,
                baseline_capture_path=baseline_capture,
                patterns=["*.bin"],
                max_total_matches=10,
            )

        mission_a = next(match for match in result["matches"] if "Mission_A" in match["hit_texts"])
        mission_b = next(match for match in result["matches"] if "Mission_B" in match["hit_texts"])
        self.assertEqual(result["target_only_count"], 1)
        self.assertEqual(result["shared_count"], 1)
        self.assertEqual(mission_a["diff_status"], "shared-with-baseline")
        self.assertEqual(mission_b["diff_status"], "target-only")
        self.assertIn("target-only", mission_b["confidence_reasons"])

    def test_correlator_adds_json_record_format_hints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            unpacked = root / "unpacked"
            unpacked.mkdir()
            target = unpacked / "missioninfo.json"
            target.write_text(
                json.dumps(
                    [
                        {
                            "Key": 1001,
                            "Internal Name": "Mission_A",
                            "Display Name": "Simple Farming",
                            "Required Members": "2~4",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            capture = root / "capture.jsonl"
            capture.write_text(json_line(capture_payload(["Mission_A"])), encoding="utf-8")

            result = correlate_capture_to_files(capture, unpacked, patterns=["*.json"], max_total_matches=10)

        match = result["matches"][0]
        hint_kinds = {hint["kind"] for hint in match["format_hints"]}
        self.assertEqual(match["file_format"], "json")
        self.assertIn("json-record", hint_kinds)
        self.assertIn("json-structure", match["confidence_reasons"])
        self.assertIn("Key=1001", match["format_hint_summary"])
        self.assertGreater(result["format_hint_count"], 0)

    def test_correlator_adds_paseq_binary_format_hints(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            unpacked = root / "unpacked"
            unpacked.mkdir()
            target = unpacked / "mission_flow.paseq"
            target.write_bytes(b"\x39\x30\x00\x00xxxxMission_Ayyyy")
            capture = root / "capture.jsonl"
            capture.write_text(json_line(capture_payload(["Mission_A"])), encoding="utf-8")

            result = correlate_capture_to_files(capture, unpacked, patterns=["*.paseq"], max_total_matches=10)

        match = result["matches"][0]
        hint_kinds = {hint["kind"] for hint in match["format_hints"]}
        self.assertEqual(match["file_format"], "paseq")
        self.assertIn("paseq-binary", hint_kinds)
        self.assertIn("little-endian-context", match["confidence_reasons"])

    def test_paz_parser_reads_synthetic_pamt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            pamt = write_synthetic_pamt(root, "data/test.bin", comp_size=11, orig_size=11, flags=0)
            (root / "0.paz").write_bytes(b"hello world")

            entries = parse_pamt(pamt)
            report = build_archive_report([pamt])

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].path, "testpkg/data/test.bin")
        self.assertEqual(entries[0].comp_size, 11)
        self.assertEqual(report["entry_count"], 1)
        self.assertEqual(report["entries"][0]["compression_name"], "none")

    def test_paz_extracts_uncompressed_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            pamt = write_synthetic_pamt(root, "data/test.bin", comp_size=11, orig_size=11, flags=0)
            (root / "0.paz").write_bytes(b"hello world")
            output = root / "out"

            entry = parse_pamt(pamt)[0]
            result = extract_entry(entry, output, decrypt_xml=False)

            self.assertEqual(result["size"], 11)
            self.assertFalse(result["decrypted"])
            self.assertFalse(result["decompressed"])
            self.assertEqual((output / "testpkg" / "data" / "test.bin").read_bytes(), b"hello world")

    def test_paz_extracts_zlib_entry_and_filters(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            raw = b"Mission_A" * 20
            compressed = zlib.compress(raw)
            pamt = write_synthetic_pamt(root, "data/mission.bin", comp_size=len(compressed), orig_size=len(raw), flags=0x00040000)
            (root / "0.paz").write_bytes(compressed)
            output = root / "out"

            entries = parse_pamt(pamt)
            filtered = filter_archive_entries(entries, patterns=["*mission*"])
            result = extract_entries(filtered, output, decrypt_xml=False)

            self.assertEqual(len(filtered), 1)
            self.assertEqual(result["extracted_count"], 1)
            self.assertEqual(result["decompressed_count"], 1)
            self.assertEqual((output / "testpkg" / "data" / "mission.bin").read_bytes(), raw)

    def test_paz_hashlittle_uses_documented_vector(self):
        self.assertEqual(hashlittle(b"rendererconfigurationmaterial.xml", 0x000C5EDE), 0xAF3DCEF3)


def json_line(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False) + "\n"


def capture_payload(texts: list[str]) -> dict:
    return {
        "schema_version": 1,
        "timestamp": "2026-01-01T00:00:00Z",
        "regions": [
            {
                "base_address": 0x1000,
                "region_size": 0x2000,
                "hits": [
                    {
                        "address": 0x1000 + index * 0x10,
                        "module_rva": index * 0x10,
                        "encoding": "ascii",
                        "text": text,
                        "context": {"hit_bytes": text.encode("ascii").hex(" ")},
                    }
                    for index, text in enumerate(texts, start=1)
                ],
            }
        ],
    }


def write_synthetic_pamt(root: Path, node_path: str, *, comp_size: int, orig_size: int, flags: int) -> Path:
    node_parts = node_path.split("/")
    buffer = bytearray()
    buffer += struct.pack("<I", 0x09F510ED)
    buffer += struct.pack("<I", 1)
    buffer += struct.pack("<II", 0, 0)
    buffer += struct.pack("<II", 0, 4096)

    folder = bytearray()
    folder_name = b"testpkg"
    folder += struct.pack("<I", 0xFFFFFFFF)
    folder += struct.pack("B", len(folder_name)) + folder_name
    buffer += struct.pack("<I", len(folder)) + folder

    nodes = bytearray()
    parent = 0xFFFFFFFF
    last_ref = 0
    for index, part in enumerate(node_parts):
        if index < len(node_parts) - 1:
            name = f"{part}/".encode("utf-8")
        else:
            name = part.encode("utf-8")
        node_ref = len(nodes)
        nodes += struct.pack("<I", parent)
        nodes += struct.pack("B", len(name)) + name
        parent = node_ref
        last_ref = node_ref
    buffer += struct.pack("<I", len(nodes)) + nodes

    buffer += struct.pack("<II", 1, 0)
    buffer += b"\x00" * 16
    buffer += struct.pack("<IIIII", last_ref, 0, comp_size, orig_size, flags)

    pamt = root / "0.pamt"
    pamt.write_bytes(bytes(buffer))
    return pamt


if __name__ == "__main__":
    unittest.main()
