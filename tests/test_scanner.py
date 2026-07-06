from pathlib import Path
import sys
import unittest
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cd_sniffer.cli import build_comparison, load_signature_pack, timestamped_output_path
from cd_sniffer.core import (
    render_search_results_csv,
    render_search_results_markdown,
    search_capture_directory,
    search_capture_file,
    search_flattened_hits,
    search_payload_values,
)
from cd_sniffer.scanner import RegionScan, MemoryHit, extract_strings, filter_hits, summarize_top_hits
from cd_sniffer.windows import vk_from_name


class ScannerTests(unittest.TestCase):
    def test_extract_strings_finds_ascii_and_utf16le(self):
        blob = b"xxxxMission_DeepForestBeacon_Surroundyyyy" + "Quest_Node_Her_DeepForestBeacon_Normal".encode("utf-16le")
        strings = extract_strings(blob)
        texts = [text for _, _, text in strings]
        self.assertTrue(any("Mission_DeepForestBeacon_Surround" in text for text in texts))
        self.assertTrue(any("Quest_Node_Her_DeepForestBeacon_Normal" in text for text in texts))
        ascii_hit = next(item for item in strings if item[1] == "ascii")
        utf16_hit = next(item for item in strings if item[1] == "utf16le")
        self.assertEqual(ascii_hit[0], 0)
        self.assertGreater(utf16_hit[0], ascii_hit[0])

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


if __name__ == "__main__":
    unittest.main()
