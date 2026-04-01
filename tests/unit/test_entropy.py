"""Tests for thresher.scanners.entropy."""

from __future__ import annotations

from thresher.scanners.entropy import parse_entropy_output


class TestParseEntropyOutput:
    def test_empty_output(self):
        raw = {"scanner": "entropy", "findings": [], "total": 0}
        findings = parse_entropy_output(raw)
        assert findings == []

    def test_high_entropy_string(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {
                    "type": "high_entropy_string",
                    "file": "/opt/deps/npm/pkg/index.js",
                    "severity": "low",
                    "description": "High-entropy string (80 chars, entropy=5.20 bits/char)",
                    "detail": {"length": 80, "entropy": 5.2, "preview": "abc123..."},
                }
            ],
            "total": 1,
        }
        findings = parse_entropy_output(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.source_tool == "entropy"
        assert f.category == "obfuscation"
        assert f.severity == "low"
        assert "high_entropy_string" in f.title
        assert f.file_path == "/opt/deps/npm/pkg/index.js"

    def test_base64_blob(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {
                    "type": "base64_blob",
                    "file": "/opt/deps/pypi/pkg/payload.py",
                    "severity": "medium",
                    "description": "Base64 blob detected (500 chars, entropy=5.90)",
                    "detail": {"length": 500, "entropy": 5.9},
                }
            ],
            "total": 1,
        }
        findings = parse_entropy_output(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "medium"
        assert "base64_blob" in f.title

    def test_hex_payload(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {
                    "type": "hex_payload",
                    "file": "/opt/deps/npm/pkg/lib.js",
                    "severity": "medium",
                    "description": "Hex-encoded payload (128 chars)",
                    "detail": {"length": 128},
                }
            ],
            "total": 1,
        }
        findings = parse_entropy_output(raw)
        assert len(findings) == 1
        assert findings[0].category == "obfuscation"

    def test_minified_code(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {
                    "type": "minified_code",
                    "file": "/opt/deps/npm/pkg/bundle.js",
                    "severity": "medium",
                    "description": "Minified/single-line file (50000 bytes in 1 lines)",
                    "detail": {"size_bytes": 50000, "line_count": 1},
                }
            ],
            "total": 1,
        }
        findings = parse_entropy_output(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "medium"
        assert "minified_code" in f.title

    def test_multiple_findings(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {"type": "base64_blob", "file": "/a", "severity": "medium", "description": "blob"},
                {"type": "hex_payload", "file": "/b", "severity": "medium", "description": "hex"},
                {"type": "high_entropy_string", "file": "/c", "severity": "low", "description": "entropy"},
            ],
            "total": 3,
        }
        findings = parse_entropy_output(raw)
        assert len(findings) == 3
        # All should have unique IDs
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids))

    def test_missing_findings_key(self):
        raw = {"scanner": "entropy"}
        findings = parse_entropy_output(raw)
        assert findings == []

    def test_all_findings_have_obfuscation_category(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {"type": "base64_blob", "severity": "medium", "description": "a"},
                {"type": "minified_code", "severity": "medium", "description": "b"},
            ],
            "total": 2,
        }
        findings = parse_entropy_output(raw)
        assert all(f.category == "obfuscation" for f in findings)

    def test_hex_escape_string(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {
                    "type": "hex_escape_string",
                    "file": "/opt/deps/npm/pkg/evil.js",
                    "severity": "high",
                    "description": "Hex-escaped string (30 chars) decodes to: 'eval('",
                    "detail": {"length": 30, "decoded": "eval("},
                }
            ],
            "total": 1,
        }
        findings = parse_entropy_output(raw)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "hex_escape_string" in findings[0].title

    def test_unicode_escape_string(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {
                    "type": "unicode_escape_string",
                    "file": "/opt/deps/npm/pkg/hidden.js",
                    "severity": "high",
                    "description": "Unicode-escaped string decodes to: 'eval'",
                    "detail": {"decoded": "eval"},
                }
            ],
            "total": 1,
        }
        findings = parse_entropy_output(raw)
        assert findings[0].severity == "high"

    def test_from_char_code(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {
                    "type": "from_char_code",
                    "file": "/opt/deps/npm/pkg/obf.js",
                    "severity": "high",
                    "description": "String.fromCharCode with 10 codes decodes to: 'eval(atob('",
                    "detail": {"decoded": "eval(atob("},
                }
            ],
            "total": 1,
        }
        findings = parse_entropy_output(raw)
        assert findings[0].severity == "high"
        assert "from_char_code" in findings[0].title

    def test_js_obfuscated_vars(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {
                    "type": "js_obfuscated_vars",
                    "file": "/opt/deps/npm/pkg/packed.js",
                    "severity": "high",
                    "description": "JS obfuscator variable names detected (15 unique _0x* identifiers)",
                    "detail": {"count": 15, "samples": ["_0x4a2b", "_0x1f3c"]},
                }
            ],
            "total": 1,
        }
        findings = parse_entropy_output(raw)
        assert findings[0].severity == "high"

    def test_eval_decoded_string_is_critical(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {
                    "type": "eval_decoded_string",
                    "file": "/opt/deps/npm/pkg/payload.js",
                    "severity": "critical",
                    "description": "eval/exec of decoded string: eval(atob(",
                    "detail": {"pattern": "eval(atob("},
                }
            ],
            "total": 1,
        }
        findings = parse_entropy_output(raw)
        assert findings[0].severity == "critical"

    def test_chr_concat(self):
        raw = {
            "scanner": "entropy",
            "findings": [
                {
                    "type": "chr_concat",
                    "file": "/opt/deps/pypi/pkg/sneaky.py",
                    "severity": "high",
                    "description": "chr() concatenation (8 calls) decodes to: 'import os'",
                    "detail": {"decoded": "import os"},
                }
            ],
            "total": 1,
        }
        findings = parse_entropy_output(raw)
        assert findings[0].severity == "high"
        assert "chr_concat" in findings[0].title
