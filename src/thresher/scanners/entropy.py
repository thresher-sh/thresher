"""Entropy scanner -- detects obfuscation patterns in dependency source."""

from __future__ import annotations

import logging
import time
from typing import Any

from thresher.scanners.models import Finding, ScanResults
from thresher.vm.ssh import ssh_exec, ssh_write_file

logger = logging.getLogger(__name__)

# Self-contained Python script that runs INSIDE the VM.
_ENTROPY_SCRIPT = r'''#!/usr/bin/env python3
"""Scan dependency source for high-entropy strings and obfuscation patterns.

Writes JSON results to /opt/scan-results/entropy.json.
"""

import json
import math
import os
import re
import sys

DEPS_DIR = "/opt/deps"
OUTPUT_PATH = "/opt/scan-results/entropy.json"

# Thresholds
ENTROPY_THRESHOLD = 4.5       # bits per character
ENTROPY_MIN_LENGTH = 40       # minimum string length for entropy check
BASE64_MIN_LENGTH = 100       # minimum base64 blob length
HEX_MIN_LENGTH = 64           # minimum hex string length
MINIFIED_LINE_THRESHOLD = 10240  # 10 KB single-line threshold

# File extensions to analyze
TEXT_EXTENSIONS = {
    ".js", ".py", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".rb", ".pl", ".sh", ".bash", ".ps1", ".bat", ".cmd",
    ".json", ".yaml", ".yml", ".toml", ".xml", ".html",
    ".c", ".cpp", ".h", ".go", ".rs", ".java",
}

# Patterns — encoded data
BASE64_RE = re.compile(r'[A-Za-z0-9+/]{100,}={0,2}')
HEX_RE = re.compile(r'(?:0x)?[0-9a-fA-F]{64,}')

# Patterns — string escape obfuscation
# \x68\x65\x6c\x6c\x6f style (5+ consecutive hex escapes)
HEX_ESCAPE_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}){5,}')
# \u0065\u0076\u0061\u006c style (4+ consecutive unicode escapes)
UNICODE_ESCAPE_RE = re.compile(r'(?:\\u[0-9a-fA-F]{4}){4,}')
# String.fromCharCode(104,101,108,...) with 5+ codes
FROM_CHAR_CODE_RE = re.compile(
    r'String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){4,}\d+\s*\)'
)
# chr() concatenation: chr(104)+chr(101)+... with 5+ calls
CHR_CONCAT_RE = re.compile(r'(?:chr\(\d+\)\s*\+\s*){4,}chr\(\d+\)')

# Patterns — JS obfuscator variable names (_0x4a2b, _0xabcd)
JS_OBFUSCATED_VAR_RE = re.compile(r'\b_0x[0-9a-fA-F]{2,8}\b')

# Patterns — eval of decoded/computed strings
EVAL_ATOB_RE = re.compile(r'eval\s*\(\s*atob\s*\(')
EVAL_BUFFER_RE = re.compile(r'eval\s*\(\s*Buffer\.from\s*\(')
EVAL_DECODE_RE = re.compile(
    r'(?:eval|exec|Function)\s*\(\s*'
    r'(?:atob|Buffer\.from|decodeURIComponent|unescape|'
    r'base64\.b64decode|codecs\.decode)\s*\('
)

# Patterns — array-based string reconstruction
# var _0x1234 = ["eval","fromCharCode",...]; (JS obfuscator arrays)
OBFUSCATOR_ARRAY_RE = re.compile(
    r'(?:var|let|const)\s+_0x[0-9a-fA-F]+\s*=\s*\[(?:\s*["\'][^"\']*["\']\s*,\s*){5,}'
)

findings = []


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def check_file(file_path: str) -> None:
    """Analyze a single file for obfuscation patterns."""
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
    except IOError:
        return

    lines = content.split("\n")
    ext = os.path.splitext(file_path)[1].lower()

    # ── Minified code ───────────────────────────────────────────
    if ext in (".js", ".py", ".ts") and len(lines) <= 3:
        total_size = sum(len(line) for line in lines)
        if total_size > MINIFIED_LINE_THRESHOLD:
            findings.append({
                "type": "minified_code",
                "file": file_path,
                "severity": "medium",
                "description": (
                    f"Minified/single-line file ({total_size} bytes in "
                    f"{len(lines)} lines)"
                ),
                "detail": {"size_bytes": total_size, "line_count": len(lines)},
            })

    # ── Base64 blobs ────────────────────────────────────────────
    for match in BASE64_RE.finditer(content):
        blob = match.group()
        if len(blob) >= BASE64_MIN_LENGTH:
            ent = shannon_entropy(blob)
            findings.append({
                "type": "base64_blob",
                "file": file_path,
                "severity": "medium",
                "description": (
                    f"Base64 blob detected ({len(blob)} chars, "
                    f"entropy={ent:.2f})"
                ),
                "detail": {"length": len(blob), "entropy": round(ent, 2)},
            })

    # ── Hex-encoded payloads ────────────────────────────────────
    for match in HEX_RE.finditer(content):
        hexstr = match.group()
        if len(hexstr) >= HEX_MIN_LENGTH:
            findings.append({
                "type": "hex_payload",
                "file": file_path,
                "severity": "medium",
                "description": f"Hex-encoded payload ({len(hexstr)} chars)",
                "detail": {"length": len(hexstr)},
            })

    # ── String escape obfuscation ───────────────────────────────
    # \x68\x65\x6c\x6c\x6f — hex escape sequences hiding strings
    for match in HEX_ESCAPE_RE.finditer(content):
        escaped = match.group()
        # Decode to show what it actually says
        try:
            decoded = escaped.encode().decode("unicode_escape")
        except Exception:
            decoded = ""
        findings.append({
            "type": "hex_escape_string",
            "file": file_path,
            "severity": "high",
            "description": (
                f"Hex-escaped string ({len(escaped)} chars)"
                + (f" decodes to: {decoded[:60]!r}" if decoded else "")
            ),
            "detail": {
                "length": len(escaped),
                "preview": escaped[:80],
                "decoded": decoded[:100] if decoded else None,
            },
        })

    # \u0065\u0076\u0061\u006c — unicode escapes hiding identifiers
    for match in UNICODE_ESCAPE_RE.finditer(content):
        escaped = match.group()
        try:
            decoded = escaped.encode().decode("unicode_escape")
        except Exception:
            decoded = ""
        findings.append({
            "type": "unicode_escape_string",
            "file": file_path,
            "severity": "high",
            "description": (
                f"Unicode-escaped string ({len(escaped)} chars)"
                + (f" decodes to: {decoded[:60]!r}" if decoded else "")
            ),
            "detail": {
                "length": len(escaped),
                "preview": escaped[:80],
                "decoded": decoded[:100] if decoded else None,
            },
        })

    # String.fromCharCode(104,101,...) — character code reconstruction
    for match in FROM_CHAR_CODE_RE.finditer(content):
        call = match.group()
        try:
            codes = re.findall(r'\d+', call)
            decoded = "".join(chr(int(c)) for c in codes)
        except Exception:
            decoded = ""
        findings.append({
            "type": "from_char_code",
            "file": file_path,
            "severity": "high",
            "description": (
                f"String.fromCharCode with {len(re.findall(chr(44), call))+1} codes"
                + (f" decodes to: {decoded[:60]!r}" if decoded else "")
            ),
            "detail": {"decoded": decoded[:100] if decoded else None},
        })

    # chr(104)+chr(101)+... — Python char concatenation
    for match in CHR_CONCAT_RE.finditer(content):
        call = match.group()
        try:
            codes = re.findall(r'chr\((\d+)\)', call)
            decoded = "".join(chr(int(c)) for c in codes)
        except Exception:
            decoded = ""
        findings.append({
            "type": "chr_concat",
            "file": file_path,
            "severity": "high",
            "description": (
                f"chr() concatenation ({len(re.findall(r'chr', call))} calls)"
                + (f" decodes to: {decoded[:60]!r}" if decoded else "")
            ),
            "detail": {"decoded": decoded[:100] if decoded else None},
        })

    # ── JS obfuscator patterns ──────────────────────────────────
    # _0x4a2b style variable names (common in JS obfuscators)
    obfuscated_vars = set(JS_OBFUSCATED_VAR_RE.findall(content))
    if len(obfuscated_vars) >= 5:
        findings.append({
            "type": "js_obfuscated_vars",
            "file": file_path,
            "severity": "high",
            "description": (
                f"JS obfuscator variable names detected "
                f"({len(obfuscated_vars)} unique _0x* identifiers)"
            ),
            "detail": {
                "count": len(obfuscated_vars),
                "samples": sorted(obfuscated_vars)[:10],
            },
        })

    # Obfuscator string arrays: var _0x1234 = ["eval","fromCharCode",...]
    for match in OBFUSCATOR_ARRAY_RE.finditer(content):
        findings.append({
            "type": "obfuscator_string_array",
            "file": file_path,
            "severity": "high",
            "description": "JS obfuscator string lookup array detected",
            "detail": {"preview": match.group()[:120]},
        })

    # ── Eval of decoded/computed strings ────────────────────────
    for match in EVAL_DECODE_RE.finditer(content):
        call = match.group()
        findings.append({
            "type": "eval_decoded_string",
            "file": file_path,
            "severity": "critical",
            "description": (
                f"eval/exec of decoded string: {call[:80]}"
            ),
            "detail": {"pattern": call[:120]},
        })

    # ── High-entropy strings ────────────────────────────────────
    tokens = re.split(r'[\s"\'`,;=\[\]\{\}\(\)]+', content)
    seen_high_entropy = set()
    for token in tokens:
        if len(token) < ENTROPY_MIN_LENGTH:
            continue
        ent = shannon_entropy(token)
        if ent > ENTROPY_THRESHOLD:
            key = (file_path, hash(token))
            if key not in seen_high_entropy:
                seen_high_entropy.add(key)
                findings.append({
                    "type": "high_entropy_string",
                    "file": file_path,
                    "severity": "low",
                    "description": (
                        f"High-entropy string ({len(token)} chars, "
                        f"entropy={ent:.2f} bits/char)"
                    ),
                    "detail": {
                        "length": len(token),
                        "entropy": round(ent, 2),
                        "preview": token[:60] + "..." if len(token) > 60 else token,
                    },
                })


def scan_deps_dir() -> None:
    """Walk /opt/deps/ and analyze text files."""
    if not os.path.isdir(DEPS_DIR):
        return

    for root, dirs, files in os.walk(DEPS_DIR):
        # Skip common non-source dirs
        dirs[:] = [d for d in dirs if d not in {
            "node_modules", ".git", "__pycache__", ".tox", "venv",
        }]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            # Skip very large files (> 1 MB)
            try:
                if os.path.getsize(fpath) > 1_000_000:
                    continue
            except OSError:
                continue
            check_file(fpath)


if __name__ == "__main__":
    scan_deps_dir()
    output = {
        "scanner": "entropy",
        "findings": findings,
        "total": len(findings),
    }
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Entropy scan complete: {len(findings)} findings")
'''


def run_entropy(vm_name: str, output_dir: str) -> ScanResults:
    """Run entropy/obfuscation analysis inside the VM.

    Copies the analysis script into the VM, executes it, and returns
    metadata only. All findings data stays in the VM.

    Args:
        vm_name: Name of the Lima VM.
        output_dir: Directory for scan artifacts inside the VM.

    Returns:
        ScanResults with execution metadata only (findings stay in VM).
    """
    script_remote_path = "/tmp/entropy_scanner.py"

    start = time.monotonic()
    try:
        # Copy the script into the VM
        ssh_write_file(vm_name, _ENTROPY_SCRIPT, script_remote_path)

        # Execute it
        cmd = f"python3 {script_remote_path}"
        result = ssh_exec(vm_name, cmd, timeout=300)
        elapsed = time.monotonic() - start

        output_path = f"{output_dir}/entropy.json"

        if result.exit_code != 0:
            logger.warning(
                "Entropy scanner exited with code %d: %s",
                result.exit_code,
                result.stderr,
            )
            return ScanResults(
                tool_name="entropy",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=[
                    f"Entropy scanner failed (exit {result.exit_code}): "
                    f"{result.stderr}"
                ],
            )

        return ScanResults(
            tool_name="entropy",
            execution_time_seconds=elapsed,
            exit_code=result.exit_code,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Entropy scanner execution failed")
        return ScanResults(
            tool_name="entropy",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"Entropy scanner execution error: {exc}"],
        )


def parse_entropy_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse entropy scanner JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from the entropy scanner.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    for idx, item in enumerate(raw.get("findings", [])):
        finding_type = item.get("type", "unknown")
        severity = item.get("severity", "low")
        description = item.get("description", "")
        file_path = item.get("file")

        findings.append(
            Finding(
                id=f"entropy-{idx}-{finding_type}",
                source_tool="entropy",
                category="obfuscation",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=f"Obfuscation detected: {finding_type}",
                description=description,
                file_path=file_path,
                line_number=None,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output=item,
            )
        )

    return findings
