"""Tests for the Thresher report JSON schema."""

import json
from pathlib import Path

import pytest
from jsonschema import ValidationError, validate

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "src" / "thresher" / "report" / "schema" / "report_schema.json"


@pytest.fixture(scope="module")
def schema():
    return json.loads(SCHEMA_PATH.read_text())


def _valid_report_data():
    """Return a minimal valid report data dict."""
    return {
        "meta": {
            "scan_date": "2026-04-09",
            "thresher_version": "0.2.2",
            "scanner_count": "22",
            "analyst_count": "8",
            "repo_name": "example/repo",
            "repo_url": "https://github.com/example/repo",
        },
        "verdict": {
            "label": "Low Risk",
            "severity": "low",
            "callout": "No critical issues found.",
        },
        "counts": {
            "total_scanner": "0",
            "total_ai": "0",
            "p0": "0",
            "critical": "0",
            "high_scanner": "0",
            "high_ai": "0",
            "medium": "0",
            "low": "0",
        },
        "executive_summary": "The repository appears safe.",
        "mitigations": [],
        "scanner_findings": [],
        "ai_findings": [],
        "trust_signals": [],
        "dependency_upgrades": [],
        "remediation": None,
        "pipeline": {
            "scanners": [],
            "analysts": [],
            "notes": "",
        },
        "config": {
            "show_cta": "true",
            "show_remediation": "false",
        },
    }


def test_valid_minimal_data_passes(schema):
    data = _valid_report_data()
    validate(instance=data, schema=schema)


def test_valid_full_data_passes(schema):
    data = _valid_report_data()
    data["mitigations"] = ["Update lodash to 4.17.21"]
    data["scanner_findings"] = [
        {
            "rank": "1",
            "severity": "critical",
            "package": "lodash@4.17.19",
            "title": "Prototype Pollution",
            "cve": "CVE-2021-23337",
            "cvss": "7.2",
        }
    ]
    data["ai_findings"] = [
        {
            "severity": "high",
            "title": "Suspicious eval() usage",
            "file": "src/utils.js",
            "description": "Dynamic code execution from user input.",
            "confidence": "85%",
            "analysts": ["code-reviewer", "supply-chain"],
        }
    ]
    data["trust_signals"] = [
        {"icon": "check", "text": "Signed commits"},
    ]
    data["dependency_upgrades"] = [
        {
            "package": "lodash",
            "old_version": "4.17.19",
            "new_version": "4.17.21",
            "severity": "critical",
            "cvss": "7.2",
            "cves": "CVE-2021-23337",
        }
    ]
    data["remediation"] = {
        "pr_title": "fix: upgrade lodash",
        "pr_url": "https://github.com/example/repo/pull/42",
        "summary": "Upgrades lodash to fix prototype pollution.",
        "fixes": ["CVE-2021-23337"],
    }
    data["pipeline"] = {
        "scanners": ["grype", "trivy", "osv"],
        "analysts": ["code-reviewer", "supply-chain"],
        "notes": "All scanners completed successfully.",
    }
    validate(instance=data, schema=schema)


def test_missing_required_top_level_field(schema):
    data = _valid_report_data()
    del data["verdict"]
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_missing_required_meta_field(schema):
    data = _valid_report_data()
    del data["meta"]["repo_name"]
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_invalid_severity_enum(schema):
    data = _valid_report_data()
    data["verdict"]["severity"] = "urgent"
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_invalid_scanner_finding_severity(schema):
    data = _valid_report_data()
    data["scanner_findings"] = [
        {
            "rank": "1",
            "severity": "CRITICAL",
            "package": "lodash@4.17.19",
            "title": "Prototype Pollution",
            "cve": "CVE-2021-23337",
            "cvss": "7.2",
        }
    ]
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_integer_value_rejected(schema):
    data = _valid_report_data()
    data["counts"]["critical"] = 5
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_additional_properties_rejected(schema):
    data = _valid_report_data()
    data["extra_field"] = "should not be here"
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_remediation_null_is_valid(schema):
    data = _valid_report_data()
    data["remediation"] = None
    validate(instance=data, schema=schema)


def test_remediation_object_is_valid(schema):
    data = _valid_report_data()
    data["remediation"] = {
        "pr_title": "fix: upgrade deps",
        "pr_url": "https://github.com/example/repo/pull/1",
        "summary": "Upgrades vulnerable dependencies.",
        "fixes": ["CVE-2021-12345"],
    }
    validate(instance=data, schema=schema)


def test_invalid_config_show_cta(schema):
    data = _valid_report_data()
    data["config"]["show_cta"] = "yes"
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_empty_arrays_valid(schema):
    data = _valid_report_data()
    data["mitigations"] = []
    data["scanner_findings"] = []
    data["ai_findings"] = []
    data["trust_signals"] = []
    data["dependency_upgrades"] = []
    validate(instance=data, schema=schema)
