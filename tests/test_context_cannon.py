"""Tests for context-cannon core functionality."""

import json
import tempfile
from pathlib import Path

import pytest

from context_cannon import ContextCannon, C


class TestPayloadGeneration:
    """Tests for generating payloads by type and context."""

    def setup_method(self):
        self.cannon = ContextCannon()

    def test_xss_html_returns_payloads(self):
        result = self.cannon.generate('xss', 'html')
        assert len(result) > 0
        assert any('<script>' in p for p in result)

    def test_sqli_mysql_returns_payloads(self):
        result = self.cannon.generate('sqli', 'mysql')
        assert len(result) > 0
        assert any('UNION' in p for p in result)

    def test_ssti_jinja2_returns_payloads(self):
        result = self.cannon.generate('ssti', 'jinja2')
        assert len(result) > 0
        assert any('{{' in p for p in result)

    def test_ssrf_localhost_returns_payloads(self):
        result = self.cannon.generate('ssrf', 'localhost')
        assert len(result) > 0
        assert any('127.0.0.1' in p for p in result)

    def test_lfi_basic_returns_payloads(self):
        result = self.cannon.generate('lfi', 'basic')
        assert len(result) > 0
        assert any('etc/passwd' in p for p in result)

    def test_cmdi_basic_returns_payloads(self):
        result = self.cannon.generate('cmdi', 'basic')
        assert len(result) > 0
        assert any('; id' in p for p in result)

    def test_all_contexts_no_context(self):
        result = self.cannon.generate('xss')
        # Should return payloads from all XSS contexts
        assert len(result) > 10

    def test_unknown_type_returns_empty(self):
        result = self.cannon.generate('nosuchtype')
        assert result == []

    def test_invalid_context_falls_back(self):
        result = self.cannon.generate('xss', 'nonexistent')
        # Falls back to all contexts
        assert len(result) > 0


class TestFiltering:
    """Tests for --filter functionality."""

    def setup_method(self):
        self.cannon = ContextCannon()

    def test_filter_removes_matching(self):
        result = self.cannon.generate('xss', 'html', filters='script')
        assert all('script' not in p.lower() for p in result)

    def test_filter_multiple(self):
        result = self.cannon.generate('xss', 'html', filters='script,alert')
        assert all('script' not in p.lower() and 'alert' not in p.lower() for p in result)

    def test_filter_case_insensitive(self):
        result = self.cannon.generate('xss', 'html', filters='SCRIPT')
        assert all('script' not in p.lower() for p in result)

    def test_filter_all_returns_empty(self):
        # Filter everything
        result = self.cannon.generate('sqli', 'mysql', filters="'")
        assert result == []


class TestEncoding:
    """Tests for encoding functionality."""

    def setup_method(self):
        self.cannon = ContextCannon()

    def test_url_encoding(self):
        result = self.cannon.generate('xss', 'html', encode='url')
        assert len(result) > 0
        # URL encoded payloads shouldn't have raw < or >
        assert all('<' not in p for p in result)

    def test_base64_encoding(self):
        result = self.cannon.generate('xss', 'html', encode='base64')
        assert len(result) > 0
        # Base64 doesn't contain < or >
        assert all('<' not in p for p in result)

    def test_html_encoding(self):
        result = self.cannon.generate('xss', 'html', encode='html')
        assert len(result) > 0
        # HTML encoded < becomes &lt;
        assert all('<' not in p for p in result)

    def test_hex_encoding(self):
        result = self.cannon.generate('xss', 'html', encode='hex')
        assert len(result) > 0
        assert all('%' in p for p in result)

    def test_double_url_encoding(self):
        result = self.cannon.generate('xss', 'html', encode='double_url')
        assert len(result) > 0
        # Double-encoded % becomes %25
        assert all('%25' in p for p in result)


class TestDeduplication:
    """Tests for payload deduplication."""

    def setup_method(self):
        self.cannon = ContextCannon()

    def test_no_duplicates(self):
        result = self.cannon.generate('xss')
        assert len(result) == len(set(result))

    def test_deterministic_order(self):
        result1 = self.cannon.generate('xss', 'html')
        result2 = self.cannon.generate('xss', 'html')
        assert result1 == result2


class TestColorDisable:
    """Tests for --no-color functionality."""

    def test_disable_colors(self):
        C.disable()
        assert C.R == ''
        assert C.G == ''
        assert C.Y == ''
        assert C.E == ''
        # Reset for other tests
        C.R = '\033[91m'
        C.G = '\033[92m'
        C.Y = '\033[93m'
        C.B = '\033[94m'
        C.M = '\033[95m'
        C.C = '\033[96m'
        C.W = '\033[97m'
        C.E = '\033[0m'


class TestPayloadCoverage:
    """Tests that all vuln types and contexts are populated."""

    def setup_method(self):
        self.cannon = ContextCannon()

    def test_all_types_exist(self):
        expected = {'xss', 'sqli', 'ssti', 'ssrf', 'lfi', 'cmdi'}
        assert set(self.cannon.payloads.keys()) == expected

    def test_all_contexts_have_payloads(self):
        for vtype, contexts in self.cannon.payloads.items():
            for ctx, payloads in contexts.items():
                assert len(payloads) > 0, f"{vtype}/{ctx} has no payloads"

    def test_minimum_payload_count(self):
        total = sum(
            len(p) for ctx in self.cannon.payloads.values() for p in ctx.values()
        )
        assert total >= 100


class TestFileOutput:
    """Tests for file output functionality."""

    def test_output_file_content(self):
        cannon = ContextCannon()
        payloads = cannon.generate('sqli', 'mysql')
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(payloads))
            path = f.name

        content = Path(path).read_text()
        lines = content.strip().split('\n')
        assert len(lines) == len(payloads)
        Path(path).unlink()
