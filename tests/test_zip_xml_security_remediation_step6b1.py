"""
test_zip_xml_security_remediation_step6b1.py — Focused Regression Suite for Step 6B.1 Remediation.

Proves:
  Part A (ZIP Decompression Safety):
    1. An archive exceeding decompression-bomb thresholds is rejected.
    2. ZipFile.testzip() is NOT called when bomb or Zip-Slip security thresholds are breached (verified via mock/spy).
    3. Ordinary valid ZIP files validate correctly and invoke testzip() for CRC verification.
    4. Malformed ZIP inputs produce controlled validation failures rather than unhandled server errors.
    5. Zip-Slip directory traversal attempts are rejected and testzip() is aborted.
    6. Reconstruct_zip immediately rejects security violations without attempting member decompression.

  Part B (XML Parser Safety):
    7. Valid UTF-8 XML validates correctly and extracts root metadata.
    8. Valid multibyte XML (UTF-16LE and UTF-16BE) validates correctly and detects encoding.
    9. XXE external entity references (SYSTEM) are rejected across UTF-8, UTF-16LE, and UTF-16BE.
    10. DOCTYPE external references (PUBLIC) are rejected across UTF-8, UTF-16LE, and UTF-16BE.
    11. Recursive entity expansion (Billion Laughs) is rejected across UTF-8, UTF-16LE, and UTF-16BE.
    12. Scanner format classification safely processes hostile XML without expanding entities or crashing.
    13. Malformed XML produces controlled validation failures with clean error messages.
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from unittest.mock import patch, MagicMock

import pytest

from backend.app.recovery.validators.zip import (
    validate_zip,
    check_zip_path_security,
    is_safe_zip_path,
    MAX_SAFE_EXPANSION_RATIO,
    MAX_SAFE_UNCOMPRESSED_SIZE,
)
from backend.app.recovery.reconstructors.zip import reconstruct_zip
from backend.app.recovery.validators.xml import (
    validate_xml,
    check_xml_security,
    decode_xml_bytes,
    safe_parse_xml,
    XMLSecurityError,
)
from backend.app.recovery.scanner import _classify_synthetic_content, scan_evidence


# ── PART A: ZIP DECOMPRESSION SAFETY ───────────────────────────────────

def create_in_memory_zip(files: dict[str, bytes]) -> bytes:
    """Helper to create a standard valid ZIP archive in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_ordinary_valid_zip_passes_and_calls_testzip():
    """Verify that legitimate ZIP archives validate successfully and testzip() runs."""
    valid_data = create_in_memory_zip({"hello.txt": b"Hello Recoverix Evidence"})

    real_testzip = zipfile.ZipFile.testzip
    call_count = [0]

    def spy_testzip(self):
        call_count[0] += 1
        return real_testzip(self)

    with patch.object(zipfile.ZipFile, "testzip", spy_testzip):
        res = validate_zip(valid_data)
        assert res.valid
        assert len(res.errors) == 0
        assert res.details["file_count"] == 1
        assert call_count[0] == 1


def test_zip_bomb_threshold_rejection_and_testzip_not_called():
    """Verify that an archive exceeding safe limits is rejected and testzip() is NOT called."""
    # Create a small valid zip
    valid_data = create_in_memory_zip({"file.bin": b"A" * 1024})

    # Mock total uncompressed size and ratio to simulate exceeding thresholds
    # We patch infolist on the zipfile instance to simulate a decompression bomb
    original_infolist = zipfile.ZipFile.infolist

    def fake_infolist(self):
        real = original_infolist(self)
        for zinfo in real:
            # Simulate a 200 MiB uncompressed file from 1 KiB compressed (ratio > 100:1)
            zinfo.file_size = int(MAX_SAFE_UNCOMPRESSED_SIZE * 2)
            zinfo.compress_size = 1024
        return real

    with patch.object(zipfile.ZipFile, "infolist", fake_infolist):
        with patch.object(zipfile.ZipFile, "testzip") as mock_testzip:
            res = validate_zip(valid_data)
            assert not res.valid
            assert any("Security: Decompression ratio" in e or "safe limit" in e for e in res.errors)
            # PROVE: testzip() was NEVER called because security threshold was breached
            mock_testzip.assert_not_called()


def test_zip_slip_rejection_and_testzip_not_called():
    """Verify that Zip-Slip path traversal is rejected and testzip() is aborted."""
    slip_data = create_in_memory_zip({"../../etc/shadow": b"root:x:0:0:root"})

    with patch.object(zipfile.ZipFile, "testzip") as mock_testzip:
        res = validate_zip(slip_data)
        assert not res.valid
        assert any("Zip-Slip" in e for e in res.errors)
        # PROVE: testzip() was NEVER called because Zip-Slip violation was detected
        mock_testzip.assert_not_called()


def test_malformed_zip_controlled_rejection():
    """Verify that malformed or truncated ZIP bytes produce controlled errors, not unhandled 500s."""
    # Truncated local header
    truncated = b"PK\x03\x04\x14\x00\x00\x00"
    res1 = validate_zip(truncated)
    assert not res1.valid
    assert len(res1.errors) > 0

    # Random binary garbage
    garbage = b"\xde\xad\xbe\xef" * 32
    res2 = validate_zip(garbage)
    assert not res2.valid
    assert any("Missing valid 4-byte ZIP Local File Header" in e for e in res2.errors)


def test_zip_reconstruction_aborts_on_security_violation():
    """Verify that reconstruct_zip aborts immediately on security violations without decompression."""
    slip_data = create_in_memory_zip({"../evil.sh": b"#!/bin/bash\nrm -rf /"})
    recon_res = reconstruct_zip(slip_data)
    assert not recon_res.success
    assert recon_res.status == "UNRECOVERABLE"
    assert any("Zip-Slip" in r.get("description", "") for r in recon_res.damage_regions)


# ── PART B: XML PARSER SAFETY ──────────────────────────────────────────

def test_valid_utf8_xml_passes():
    """Verify that standard valid UTF-8 XML passes validation and records metadata."""
    xml_data = b'<?xml version="1.0" encoding="utf-8"?><evidence id="101"><note>Valid</note></evidence>'
    res = validate_xml(xml_data)
    assert res.valid
    assert res.details["root_tag"] == "evidence"
    assert res.details["encoding"] == "utf-8"
    assert res.details["has_xml_declaration"] is True


def test_valid_utf16_multibyte_xml_passes():
    """Verify that valid UTF-16LE and UTF-16BE XML validates correctly."""
    # UTF-16LE with BOM
    xml_text = '<?xml version="1.0"?><forensicCase><id>42</id></forensicCase>'
    xml_utf16le = b"\xff\xfe" + xml_text.encode("utf-16le")
    res_le = validate_xml(xml_utf16le)
    assert res_le.valid
    assert res_le.details["root_tag"] == "forensicCase"
    assert res_le.details["encoding"] == "utf-16le"

    # UTF-16BE with BOM
    xml_utf16be = b"\xfe\xff" + xml_text.encode("utf-16be")
    res_be = validate_xml(xml_utf16be)
    assert res_be.valid
    assert res_be.details["root_tag"] == "forensicCase"
    assert res_be.details["encoding"] == "utf-16be"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16le", "utf-16be"])
def test_xml_xxe_system_entity_rejected_across_encodings(encoding: str):
    """Verify that XXE SYSTEM entity references are rejected across all supported encodings."""
    xxe_template = """<?xml version="1.0"?>
    <!DOCTYPE test [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <test>&xxe;</test>"""

    payload = xxe_template.encode(encoding)
    # If UTF-16, prepend appropriate BOM for robust standard testing
    if encoding == "utf-16le":
        payload = b"\xff\xfe" + payload
    elif encoding == "utf-16be":
        payload = b"\xfe\xff" + payload

    # 1. Check security function
    sec_err = check_xml_security(payload)
    assert sec_err is not None
    assert "XXE" in sec_err

    # 2. Check full validator
    res = validate_xml(payload)
    assert not res.valid
    assert any("XXE" in err for err in res.errors)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16le", "utf-16be"])
def test_xml_public_entity_rejected_across_encodings(encoding: str):
    """Verify that PUBLIC external DTD references are rejected across all supported encodings."""
    public_template = """<?xml version="1.0"?>
    <!DOCTYPE test PUBLIC "-//OASIS//DTD DocBook XML V4.1.2//EN" "http://attacker.com/evil.dtd">
    <test>Content</test>"""

    payload = public_template.encode(encoding)
    if encoding == "utf-16le":
        payload = b"\xff\xfe" + payload
    elif encoding == "utf-16be":
        payload = b"\xfe\xff" + payload

    sec_err = check_xml_security(payload)
    assert sec_err is not None
    assert "XXE" in sec_err

    res = validate_xml(payload)
    assert not res.valid
    assert any("XXE" in err for err in res.errors)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16le", "utf-16be"])
def test_xml_billion_laughs_rejected_across_encodings(encoding: str):
    """Verify that recursive entity expansion (Billion Laughs) is rejected across encodings."""
    bomb_template = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol1 "&lol;&lol;">
      <!ENTITY lol2 "&lol1;&lol1;">
      <!ENTITY lol3 "&lol2;&lol2;">
    ]>
    <lolz>&lol3;</lolz>"""

    payload = bomb_template.encode(encoding)
    if encoding == "utf-16le":
        payload = b"\xff\xfe" + payload
    elif encoding == "utf-16be":
        payload = b"\xfe\xff" + payload

    sec_err = check_xml_security(payload)
    assert sec_err is not None
    assert "Entity expansion" in sec_err

    res = validate_xml(payload)
    assert not res.valid
    assert any("Entity expansion" in err for err in res.errors)


def test_safe_parse_xml_raises_on_external_dtd_and_entities():
    """Verify parser-level enforcement in safe_parse_xml."""
    # External DOCTYPE
    with pytest.raises(XMLSecurityError) as exc1:
        safe_parse_xml('<!DOCTYPE test SYSTEM "http://evil.com/xxe.dtd"><test>1</test>')
    assert "external DOCTYPE" in str(exc1.value)

    # Excessive entity definitions
    bomb = """<!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol1 "&lol;&lol;">
      <!ENTITY lol2 "&lol1;&lol1;">
      <!ENTITY lol3 "&lol2;&lol2;">
    ]><lolz>&lol3;</lolz>"""
    with pytest.raises(XMLSecurityError) as exc2:
        safe_parse_xml(bomb, forbid_dtd=False, forbid_entities=False)
    assert "excessive entity" in str(exc2.value)


def test_xml_scanner_format_detection_safety():
    """Verify that scanner format detection handles malicious XML without executing unsafe entity resolution."""
    malicious_body = b"""<?xml version="1.0"?>
    <!DOCTYPE test [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <test>&xxe;</test>"""

    # _classify_synthetic_content should safely identify xml without crashing or resolving external entity
    fmt, mime, cat = _classify_synthetic_content(malicious_body)
    assert fmt == "xml"
    assert mime == "application/xml"
    assert cat == "structured"

    # Synthetic block scanning
    synthetic_block = b"[SYNTHETIC_ARTIFACT_START]" + malicious_body + b"[SYNTHETIC_ARTIFACT_END]"
    candidates = scan_evidence(synthetic_block)
    assert len(candidates) >= 1
    assert candidates[0].format == "xml"


def test_malformed_xml_produces_controlled_error():
    """Verify that malformed XML produces structured validation failure, not an unhandled exception."""
    malformed = b"<root><item>Missing closing tag</root>"
    res = validate_xml(malformed)
    assert not res.valid
    assert any("XML parsing failed" in e for e in res.errors)


# ── PART C: STEP 6B.1B REMEDIATION TESTS ─────────────────────────────────

@pytest.mark.parametrize(
    "path,expected_safe,reason",
    [
        ("folder/file.txt", True, "Safe relative nested path"),
        ("a/b/c/d/file.csv", True, "Safe deep nested path"),
        ("hello.txt", True, "Safe single filename"),
        ("..safe.txt", True, "Safe filename with leading double dots"),
        ("safe..name.txt", True, "Safe filename with internal double dots"),
        ("nested/dir/", True, "Safe directory path"),
        ("C:\\Windows\\System32\\cmd.exe", False, "Windows drive backslash prefix"),
        ("C:/Windows/System32/cmd.exe", False, "Windows drive forward slash prefix"),
        ("C:payload.exe", False, "Windows drive relative path"),
        ("d:sub/file.txt", False, "Lowercase Windows drive relative path"),
        ("//server/share/file.txt", False, "UNC network forward slashes"),
        ("\\\\server\\share\\file.txt", False, "UNC network backslashes"),
        ("/etc/passwd", False, "Unix root absolute path"),
        ("\\Windows\\file.txt", False, "Windows root absolute path"),
        ("../secret.txt", False, "Parent traversal"),
        ("folder/../../secret.txt", False, "Nested parent traversal"),
        ("foo/..\\bar.txt", False, "Mixed separator traversal (forward then backslash)"),
        ("foo\\../bar.txt", False, "Mixed separator traversal (backslash then forward)"),
    ],
)
def test_zip_path_normalization_adversarial_suite(path: str, expected_safe: bool, reason: str):
    """Verify that Zip-Slip path normalization catches Windows drives, UNC paths, and mixed slashes."""
    is_safe = is_safe_zip_path(path)
    err = check_zip_path_security(path)
    if expected_safe:
        assert is_safe, f"Expected safe path for '{path}' ({reason}), but got error: {err}"
        assert err is None
    else:
        assert not is_safe, f"Expected unsafe path for '{path}' ({reason}), but evaluated as safe"
        assert err is not None

        # Verify that an archive with this path is rejected by validate_zip and testzip() is NOT called
        unsafe_zip = create_in_memory_zip({path: b"malicious content"})
        with patch.object(zipfile.ZipFile, "testzip") as mock_testzip:
            val_res = validate_zip(unsafe_zip)
            assert not val_res.valid
            assert any("Zip-Slip" in e for e in val_res.errors)
            mock_testzip.assert_not_called()

        # Verify that reconstruct_zip safely aborts without decompressing or executing payload
        recon_res = reconstruct_zip(unsafe_zip)
        assert not recon_res.success
        assert recon_res.status == "UNRECOVERABLE"


def test_safe_parse_xml_dual_parser_consistency():
    """Verify that safe_parse_xml behaves identically with defusedxml and standard expat fallback."""
    benign_xml = "<evidence><id>42</id><status>ACTIVE</status></evidence>"
    internal_dtd_xml = "<!DOCTYPE note [ <!ELEMENT note (body)> <!ELEMENT body (#PCDATA)> ]><note><body>Test</body></note>"
    entity_decl_xml = "<!DOCTYPE note [ <!ENTITY author \"Alice\"> ]><note><body>&author;</body></note>"
    external_dtd_xml = "<!DOCTYPE note SYSTEM \"http://evil.com/note.dtd\"><note>1</note>"
    bomb_xml = """<!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol1 "&lol;&lol;">
      <!ENTITY lol2 "&lol1;&lol1;">
      <!ENTITY lol3 "&lol2;&lol2;">
    ]><lolz>&lol3;</lolz>"""

    # 1. Test Expat fallback path (defused_ET is None)
    with patch("backend.app.recovery.xml_security.defused_ET", None):
        # Benign XML parses cleanly
        elem = safe_parse_xml(benign_xml)
        assert elem.tag == "evidence"

        # Internal DTD: rejected with default forbid_dtd=True
        with pytest.raises(XMLSecurityError) as exc:
            safe_parse_xml(internal_dtd_xml, forbid_dtd=True)
        assert "forbidden DOCTYPE" in str(exc.value)

        # Internal DTD: allowed with forbid_dtd=False, forbid_entities=True when no entities declared
        elem_dtd = safe_parse_xml(internal_dtd_xml, forbid_dtd=False, forbid_entities=True)
        assert elem_dtd.tag == "note"

        # Entity declaration: rejected when forbid_entities=True
        with pytest.raises(XMLSecurityError) as exc:
            safe_parse_xml(entity_decl_xml, forbid_dtd=False, forbid_entities=True)
        assert "forbidden entity" in str(exc.value)

        # External DTD: rejected
        with pytest.raises(XMLSecurityError) as exc:
            safe_parse_xml(external_dtd_xml)
        assert "DOCTYPE" in str(exc.value)

        # Bomb: rejected
        with pytest.raises(XMLSecurityError) as exc:
            safe_parse_xml(bomb_xml)
        assert "DOCTYPE" in str(exc.value) or "excessive" in str(exc.value)

    # 2. Test defused_ET path when defusedxml is simulated/present
    class MockDefusedET:
        class DefusedXmlException(ValueError):
            pass
        class DTDForbidden(DefusedXmlException):
            pass
        class EntitiesForbidden(DefusedXmlException):
            pass
        class ExternalReferenceForbidden(DefusedXmlException):
            pass

        @classmethod
        def fromstring(cls, text, forbid_dtd=True, forbid_entities=True, forbid_external=True):
            if forbid_dtd and "<!DOCTYPE" in text.upper():
                raise cls.DTDForbidden("DTD forbidden by security policy")
            if forbid_entities and "<!ENTITY" in text.upper():
                raise cls.EntitiesForbidden("Entities forbidden by security policy")
            if "SYSTEM" in text.upper() or "PUBLIC" in text.upper():
                raise cls.ExternalReferenceForbidden("External references forbidden")
            import xml.etree.ElementTree as standard_ET
            return standard_ET.fromstring(text)

    with patch("backend.app.recovery.xml_security.defused_ET", MockDefusedET):
        # Benign parses cleanly
        elem = safe_parse_xml(benign_xml)
        assert elem.tag == "evidence"

        # DTD forbidden raises XMLSecurityError (converted from DTDForbidden)
        with pytest.raises(XMLSecurityError) as exc:
            safe_parse_xml(internal_dtd_xml, forbid_dtd=True)
        assert "security policy violation" in str(exc.value)

        # Entity forbidden raises XMLSecurityError
        with pytest.raises(XMLSecurityError) as exc:
            safe_parse_xml(entity_decl_xml, forbid_dtd=False, forbid_entities=True)
        assert "security policy violation" in str(exc.value)

        # External DTD raises XMLSecurityError
        with pytest.raises(XMLSecurityError) as exc:
            safe_parse_xml(external_dtd_xml)
        assert "security policy violation" in str(exc.value)


@pytest.mark.parametrize(
    "whitespace_prefix",
    [
        "   ",
        "\t\t",
        "\r\n  ",
        "  \t\r\n  \t  ",
    ],
)
@pytest.mark.parametrize("encoding", ["utf-16le", "utf-16be"])
def test_utf16_xml_leading_whitespace_detection(whitespace_prefix: str, encoding: str):
    """Verify that UTF-16 XML with leading whitespace is detected and decoded correctly without BOM."""
    raw_content = f"{whitespace_prefix}<forensicLog id=\"99\"><entry>Valid</entry></forensicLog>"
    encoded_bytes = raw_content.encode(encoding)

    # 1. Direct decode_xml_bytes check without BOM
    text, detected_enc, err = decode_xml_bytes(encoded_bytes)
    assert err is None
    assert detected_enc == encoding
    assert "<forensicLog id=\"99\">" in text

    # 2. Validation check passes and extracts correct metadata
    res = validate_xml(encoded_bytes)
    assert res.valid
    assert res.details["root_tag"] == "forensicLog"
    assert res.details["encoding"] == encoding

    # 3. Hostile payload with leading whitespace in UTF-16 is decoded and rejected
    hostile_raw = f"{whitespace_prefix}<!DOCTYPE test SYSTEM \"http://attacker.com/evil.dtd\"><test/>"
    hostile_bytes = hostile_raw.encode(encoding)

    h_text, h_enc, h_err = decode_xml_bytes(hostile_bytes)
    assert h_err is None
    assert h_enc == encoding
    assert "evil.dtd" in h_text

    h_val = validate_xml(hostile_bytes)
    assert not h_val.valid
    assert any("XXE" in e or "DOCTYPE" in e for e in h_val.errors)
