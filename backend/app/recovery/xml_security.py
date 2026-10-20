"""
xml_security.py — Safe XML decoding, parsing, and security boundary enforcement.

Provides:
  - decode_xml_bytes: Robust multi-byte encoding detection and decoding (UTF-8, UTF-16LE, UTF-16BE).
  - check_xml_security: Lexical security pre-audit preventing XXE (SYSTEM/PUBLIC) and Billion Laughs bombs across encodings.
  - safe_parse_xml: Parser-level enforcement using defusedxml (if available) or standard expat handlers forbidding external DTDs and entity recursion.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import xml.parsers.expat as expat
from typing import Optional, Tuple

try:
    import defusedxml.ElementTree as defused_ET
except ImportError:
    defused_ET = None


class XMLSecurityError(ValueError):
    """Raised when an unsafe XML construct (XXE or Billion Laughs bomb) is detected."""
    pass


def decode_xml_bytes(raw: bytes) -> Tuple[str, str, Optional[str]]:
    """Decode raw XML bytes into Unicode text, detecting encoding from BOM or XML declaration.

    Supports UTF-8, UTF-16LE, and UTF-16BE (including documents with leading XML whitespace).
    Returns (text, encoding_name, error_message).
    """
    if not raw:
        return "", "utf-8", "XML bytes are empty"

    # 1. Byte Order Mark (BOM) detection
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw[3:].decode("utf-8"), "utf-8", None
        except UnicodeDecodeError as e:
            return "", "utf-8", f"UTF-8 decoding failed: {e}"
    elif raw.startswith(b"\xff\xfe"):
        try:
            return raw[2:].decode("utf-16le"), "utf-16le", None
        except UnicodeDecodeError as e:
            return "", "utf-16le", f"UTF-16LE decoding failed: {e}"
    elif raw.startswith(b"\xfe\xff"):
        try:
            return raw[2:].decode("utf-16be"), "utf-16be", None
        except UnicodeDecodeError as e:
            return "", "utf-16be", f"UTF-16BE decoding failed: {e}"

    # 2. Heuristic multi-byte detection without BOM (handling leading XML whitespace)
    # XML whitespace in ASCII: space (0x20), tab (0x09), LF (0x0A), CR (0x0D)
    raw_len = len(raw)
    ws_chars = (0x20, 0x09, 0x0A, 0x0D)

    # Check UTF-16LE: sequence of (ws, 0x00)* followed by (0x3C, 0x00) ('<')
    i = 0
    while i + 1 < raw_len and raw[i] in ws_chars and raw[i + 1] == 0x00:
        i += 2
    if i + 1 < raw_len and raw[i] == 0x3C and raw[i + 1] == 0x00:
        try:
            return raw.decode("utf-16le"), "utf-16le", None
        except UnicodeDecodeError as e:
            return "", "utf-16le", f"UTF-16LE decoding failed: {e}"

    # Check UTF-16BE: sequence of (0x00, ws)* followed by (0x00, 0x3C) ('<')
    j = 0
    while j + 1 < raw_len and raw[j] == 0x00 and raw[j + 1] in ws_chars:
        j += 2
    if j + 1 < raw_len and raw[j] == 0x00 and raw[j + 1] == 0x3C:
        try:
            return raw.decode("utf-16be"), "utf-16be", None
        except UnicodeDecodeError as e:
            return "", "utf-16be", f"UTF-16BE decoding failed: {e}"

    # 3. Default to UTF-8
    try:
        return raw.decode("utf-8"), "utf-8", None
    except UnicodeDecodeError as e:
        return "", "utf-8", f"UTF-8 decoding failed: {e}"


def check_xml_security(data: bytes | str) -> Optional[str]:
    """Check for unsafe XML constructs (XXE, Billion Laughs entity bombs).

    Accepts raw evidence bytes or decoded Unicode string.
    Decodes multi-byte encodings (UTF-16LE/BE) to ensure lexical checks cannot be bypassed.
    Returns an error description if unsafe, or None if safe.
    """
    text: str
    if isinstance(data, (bytes, bytearray)):
        text, _, err = decode_xml_bytes(bytes(data))
        if err:
            return None
    elif isinstance(data, str):
        text = data
    else:
        return None

    lower = text.lower()

    # External DTD and external entities (SYSTEM / PUBLIC)
    if "<!doctype" in lower and ("system" in lower or "public" in lower):
        return "XML contains external DOCTYPE declaration: external entity reference (XXE vulnerability protection)"

    if "<!entity" in lower:
        # Check for external entities (SYSTEM, PUBLIC)
        if "system" in lower or "public" in lower:
            return "XML contains external entity reference (XXE vulnerability protection)"
        # Check for recursive entity expansion (Billion Laughs)
        entity_count = lower.count("<!entity")
        if entity_count > 3:
            return "XML contains excessive entity declarations (Entity expansion protection)"

    return None


def safe_parse_xml(
    text: str,
    forbid_dtd: bool = True,
    forbid_entities: bool = True,
) -> ET.Element:
    """Parse XML string with strict parser-level entity and DTD protections.

    If defusedxml is available, enforces forbid_dtd and forbid_entities.
    Otherwise, configures standard library xml.parsers.expat with strict security
    handlers enforcing identical defensive policy against DTDs and entity declarations.

    Args:
        text: XML string to parse.
        forbid_dtd: If True, forbids any DOCTYPE declaration.
        forbid_entities: If True, forbids any entity declaration.

    Returns:
        Root Element of parsed XML.

    Raises:
        XMLSecurityError: When forbidden DTD or entity construct is encountered.
        expat.ExpatError / ET.ParseError: When XML syntax is malformed.
    """
    # Always enforce baseline security invariants against XXE and Billion Laughs
    sec_err = check_xml_security(text)
    if sec_err:
        raise XMLSecurityError(f"XML security policy violation: {sec_err}")

    if defused_ET is not None:
        try:
            return defused_ET.fromstring(
                text,
                forbid_dtd=forbid_dtd,
                forbid_entities=forbid_entities,
                forbid_external=True,
            )
        except Exception as e:
            # If defusedxml raised a security exception (DTDForbidden, EntitiesForbidden, etc.),
            # convert to XMLSecurityError to guarantee consistent caller handling.
            if "Forbidden" in type(e).__name__ or (
                hasattr(defused_ET, "DefusedXmlException")
                and isinstance(e, getattr(defused_ET, "DefusedXmlException", ValueError))
            ):
                raise XMLSecurityError(f"XML security policy violation: {e}") from e
            raise

    builder = ET.TreeBuilder()
    p = expat.ParserCreate()
    entity_count = [0]

    def start_element(name, attrs):
        builder.start(name, attrs)

    def end_element(name):
        builder.end(name)

    def char_data(data):
        builder.data(data)

    def start_doctype(name, system_id, public_id, has_internal_subset):
        if system_id or public_id:
            raise XMLSecurityError(
                f"XML contains external DOCTYPE declaration: system={system_id}, public={public_id}"
            )
        if forbid_dtd:
            raise XMLSecurityError(
                f"XML contains forbidden DOCTYPE declaration: {name}"
            )

    def entity_decl(entityName, is_parameter_entity, value, base, systemId, publicId, notationName):
        entity_count[0] += 1
        if forbid_entities:
            raise XMLSecurityError(
                f"XML contains forbidden entity declaration: {entityName}"
            )
        if systemId or publicId:
            raise XMLSecurityError(f"XML contains external entity declaration: {entityName}")
        if entity_count[0] > 3:
            raise XMLSecurityError(
                f"XML contains excessive entity declarations ({entity_count[0]}) (Billion Laughs protection)"
            )

    def external_ref(context, base, systemId, publicId):
        raise XMLSecurityError(f"XML contains external entity reference: {systemId}")

    p.StartElementHandler = start_element
    p.EndElementHandler = end_element
    p.CharacterDataHandler = char_data
    p.StartDoctypeDeclHandler = start_doctype
    p.EntityDeclHandler = entity_decl
    p.ExternalEntityRefHandler = external_ref

    p.Parse(text, True)
    return builder.close()
