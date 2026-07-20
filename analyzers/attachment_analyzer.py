import hashlib
import re


# -------------------------
# File signature ("magic bytes") table.
# Each entry: (family_name, offset, signature_bytes)
# Checked in order; first match wins.
# -------------------------

FILE_SIGNATURES = [
    ("PE_EXECUTABLE", 0, b"MZ"),
    ("ELF_EXECUTABLE", 0, b"\x7fELF"),
    ("ZIP_ARCHIVE", 0, b"PK\x03\x04"),
    ("ZIP_ARCHIVE", 0, b"PK\x05\x06"),  # empty zip
    ("ZIP_ARCHIVE", 0, b"PK\x07\x08"),  # spanned zip
    ("RAR_ARCHIVE", 0, b"Rar!\x1a\x07"),
    ("SEVEN_ZIP_ARCHIVE", 0, b"7z\xbc\xaf\x27\x1c"),
    ("GZIP_ARCHIVE", 0, b"\x1f\x8b"),
    ("PDF_DOCUMENT", 0, b"%PDF"),
    ("OLE_DOCUMENT", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),  # legacy .doc/.xls/.ppt
    ("RTF_DOCUMENT", 0, b"{\\rtf"),
]

# Which "families" are legitimately expected for a given extension.
# A file is flagged as spoofed if its detected signature family exists
# (i.e. is a known binary type) but isn't in this expected set.
EXTENSION_EXPECTED_FAMILIES = {
    ".exe": {"PE_EXECUTABLE"},
    ".dll": {"PE_EXECUTABLE"},
    ".scr": {"PE_EXECUTABLE"},
    ".zip": {"ZIP_ARCHIVE"},
    ".docx": {"ZIP_ARCHIVE"},
    ".xlsx": {"ZIP_ARCHIVE"},
    ".pptx": {"ZIP_ARCHIVE"},
    ".docm": {"ZIP_ARCHIVE"},
    ".xlsm": {"ZIP_ARCHIVE"},
    ".pptm": {"ZIP_ARCHIVE"},
    ".jar": {"ZIP_ARCHIVE"},
    ".rar": {"RAR_ARCHIVE"},
    ".7z": {"SEVEN_ZIP_ARCHIVE"},
    ".gz": {"GZIP_ARCHIVE"},
    ".pdf": {"PDF_DOCUMENT"},
    ".doc": {"OLE_DOCUMENT"},
    ".xls": {"OLE_DOCUMENT"},
    ".ppt": {"OLE_DOCUMENT"},
    ".rtf": {"RTF_DOCUMENT"},
}

# Unicode right-to-left / bidi override characters used to visually
# disguise a dangerous extension (e.g. "invoice_\u202egnp.exe" renders
# as "invoice_exe.png" to the eye).
BIDI_OVERRIDE_CHARS = [
    "\u202a",  # LRE
    "\u202b",  # RLE
    "\u202c",  # PDF (pop directional formatting)
    "\u202d",  # LRO
    "\u202e",  # RLO - the common one used in RLO spoofing attacks
]

DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.[a-z0-9]{2,5}\.(exe|scr|bat|cmd|js|vbs|ps1|jar|com|pif|dll|msi)$",
    re.IGNORECASE
)

# -------------------------
# Script content sniffing.
# Applied to attachments with no recognized binary signature (UNKNOWN
# family), since malicious scripts are plain text and hide behind
# innocent-looking extensions like .txt, .log, .csv, or even .jpg.
# Each entry: (label, regex pattern)
# -------------------------

SCRIPT_CONTENT_INDICATORS = [
    ("PowerShell download/execute", re.compile(r"(?i)invoke-expression|iex\s*\(|downloadstring|downloadfile|-encodedcommand|net\.webclient")),
    ("PowerShell obfuscation", re.compile(r"(?i)-nop\b|-noprofile|-windowstyle\s+hidden|-executionpolicy\s+bypass|frombase64string")),
    ("VBScript shell execution", re.compile(r"(?i)createobject\s*\(\s*[\"']wscript\.shell|createobject\s*\(\s*[\"']shell\.application")),
    ("JScript/HTA shell execution", re.compile(r"(?i)activexobject\s*\(\s*[\"']wscript\.shell|activexobject\s*\(\s*[\"']shell\.application")),
    ("Obfuscated JavaScript eval", re.compile(r"(?i)eval\s*\(\s*unescape\s*\(|eval\s*\(\s*atob\s*\(|fromcharcode\s*\(")),
    ("Windows shell command chain", re.compile(r"(?i)cmd(\.exe)?\s*/c\s|%comspec%")),
    ("Macro auto-execution", re.compile(r"(?i)auto_?open\b|auto_?exec\b|document_open\b|workbook_open\b")),
    ("Remote payload retrieval", re.compile(r"(?i)certutil\s+-urlcache|bitsadmin\s+/transfer|start-bitstransfer")),
]

MAX_SNIFF_BYTES = 200_000  # avoid decoding huge attachments as text


def detect_script_content_indicators(data):
    """Scan attachment content for known malicious-script patterns.
    Returns a list of matched indicator labels (empty if none found or
    if the content doesn't look like readable text)."""

    if not data:
        return []

    sample = data[:MAX_SNIFF_BYTES]

    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = sample.decode("latin-1")
        except Exception:
            return []

    matches = []

    for label, pattern in SCRIPT_CONTENT_INDICATORS:

        if pattern.search(text):
            matches.append(label)

    return matches


def detect_file_signature(data):
    """Identify the real file type from its magic bytes, ignoring
    whatever extension the filename claims to be."""

    if not data:
        return "UNKNOWN"

    for family, offset, signature in FILE_SIGNATURES:

        if data[offset:offset + len(signature)] == signature:
            return family

    return "UNKNOWN"


def detect_extension_spoofing(filename, detected_family):
    """Flag a mismatch between the file's real (signature-detected) type
    and what its extension claims to be - e.g. a PE executable saved
    with a .pdf extension."""

    filename_lower = filename.lower()

    matched_ext = None

    for ext in EXTENSION_EXPECTED_FAMILIES:

        if filename_lower.endswith(ext):
            matched_ext = ext
            break

    if not matched_ext:
        return False

    if detected_family == "UNKNOWN":
        # Can't confirm a binary signature either way (may genuinely be
        # a plain text / script file, which has no magic bytes).
        return False

    expected_families = EXTENSION_EXPECTED_FAMILIES[matched_ext]

    return detected_family not in expected_families


def detect_double_extension(filename):
    """Flag classic '.pdf.exe' style disguised double extensions."""

    return bool(DOUBLE_EXTENSION_PATTERN.search(filename))


def detect_bidi_override(filename):
    """Flag Unicode right-to-left override characters used to visually
    disguise a dangerous extension (RLO spoofing)."""

    return any(char in filename for char in BIDI_OVERRIDE_CHARS)


def analyze_attachments(msg):

    attachments = []

    for part in msg.walk():

        filename = part.get_filename()

        if filename:

            try:

                data = part.get_payload(
                    decode=True
                )

                size = len(data)

                sha256 = hashlib.sha256(
                    data
                ).hexdigest()

                detected_family = detect_file_signature(data)

                extension_spoofed = detect_extension_spoofing(
                    filename,
                    detected_family
                )

                double_extension = detect_double_extension(
                    filename
                )

                bidi_override = detect_bidi_override(
                    filename
                )

                script_indicators = []

                if detected_family == "UNKNOWN":

                    script_indicators = detect_script_content_indicators(
                        data
                    )

                attachments.append(
                    {
                        "filename": filename,
                        "size": size,
                        "sha256": sha256,
                        "content_type": part.get_content_type(),
                        "detected_file_type": detected_family,
                        "extension_spoofed": extension_spoofed,
                        "double_extension": double_extension,
                        "bidi_override": bidi_override,
                        "script_indicators": script_indicators,
                    }
                )

            except Exception as e:

                print(
                    "Attachment Error:",
                    e
                )

    return attachments