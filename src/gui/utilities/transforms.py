import base64
import gzip
import hashlib
import html as _html_mod
from urllib.parse import quote, quote_plus, unquote, unquote_plus

from gui.utilities.decode_dialog import decode_text


_ENCODE_ONLY = {"md5", "sha1", "sha256"}
_DECODE_ONLY = {"jwt"}
_SYMMETRIC   = {"reverse"}


def transform_directions(name: str) -> list[str]:
    """Return the valid directions for a given transform name."""
    if name in _ENCODE_ONLY:
        return ["Hash"]
    if name in _DECODE_ONLY:
        return ["Decode"]
    if name in _SYMMETRIC:
        return ["Encode / Decode"]
    return ["Encode", "Decode"]


def apply_transform(text: str, name: str, direction: str) -> tuple[str | None, str]:
    """
    Apply a single transform step.
    Returns (result, error_message). result is None on failure.
    """
    try:
        if name == "base64":
            if direction == "Encode":
                return base64.b64encode(text.encode("utf-8")).decode("ascii"), ""
            else:
                result, _ = decode_text(text, "base64")
                return result, "" if result is not None else f"Cannot decode as Base64"

        if name == "url_full":
            if direction == "Encode":
                return quote_plus(text), ""
            else:
                return unquote_plus(text), ""

        if name == "url_component":
            if direction == "Encode":
                return quote(text, safe=""), ""
            else:
                return unquote(text), ""

        if name == "html":
            if direction == "Encode":
                return _html_mod.escape(text), ""
            else:
                result = _html_mod.unescape(text)
                return result, ""

        if name == "hex":
            if direction == "Encode":
                return text.encode("utf-8").hex(), ""
            else:
                result, _ = decode_text(text, "hex")
                return result, "" if result is not None else "Cannot decode as Hex"

        if name == "unicode_escape":
            if direction == "Encode":
                return text.encode("unicode_escape").decode("ascii"), ""
            else:
                result, _ = decode_text(text, "unicode")
                return result, "" if result is not None else "Cannot decode Unicode escapes"

        if name == "gzip":
            if direction == "Encode":
                compressed = gzip.compress(text.encode("utf-8"))
                return base64.b64encode(compressed).decode("ascii"), ""
            else:
                raw = base64.b64decode(text + "=" * ((4 - len(text) % 4) % 4))
                return gzip.decompress(raw).decode("utf-8"), ""

        if name == "jwt":
            result, _ = decode_text(text, "jwt")
            return result, "" if result is not None else "Cannot decode as JWT"

        if name in ("md5", "sha1", "sha256"):
            fn = getattr(hashlib, name)
            return fn(text.encode("utf-8")).hexdigest(), ""

        if name == "reverse":
            return text[::-1], ""

        return None, f"Unknown transform: {name}"

    except Exception as e:
        return None, str(e)


TRANSFORM_LABELS: dict[str, str] = {
    "base64":          "Base64",
    "url_full":        "URL (full)",
    "url_component":   "URL (component)",
    "html":            "HTML Entities",
    "hex":             "Hex",
    "unicode_escape":  "Unicode Escape",
    "gzip":            "Gzip",
    "jwt":             "JWT",
    "md5":             "MD5",
    "sha1":            "SHA-1",
    "sha256":          "SHA-256",
    "reverse":         "Reverse",
}
