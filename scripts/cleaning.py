"""Message-level cleaning shared by the build script and the tests."""
import re
_PLACEHOLDER = re.compile(r"^\s*(?:null|none|nan|n/?a|na|nil|undefined|\[?empty\]?|-+|\.+)?\s*$", re.I)

def is_placeholder(text) -> bool:
    """True for missing / placeholder / destroyed text that is not a real SMS:
    empty, 'null', 'None', 'NaN', 'N/A', ... or text that is only question marks (e.g. '??????' left by an encoding loss).
    Emoticons such as ':)' are real (if tiny) SMS and are kept."""
    if text is None: return True
    t = str(text)
    if _PLACEHOLDER.match(t): return True
    return bool(re.fullmatch(r"[\s?]+", t))
