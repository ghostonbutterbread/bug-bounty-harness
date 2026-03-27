"""XSS bypass modules — technique-specific payload generators and detectors."""

from .encoding import EncodingBypass, EncodingFinding
from .attribute_injection import AttributeInjection, AttributeFinding
from .dangling_markup import DanglingMarkup, DanglingFinding
from .csp_bypass import CSPBypass, CSPFinding
from .script_context import ScriptContext, ScriptFinding
from .postmessage import PostMessageBypass, PostMessageFinding
from .file_upload import FileUploadXSS, FileUploadFinding
from .polyglot import Polyglot, PolyglotFinding

__all__ = [
    "EncodingBypass", "EncodingFinding",
    "AttributeInjection", "AttributeFinding",
    "DanglingMarkup", "DanglingFinding",
    "CSPBypass", "CSPFinding",
    "ScriptContext", "ScriptFinding",
    "PostMessageBypass", "PostMessageFinding",
    "FileUploadXSS", "FileUploadFinding",
    "Polyglot", "PolyglotFinding",
]
