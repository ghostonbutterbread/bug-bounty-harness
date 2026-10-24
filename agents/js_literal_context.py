"""Conservative inline-JavaScript literal state at a reflection offset.

This is not a JavaScript parser. Unknown template-expression nesting is treated
as code, never as proof that a reflection is inert string data.
"""


def literal_at(script: str, offset: int) -> str:
    """Return an unambiguous open quote ('/"/`) or an empty string."""
    quote = ""
    comment = ""
    escaped = False
    index = 0
    while index < offset:
        char = script[index]
        next_char = script[index + 1] if index + 1 < offset else ""
        if comment == "line":
            if char in "\r\n":
                comment = ""
        elif comment == "block":
            if char == "*" and next_char == "/":
                comment = ""
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            elif quote == "`" and char == "$" and next_char == "{":
                # Expression contents are code; without parsing nested braces
                # we cannot safely assert any later quote remains inert.
                return ""
        elif char == "/" and next_char in ("/", "*"):
            comment = "line" if next_char == "/" else "block"
            index += 1
        elif char in ("'", '"', "`"):
            quote = char
        index += 1
    return "" if comment else quote
