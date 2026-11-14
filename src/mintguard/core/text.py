"""Sanitizing of semi-trusted text before it reaches the user.

The strings MintGuard reads come from the system: a process name can
carry ANSI escape sequences (any user chooses their own name) and a
package name can be thousands of characters long. They end up in a
plain-text report the user may print in a terminal and in a Markdown
widget, so control characters are replaced and the length is capped.
"""

from __future__ import annotations

MAX_ITEM_LENGTH = 120
_CONTROL_PLACEHOLDER = "␦"


def sanitize(text: str, limit: int = MAX_ITEM_LENGTH) -> str:
    """Replace control characters and cut the text to `limit` characters."""
    cleaned = "".join(ch if ch.isprintable() else _CONTROL_PLACEHOLDER for ch in text)
    if len(cleaned) > limit:
        cleaned = cleaned[:limit].rstrip() + "…"
    return cleaned
