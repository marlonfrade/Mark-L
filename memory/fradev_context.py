"""Load redacted local FraDev Markdown context for model prompts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "fradev.local.json"
DEFAULT_MAX_CHARS = 24_000
TRUNCATION_MARKER = "\n…"

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_ASSIGNMENT_RE = re.compile(
    r"(?im)^(\s*(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"token|password|passwd|pwd|secret)\s*[:=]\s*).*$"
)
_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:sk_(?:live|test)_[A-Za-z0-9_-]{12,}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|AIza[A-Za-z0-9_-]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,})(?![A-Za-z0-9])"
)


def load_fradev_context(config_path: str | Path = DEFAULT_CONFIG_PATH) -> str:
    """Return labeled, redacted context or an empty string when unavailable."""
    config = _load_config(Path(config_path).expanduser())
    if config is None:
        return ""

    raw_sources = config.get("context_sources", [])
    if not isinstance(raw_sources, list):
        return ""
    max_chars = config.get("context_max_chars", DEFAULT_MAX_CHARS)
    if not isinstance(max_chars, int) or isinstance(max_chars, bool) or max_chars <= 0:
        max_chars = DEFAULT_MAX_CHARS

    sections: list[str] = []
    for source in raw_sources:
        parsed = _parse_source(source)
        if parsed is None:
            continue
        label, path = parsed
        try:
            if not path.is_file():
                continue
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        sections.append(f"### {label}\n{redact_secrets(content).strip()}")

    context = "\n\n".join(section for section in sections if section.strip())
    if len(context) <= max_chars:
        return context
    if max_chars <= len(TRUNCATION_MARKER):
        return "…"[:max_chars]
    return context[: max_chars - len(TRUNCATION_MARKER)].rstrip() + TRUNCATION_MARKER


def redact_secrets(text: str) -> str:
    redacted = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    redacted = _ASSIGNMENT_RE.sub(r"\1[REDACTED]", redacted)
    return _TOKEN_RE.sub("[REDACTED]", redacted)


def _load_config(path: Path) -> dict[str, Any] | None:
    try:
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def _parse_source(source: Any) -> tuple[str, Path] | None:
    if isinstance(source, str) and source.strip():
        path = Path(source).expanduser()
        return path.name, path
    if isinstance(source, dict):
        raw_path = source.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            return None
        path = Path(raw_path).expanduser()
        label = source.get("label", path.name)
        if not isinstance(label, str) or not label.strip():
            label = path.name
        return label.strip(), path
    return None
