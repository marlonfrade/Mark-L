"""Allowlisted interface to the canonical Project-of-Projects scripts."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Callable

from core.access_policy import DEFAULT_CONFIG_PATH

MAX_OUTPUT_CHARS = 20_000
COMMAND_TIMEOUT_SECONDS = 60
POP_SCRIPTS = {
    "status": "pop_status.py",
    "validate": "pop_validate.py",
    "task": "pop_task.py",
    "move": "pop_move.py",
}
POP_STAGES = frozenset(
    {
        "001_initial_task",
        "002_planning",
        "003_human_approval",
        "004_processing",
        "005_verifying",
        "006_done",
    }
)


def _bounded(text: str) -> str:
    text = text.strip()
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[: MAX_OUTPUT_CHARS - 24] + "\n[output truncated]"


def _configured_pop_root(config_path: str | Path) -> Path:
    data = json.loads(Path(config_path).expanduser().read_text(encoding="utf-8"))
    raw_root = data.get("pop_root")
    if not isinstance(raw_root, str) or not raw_root.strip():
        raise ValueError("'pop_root' must be configured as a non-empty path")
    return Path(raw_root).expanduser().resolve(strict=False)


def _required(values: dict, *names: str) -> tuple[list[str], str | None]:
    result = []
    for name in names:
        value = str(values.get(name, "")).strip()
        if not value:
            return [], f"'{name}' is required for this PoP action."
        result.append(value)
    return result, None


def _build_arguments(action: str, values: dict) -> tuple[list[str], str | None]:
    if action == "status":
        project = str(values.get("project", "")).strip()
        return (["--project", project] if project else []), None

    if action == "validate":
        return (["--standalone"] if values.get("standalone") is True else []), None

    if action == "task":
        required, error = _required(values, "project", "task_id")
        if error:
            return [], error
        args = required
        title = str(values.get("title", "")).strip()
        if title:
            args.extend(["--title", title])
        return args, None

    required, error = _required(values, "task_id", "stage")
    if error:
        return [], error
    task_id, stage = required
    if stage not in POP_STAGES:
        return [], f"Unsupported PoP stage '{stage}'. Allowed stages: {', '.join(sorted(POP_STAGES))}."
    args = [task_id, stage]

    for field, flag in (("reason", "--reason"), ("by", "--by")):
        value = str(values.get(field, "")).strip()
        if value:
            args.extend([flag, value])

    contexts = values.get("context", [])
    if isinstance(contexts, str):
        contexts = [contexts]
    if not isinstance(contexts, list) or any(not isinstance(item, str) for item in contexts):
        return [], "'context' must be a string or list of strings."
    for context in contexts:
        if context.strip():
            args.extend(["--context", context.strip()])

    if "test_seconds" in values:
        try:
            test_seconds = float(values["test_seconds"])
        except (TypeError, ValueError):
            return [], "'test_seconds' must be a non-negative number."
        if test_seconds < 0:
            return [], "'test_seconds' must be a non-negative number."
        args.extend(["--test-seconds", str(test_seconds)])
    if values.get("force") is True:
        args.append("--force")
    return args, None


def pop_control(
    parameters: dict,
    response=None,
    player=None,
    session_memory=None,
    *,
    config_path: str | Path = DEFAULT_CONFIG_PATH,
    pop_root: str | Path | None = None,
    runner: Callable = subprocess.run,
) -> str:
    """Execute one explicitly allowlisted PoP operation with structured arguments."""
    values = parameters or {}
    action = str(values.get("action", "")).strip().lower()
    if action not in POP_SCRIPTS:
        return "Unsupported PoP action. Allowed actions: status, validate, task, move."

    try:
        root = (
            Path(pop_root).expanduser().resolve(strict=False)
            if pop_root is not None
            else _configured_pop_root(config_path)
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return f"PoP configuration error: {exc}"

    script = root / "scripts" / POP_SCRIPTS[action]
    if not script.is_file():
        return f"Canonical PoP script not found: {script}"

    args, error = _build_arguments(action, values)
    if error:
        return error
    command = [sys.executable, str(script), *args]

    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=COMMAND_TIMEOUT_SECONDS,
            cwd=str(root),
        )
    except subprocess.TimeoutExpired:
        return f"PoP {action} timed out after {COMMAND_TIMEOUT_SECONDS}s."
    except OSError as exc:
        return f"Could not run PoP {action}: {exc}"

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    if completed.returncode != 0:
        return _bounded(f"PoP {action} failed: {output or 'unknown script error'}")
    return _bounded(output or f"PoP {action} completed.")


# ── Tool declaration (auto-discovered by core/action_loader.py) ──────────────
TOOL = {
    "name": "pop_control",
    "description": (
        "Runs allowlisted Project-of-Projects status, validation, task, or move "
        "operations through the canonical scripts. Never invents free-form shell commands."
    ),
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "action": {
                "type": "STRING",
                "description": "status | validate | task | move",
            },
            "project": {
                "type": "STRING",
                "description": "PoP category/project",
            },
            "task_id": {
                "type": "STRING",
                "description": "PoP task identifier",
            },
            "title": {
                "type": "STRING",
                "description": "Task title",
            },
            "stage": {
                "type": "STRING",
                "description": "Canonical numbered PoP stage",
            },
            "reason": {
                "type": "STRING",
                "description": "Move reason",
            },
            "context": {
                "type": "ARRAY",
                "items": {"type": "STRING"},
                "description": "Move context entries",
            },
            "test_seconds": {
                "type": "NUMBER",
                "description": "Verified test duration",
            },
            "by": {
                "type": "STRING",
                "description": "Actor for a move",
            },
            "force": {
                "type": "BOOLEAN",
                "description": "Explicitly force a PoP move",
            },
            "standalone": {
                "type": "BOOLEAN",
                "description": "Run standalone validation",
            },
        },
        "required": ["action"],
    },
    "handler": pop_control,
}
