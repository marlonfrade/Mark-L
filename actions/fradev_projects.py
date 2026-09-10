"""Safe project inventory and local status for configured FraDev projects."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable

from core.access_policy import AccessPolicy, DEFAULT_CONFIG_PATH, PERMISSIONS

MAX_OUTPUT_CHARS = 12_000
COMMAND_TIMEOUT_SECONDS = 15


def _bounded(text: str) -> str:
    text = text.strip()
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[: MAX_OUTPUT_CHARS - 24] + "\n[output truncated]"


def _load_projects(config_path: str | Path) -> list[dict]:
    data = json.loads(Path(config_path).expanduser().read_text(encoding="utf-8"))
    projects = data.get("projects", [])
    if not isinstance(projects, list):
        raise ValueError("'projects' must be a list")
    return projects


def fradev_projects(
    parameters: dict,
    response=None,
    player=None,
    session_memory=None,
    *,
    config_path: str | Path = DEFAULT_CONFIG_PATH,
    access_policy: AccessPolicy | None = None,
    runner: Callable = subprocess.run,
) -> str:
    """List configured grants or show local git status for one authorized project."""
    values = parameters or {}
    action = str(values.get("action", "list")).strip().lower()
    policy = access_policy or AccessPolicy.load(config_path)

    if action == "list":
        try:
            projects = _load_projects(config_path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            return f"Could not load FraDev project configuration: {exc}"
        if not projects:
            return "No FraDev projects are configured."

        lines = []
        for project in projects:
            if not isinstance(project, dict):
                continue
            raw_path = project.get("path")
            permissions = project.get("permissions", {})
            if not isinstance(raw_path, str) or not isinstance(permissions, dict):
                continue
            resolved = Path(raw_path).expanduser().resolve(strict=False)
            grants = ", ".join(
                f"{name}={str(permissions.get(name, False)).lower()}"
                for name in sorted(PERMISSIONS)
            )
            lines.append(f"{resolved} — {grants}")
        return _bounded("\n".join(lines)) if lines else "No valid FraDev projects are configured."

    if action != "status":
        return "Unsupported FraDev project action. Use list or status."

    project_path = str(values.get("project_path", "")).strip()
    if not project_path:
        return "project_path is required for FraDev project status."
    decision = policy.check(project_path, "read")
    if not decision.allowed:
        return f"Access denied: {decision.reason}"

    try:
        completed = runner(
            ["git", "-C", str(decision.requested_path), "status", "--short", "--branch"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return f"Git status timed out after {COMMAND_TIMEOUT_SECONDS}s."
    except FileNotFoundError:
        return "Git is not installed or is not available on PATH."
    except OSError as exc:
        return f"Could not run local git status: {exc}"

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    if completed.returncode != 0:
        return _bounded(f"Local git status failed: {output or 'unknown git error'}")
    return _bounded(output or "Working tree clean.")
