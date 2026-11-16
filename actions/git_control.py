"""Restricted local Git operations for AccessPolicy-authorized repositories."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable

from core.access_policy import AccessPolicy, DEFAULT_CONFIG_PATH

MAX_OUTPUT_CHARS = 20_000
COMMAND_TIMEOUT_SECONDS = 30
REMOTE_ACTIONS = frozenset(
    {
        "push",
        "pr",
        "pull_request",
        "merge",
        "fetch",
        "pull",
        "checkout",
        "reset",
        "stash",
        "rebase",
    }
)


def _bounded(text: str) -> str:
    text = text.strip()
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[: MAX_OUTPUT_CHARS - 24] + "\n[output truncated]"


def git_control(
    parameters: dict,
    response=None,
    player=None,
    session_memory=None,
    *,
    config_path: str | Path = DEFAULT_CONFIG_PATH,
    access_policy: AccessPolicy | None = None,
    runner: Callable = subprocess.run,
) -> str:
    """Run only status, diff, or commit in an explicitly authorized local repo."""
    values = parameters or {}
    action = str(values.get("action", "")).strip().lower()

    if action in REMOTE_ACTIONS:
        return (
            f"Denied: '{action}' is a remote or destructive Git operation. "
            "This tool is local-only and never pushes, opens PRs, merges, or changes branches."
        )
    if action not in {"status", "diff", "commit"}:
        return "Unsupported Git action. Allowed local actions: status, diff, commit."

    project_path = str(values.get("project_path", "")).strip()
    if not project_path:
        return "project_path is required."

    policy = access_policy or AccessPolicy.load(config_path)
    permission = "commit" if action == "commit" else "read"
    decision = policy.check(project_path, permission)
    if not decision.allowed:
        return f"Access denied: {decision.reason}"

    if action == "commit":
        message = str(values.get("message", "")).strip()
        if not message:
            return "A non-empty commit message is required."
        command = ["git", "-C", str(decision.requested_path), "commit", "-m", message]
    elif action == "diff":
        command = [
            "git",
            "-C",
            str(decision.requested_path),
            "diff",
            "--no-ext-diff",
            "--no-textconv",
        ]
    else:
        command = [
            "git",
            "-C",
            str(decision.requested_path),
            "status",
            "--short",
            "--branch",
        ]

    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return f"Local git {action} timed out after {COMMAND_TIMEOUT_SECONDS}s."
    except FileNotFoundError:
        return "Git is not installed or is not available on PATH."
    except OSError as exc:
        return f"Could not run local git {action}: {exc}"

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    if completed.returncode != 0:
        return _bounded(f"Local git {action} failed: {output or 'unknown git error'}")
    if output:
        return _bounded(output)
    return "Working tree clean." if action == "status" else f"Local git {action} completed."


# ── Tool declaration (auto-discovered by core/action_loader.py) ──────────────
TOOL = {
    "name": "git_control",
    "description": (
        "Runs authorized local-only Git status, diff, or commit. "
        "Never push, open PRs, merge, fetch, pull, checkout, reset, stash, or rebase."
    ),
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "action": {
                "type": "STRING",
                "description": "status | diff | commit",
            },
            "project_path": {
                "type": "STRING",
                "description": "Authorized local repository path",
            },
            "message": {
                "type": "STRING",
                "description": "Required explicit commit message",
            },
        },
        "required": ["action", "project_path"],
    },
    "handler": git_control,
}
