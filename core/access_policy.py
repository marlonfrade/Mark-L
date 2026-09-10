"""Deny-by-default project access policy for local FraDev tools."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PERMISSIONS = frozenset({"read", "write", "test", "commit", "remote"})
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "fradev.local.json"


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    permission: str
    requested_path: Path
    project_path: Path | None
    reason: str


@dataclass(frozen=True)
class _ProjectGrant:
    path: Path
    permissions: dict[str, bool]


class AccessDeniedError(PermissionError):
    """Raised when a caller requires access that the policy does not grant."""

    def __init__(self, decision: AccessDecision):
        super().__init__(decision.reason)
        self.decision = decision


class AccessPolicy:
    """Resolve filesystem requests against explicitly configured project grants."""

    def __init__(
        self,
        projects: tuple[_ProjectGrant, ...] = (),
        config_error: str | None = None,
    ):
        self._projects = projects
        self._config_error = config_error

    @classmethod
    def load(cls, config_path: str | Path = DEFAULT_CONFIG_PATH) -> "AccessPolicy":
        path = Path(config_path).expanduser()
        if not path.is_file():
            return cls(config_error=f"FraDev config not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            projects_data = data.get("projects", [])
            if not isinstance(projects_data, list):
                raise ValueError("'projects' must be a list")

            projects: list[_ProjectGrant] = []
            for index, item in enumerate(projects_data):
                projects.append(_parse_project(item, index))
            return cls(tuple(projects))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            return cls(config_error=f"Invalid FraDev config {path}: {exc}")

    def check(self, path: str | Path, permission: str) -> AccessDecision:
        requested = Path(path).expanduser().resolve(strict=False)
        if permission not in PERMISSIONS:
            return AccessDecision(
                False,
                permission,
                requested,
                None,
                f"Unknown permission '{permission}'; expected one of {sorted(PERMISSIONS)}",
            )
        if self._config_error:
            return AccessDecision(False, permission, requested, None, self._config_error)

        matches = [
            project
            for project in self._projects
            if _is_relative_to(requested, project.path)
        ]
        if not matches:
            return AccessDecision(
                False,
                permission,
                requested,
                None,
                f"Resolved path {requested} is outside configured projects",
            )

        project = max(matches, key=lambda grant: len(grant.path.parts))
        allowed = project.permissions.get(permission, False)
        reason = (
            f"Permission '{permission}' granted for project {project.path}"
            if allowed
            else f"Permission '{permission}' denied for project {project.path}"
        )
        return AccessDecision(allowed, permission, requested, project.path, reason)

    def is_allowed(self, path: str | Path, permission: str) -> bool:
        return self.check(path, permission).allowed

    def require(self, path: str | Path, permission: str) -> AccessDecision:
        decision = self.check(path, permission)
        if not decision.allowed:
            raise AccessDeniedError(decision)
        return decision


def _parse_project(item: Any, index: int) -> _ProjectGrant:
    if not isinstance(item, dict):
        raise ValueError(f"projects[{index}] must be an object")
    raw_path = item.get("path")
    raw_permissions = item.get("permissions", {})
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError(f"projects[{index}].path must be a non-empty string")
    if not isinstance(raw_permissions, dict):
        raise ValueError(f"projects[{index}].permissions must be an object")

    permissions: dict[str, bool] = {}
    for name in PERMISSIONS:
        value = raw_permissions.get(name, False)
        if not isinstance(value, bool):
            raise ValueError(f"projects[{index}].permissions.{name} must be boolean")
        permissions[name] = value

    return _ProjectGrant(
        Path(raw_path).expanduser().resolve(strict=False),
        permissions,
    )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
