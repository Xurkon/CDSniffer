from __future__ import annotations

from pathlib import Path


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def project_logs_dir() -> Path:
    return project_root() / "logs"


def resolve_project_path(value: str | Path, *, base_dir: Path | None = None) -> Path:
    path = Path(str(value).strip())
    if path.is_absolute():
        return path
    return (base_dir or project_root()) / path
