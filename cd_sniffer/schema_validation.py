from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any


SCHEMA_ENV_VAR = "CDSNIFFER_VALIDATE_SCHEMAS"

SCHEMA_FILES = {
    "capture": "cdsniffer-output.schema.json",
    "correlation": "cdsniffer-correlation.schema.json",
    "archive": "cdsniffer-archive.schema.json",
    "archive-index": "cdsniffer-archive-index.schema.json",
    "archive-correlation": "cdsniffer-archive-correlation.schema.json",
}


def schema_validation_requested(explicit: bool = False) -> bool:
    value = os.environ.get(SCHEMA_ENV_VAR, "")
    return explicit or value.lower() in {"1", "true", "yes", "on"}


def validate_payload_schema(payload: dict[str, Any], schema_name: str) -> None:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover - exercised only without optional dependency
        raise RuntimeError("Schema validation requires `pip install cdsniffer[schema]` or `pip install jsonschema`.") from exc

    schema = load_schema(schema_name)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.absolute_path))
    if not errors:
        return
    first = errors[0]
    path = "$" + "".join(f"[{part!r}]" if isinstance(part, str) else f"[{part}]" for part in first.absolute_path)
    raise ValueError(f"{schema_name} schema validation failed at {path}: {first.message}")


@lru_cache(maxsize=None)
def load_schema(schema_name: str) -> dict[str, Any]:
    file_name = SCHEMA_FILES.get(schema_name)
    if file_name is None:
        raise ValueError(f"Unknown schema name: {schema_name}")
    path = Path(__file__).resolve().parents[1] / "schemas" / file_name
    if not path.exists():
        raise FileNotFoundError(f"Schema file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))
