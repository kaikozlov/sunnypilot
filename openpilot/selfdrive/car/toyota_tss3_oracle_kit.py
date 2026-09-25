from __future__ import annotations

import json
import os
from pathlib import Path

EXPECTED_ORACLE_TARGET = "camry-8965F3307000"


def oracle_kit_compatibility(tool_path: Path) -> tuple[bool, str]:
  if not tool_path.is_file() or not os.access(tool_path, os.X_OK):
    return False, f"oracle tool unavailable: {tool_path}"

  meta_path = tool_path.parent / "bundle" / "unified.json"
  try:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    target = meta["target"]["name"]
  except (FileNotFoundError, OSError, json.JSONDecodeError, KeyError, TypeError):
    return False, f"oracle kit metadata invalid: {meta_path}"

  if target != EXPECTED_ORACLE_TARGET:
    return False, f"wrong oracle kit: {target}; need {EXPECTED_ORACLE_TARGET}"
  return True, ""
