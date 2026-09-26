"""Host-only parsing and display of bring-up results; no vehicle or process control."""
from __future__ import annotations

import json
from typing import Any

STATUS_SCHEMA = "camry-f33-oracle-ui-status-v1"
SUMMARY_SCHEMA = "camry-f33-oracle-ui-bringup-v1"
SUCCESS_VERDICT = "startup_caught_fresh_signer_peer_state_healthy_self_test_pass"


def parse_status(line: str) -> dict[str, Any] | None:
  try:
    row = json.loads(line)
  except json.JSONDecodeError:
    return None
  if not isinstance(row, dict) or row.get("schema") != STATUS_SCHEMA:
    return None
  if not all(isinstance(row.get(key), str) for key in ("stage", "title", "detail")):
    return None
  if type(row.get("progress")) is not int or not 0 <= row["progress"] <= 100:
    return None
  if type(row.get("done")) is not bool or type(row.get("error")) is not bool:
    return None
  if row["done"] != (row["stage"] == "done") or row["error"] != (row["stage"] == "error"):
    return None
  return row


def process_status(status: dict[str, Any] | None, returncode: int, last_output: str = "") -> dict[str, Any]:
  """An emitted completion does not override a later process failure."""
  if status is not None and status.get("error") is True:
    return status
  if returncode == 0 and status is not None and status.get("done") is True:
    return status
  detail = f"Backend exited with status {returncode}." if returncode != 0 else "Backend exited without a completion status."
  if last_output:
    detail += f" Last output: {last_output}"
  return {
    "schema": STATUS_SCHEMA, "stage": "error", "title": "Oracle bringup stopped",
    "detail": detail, "progress": 0, "done": False, "error": True,
  }
