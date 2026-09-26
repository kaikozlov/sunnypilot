from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from openpilot.selfdrive.car.toyota_tss3_oracle_kit import oracle_kit_compatibility
from openpilot.selfdrive.car.toyota_tss3_oracle_status import parse_status, process_status
from openpilot.selfdrive.ui.ui_state import device
from openpilot.selfdrive.ui.mici.widgets.button import BigButton, GreyBigButton
from openpilot.system.ui.widgets.scroller import NavScroller

TOOL_PATH = Path(os.getenv("TSS3_ORACLE_TOOL", "/data/tss3-oracle/tss3-unified-signer"))
RUN_ROOT = Path(os.getenv("TSS3_ORACLE_RUN_ROOT", "/data/tss3-oracle-runs"))

_oracle_bringup_active = False

STAGE_LABELS = {
  "arming": "starting",
  "armed": "waiting for POWER",
  "programming": "installing RAM oracle",
  "waiting_ready": "waiting for READY / Park",
  "verifying": "checking peer health + signer",
  "finishing": "waiting for backend exit",
  "done": "complete",
  "error": "failed",
}


def tool_available() -> bool:
  return TOOL_PATH.is_file() and os.access(TOOL_PATH, os.X_OK)


def tool_compatible() -> bool:
  return oracle_kit_compatibility(TOOL_PATH)[0]


def oracle_bringup_active() -> bool:
  return _oracle_bringup_active


class Tss3OracleBringupPage(NavScroller):
  """Native comma-four page for the exact-F33 RAM-oracle startup flow."""

  def __init__(self):
    super().__init__()
    self._lock = threading.Lock()
    self._status: dict[str, Any] = {
      "stage": "arming",
      "title": "Arming oracle bringup",
      "detail": "Preparing the startup catcher.",
      "progress": 0,
      "done": False,
      "error": False,
    }
    self._last_output = ""
    self._proc: subprocess.Popen[str] | None = None
    self._run_dir: Path | None = None

    self._status_card = GreyBigButton("oracle bringup", "Preparing the startup catcher.")
    self._progress_card = GreyBigButton("progress", "0%\nstarting")
    self._contract_card = GreyBigButton(
      "RAM-only startup path",
      "No EPS flash writes.\nNo Brake/FRC resets on a healthy run.\nKeep the vehicle in Park.",
    )
    self._action_button = BigButton("cancel bringup", "swipe down also works")
    self._action_button.set_click_callback(self.dismiss)

    self._scroller.add_widgets([
      self._status_card,
      self._progress_card,
      self._contract_card,
      self._action_button,
    ])

    self._start_worker()

  def show_event(self):
    global _oracle_bringup_active
    super().show_event()
    _oracle_bringup_active = True
    device.set_override_interactive_timeout(300)

  def hide_event(self):
    global _oracle_bringup_active
    _oracle_bringup_active = False
    device.set_override_interactive_timeout(None)

    status = self._snapshot()
    proc = self._proc
    if proc is not None and proc.poll() is None and not status.get("done") and not status.get("error"):
      try:
        os.killpg(proc.pid, signal.SIGTERM)
      except ProcessLookupError:
        pass

    super().hide_event()

  def _snapshot(self) -> dict[str, Any]:
    with self._lock:
      return dict(self._status)

  def _set_status(self, status: dict[str, Any]) -> None:
    with self._lock:
      self._status = dict(status)

  def _start_worker(self) -> None:
    compatible, detail = oracle_kit_compatibility(TOOL_PATH)
    if not compatible:
      if detail.startswith("wrong oracle kit:"):
        title = "Wrong oracle kit"
      elif detail.startswith("oracle kit metadata invalid:"):
        title = "Oracle kit invalid"
      else:
        title = "Oracle tool unavailable"
      self._set_status({
        "stage": "error",
        "title": title,
        "detail": detail,
        "progress": 0,
        "done": False,
        "error": True,
      })
      return

    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime())
    self._run_dir = RUN_ROOT / f"{stamp}-{os.getpid()}"
    cmd = [str(TOOL_PATH), "--topology", "camry-post-repin", "oracle-ui-bringup", str(self._run_dir)]

    try:
      self._proc = subprocess.Popen(
        cmd,
        cwd=str(TOOL_PATH.parent),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        start_new_session=True,
      )
    except OSError as exc:
      self._set_status({
        "stage": "error",
        "title": "Could not start oracle bringup",
        "detail": f"{type(exc).__name__}: {exc}",
        "progress": 0,
        "done": False,
        "error": True,
      })
      return

    threading.Thread(target=self._reader, name="tss3_oracle_ui", daemon=True).start()

  def _reader(self) -> None:
    assert self._proc is not None and self._proc.stdout is not None
    latest_status: dict[str, Any] | None = None
    for raw in self._proc.stdout:
      line = raw.strip()
      if not line:
        continue
      status = parse_status(line)
      if status is None:
        with self._lock:
          self._last_output = line
        continue
      if latest_status is None or not latest_status.get("error"):
        latest_status = status
        if status["done"]:
          self._set_status({
            **status, "stage": "finishing", "title": "Finalizing bringup",
            "detail": "Waiting for the backend to finish.", "done": False,
          })
        else:
          self._set_status(status)

    rc = self._proc.wait()
    with self._lock:
      last_output = self._last_output
    self._set_status(process_status(latest_status, rc, last_output))

  def _update_state(self):
    super()._update_state()
    status = self._snapshot()
    stage = str(status.get("stage", "arming"))
    progress = max(0, min(100, int(status.get("progress", 0))))

    self._status_card.set_text(str(status.get("title", "Oracle bringup")))
    self._status_card.set_value(str(status.get("detail", "")))
    self._progress_card.set_value(f"{progress}%\n{STAGE_LABELS.get(stage, stage)}")

    if status.get("done"):
      self._action_button.set_text("close")
      self._action_button.set_value("bringup passed")
    elif status.get("error"):
      self._action_button.set_text("close")
      self._action_button.set_value("bringup failed")
    else:
      self._action_button.set_text("cancel bringup")
      self._action_button.set_value("swipe down also works")
