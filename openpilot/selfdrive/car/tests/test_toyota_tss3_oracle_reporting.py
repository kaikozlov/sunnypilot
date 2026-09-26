import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from openpilot.selfdrive.car import toyota_tss3_oracle_auto as auto
from openpilot.selfdrive.ui.mici.layouts.settings.tss3_oracle import Tss3OracleBringupPage


STATUS_SCHEMA = "camry-f33-oracle-ui-status-v1"
SUMMARY_SCHEMA = "camry-f33-oracle-ui-bringup-v1"
SUCCESS_VERDICT = "startup_caught_fresh_signer_peer_state_healthy_self_test_pass"


def status_row(**overrides):
  return {
    "schema": STATUS_SCHEMA, "stage": "done", "title": "Bringup complete",
    "detail": "All checks passed.", "progress": 100, "done": True, "error": False,
    **overrides,
  }


def read_ui(rows, returncode=0):
  # Exercise only the subprocess-output reader; do not construct a GUI or launch a backend.
  page = SimpleNamespace(
    _proc=SimpleNamespace(stdout=io.StringIO("".join(json.dumps(row) + "\n" for row in rows)), wait=lambda: returncode),
    _lock=threading.Lock(), _status={}, _last_output="",
  )
  page._snapshot = lambda: dict(page._status)
  page._set_status = lambda value: setattr(page, "_status", dict(value))
  Tss3OracleBringupPage._reader(page)
  return page._status


class TestOracleUiReporting(unittest.TestCase):
  def test_completion_requires_zero_exit(self):
    result = read_ui([status_row()], returncode=2)
    self.assertIs(result["error"], True)
    self.assertIs(result["done"], False)
    self.assertIn("2", result["detail"])

  def test_completion_is_not_displayed_before_process_exit(self):
    page = SimpleNamespace(_lock=threading.Lock(), _status={}, _last_output="")
    page._snapshot = lambda: dict(page._status)
    page._set_status = lambda value: setattr(page, "_status", dict(value))

    def output():
      yield json.dumps(status_row()) + "\n"
      self.assertIsNot(page._status.get("done"), True)

    page._proc = SimpleNamespace(stdout=output(), wait=lambda: 0)
    Tss3OracleBringupPage._reader(page)
    self.assertIs(page._status["done"], True)

  def test_valid_completion(self):
    result = read_ui([status_row()])
    self.assertIs(result["done"], True)
    self.assertIs(result["error"], False)

  def test_exit_without_completion_is_not_success(self):
    result = read_ui([status_row(stage="verifying", done=False, progress=70)])
    self.assertIs(result["error"], True)

  def test_error_is_not_overwritten_by_late_success(self):
    error = status_row(stage="error", done=False, error=True, detail="Original backend failure.", progress=0)
    result = read_ui([error, status_row()])
    self.assertIs(result["error"], True)
    self.assertEqual(result["detail"], error["detail"])

  def test_malformed_status_cannot_report_success(self):
    for overrides in (
      {"progress": "not-a-number"}, {"progress": None}, {"progress": True},
      {"done": "false"}, {"error": "false"}, {"done": True, "error": True},
      {"title": []}, {"stage": "verifying", "done": True},
    ):
      with self.subTest(overrides=overrides):
        result = read_ui([status_row(**overrides)])
        self.assertIs(result["error"], True)
        self.assertIs(result["done"], False)


class TestOracleAutoReporting(unittest.TestCase):
  def run_report(self, summary, *, returncode=0, rows=None):
    # All process, socket, timing and compatibility boundaries are mocked. No ECU I/O.
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      run_dir = root / "run"
      log_path = root / "run.log"
      fallback = root / "trigger.json"
      proc = Mock()
      proc.stdout = io.StringIO("".join(json.dumps(row) + "\n" for row in (rows if rows is not None else [status_row()])))
      proc.wait.return_value = returncode

      def launch(*_args, **_kwargs):
        run_dir.mkdir()
        (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        return proc

      with patch.object(auto, "RUN_ROOT", root), \
           patch.object(auto, "oracle_kit_compatibility", return_value=(True, "")), \
           patch.object(auto, "_warm_worker", Mock(poll=Mock(return_value=None))), \
           patch.object(auto, "WARM_WORKER_PATH", Mock(is_socket=Mock(return_value=True))), \
           patch.object(auto, "_allocate_run_path", return_value=(run_dir, log_path, fallback)), \
           patch.object(auto.subprocess, "Popen", side_effect=launch), \
           patch.object(auto, "_write_status") as write_status, \
           patch.object(auto, "_record_trigger_timing", return_value={}), \
           patch.object(auto.cloudlog, "warning"):
        success = auto._run_bringup(root / "marker", {"pandad_wrapper_pid": 123}, catch_received_ns=1)
      return success, write_status.call_args

  def test_current_backend_summary_is_recognized(self):
    success, call = self.run_report({"schema": SUMMARY_SCHEMA, "verdict": SUCCESS_VERDICT})
    self.assertTrue(success)
    self.assertEqual(call.args[0], "complete")

  def test_malformed_summary_is_an_error_not_a_daemon_crash(self):
    for summary in ([], None, 7, "not an object"):
      with self.subTest(summary=summary):
        success, call = self.run_report(summary)
        self.assertFalse(success)
        self.assertEqual(call.args[0], "error")

  def test_wrong_contract_does_not_reuse_success_detail(self):
    for summary in (
      {"schema": SUMMARY_SCHEMA, "verdict": "unknown"},
      {"schema": "different-schema", "verdict": SUCCESS_VERDICT},
      {"verdict": SUCCESS_VERDICT},
    ):
      with self.subTest(summary=summary):
        success, call = self.run_report(summary)
        self.assertFalse(success)
        self.assertNotEqual(call.args[1], "All checks passed.")

  def test_nonzero_exit_cannot_reuse_success_detail(self):
    success, call = self.run_report({"schema": SUMMARY_SCHEMA, "verdict": SUCCESS_VERDICT}, returncode=2)
    self.assertFalse(success)
    self.assertNotEqual(call.args[1], "All checks passed.")

  def test_error_is_not_overwritten_by_late_success(self):
    row = status_row(stage="error", error=True, done=False, progress=0, detail="Original failure.")
    success, call = self.run_report(
      {"schema": SUMMARY_SCHEMA, "verdict": SUCCESS_VERDICT}, rows=[row, status_row()],
    )
    self.assertFalse(success)
    self.assertEqual(call.args[1], "Original failure.")

  def test_no_completion_status_is_not_success(self):
    success, call = self.run_report({"schema": SUMMARY_SCHEMA, "verdict": SUCCESS_VERDICT}, rows=[])
    self.assertFalse(success)
    self.assertIn("without a completion status", call.args[1])

  def test_original_backend_failure_is_preserved(self):
    row = status_row(stage="error", error=True, done=False, progress=0, detail="Original failure.")
    success, call = self.run_report({}, returncode=2, rows=[row])
    self.assertFalse(success)
    self.assertEqual(call.args[1], "Original failure.")


class TestOracleRearmReporting(unittest.TestCase):
  def test_worker_readiness_does_not_erase_previous_result(self):
    with patch.object(auto, "_stop_warm_worker"), \
         patch.object(auto, "_exit_requested", False), \
         patch.object(auto, "_warm_worker", None), \
         patch.object(auto, "oracle_kit_compatibility", return_value=(True, "")), \
         patch.object(auto, "WARM_WORKER_PATH", Mock(is_socket=Mock(return_value=True))), \
         patch.object(auto.subprocess, "Popen", return_value=Mock(poll=Mock(return_value=None))), \
         patch.object(auto, "_write_status") as write_status:
      self.assertTrue(auto._start_warm_worker(publish_ready_status=False))
      write_status.assert_not_called()
      self.assertTrue(auto._start_warm_worker())
      self.assertEqual(write_status.call_args.args[0], "armed")
