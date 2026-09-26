import json
import tempfile
import unittest
from pathlib import Path

from openpilot.selfdrive.car.toyota_tss3_oracle_kit import EXPECTED_ORACLE_TARGET, oracle_kit_compatibility


class TestToyotaTss3OracleKit(unittest.TestCase):
  def make_tool(self, root: Path, target: str) -> Path:
    tool = root / "tss3-unified-signer"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    bundle = root / "bundle"
    bundle.mkdir()
    (bundle / "unified.json").write_text(json.dumps({"target": {"name": target}}), encoding="utf-8")
    return tool

  def test_accepts_exact_f33(self):
    with tempfile.TemporaryDirectory() as td:
      tool = self.make_tool(Path(td), EXPECTED_ORACLE_TARGET)
      self.assertEqual(oracle_kit_compatibility(tool), (True, ""))

  def test_rejects_wrong_exact_target(self):
    with tempfile.TemporaryDirectory() as td:
      tool = self.make_tool(Path(td), "corolla-8965F1208000")
      compatible, detail = oracle_kit_compatibility(tool)
      self.assertFalse(compatible)
      self.assertEqual(detail, f"wrong oracle kit: corolla-8965F1208000; need {EXPECTED_ORACLE_TARGET}")

  def test_rejects_unreadable_metadata_without_crashing(self):
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      tool = self.make_tool(root, EXPECTED_ORACLE_TARGET)
      for data in (b"{", b'\xff{"target":{}}'):
        with self.subTest(data=data):
          (root / "bundle/unified.json").write_bytes(data)
          compatible, detail = oracle_kit_compatibility(tool)
          self.assertFalse(compatible)
          self.assertTrue(detail.startswith("oracle kit metadata invalid:"))

  def test_rejects_missing_metadata(self):
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      tool = root / "tss3-unified-signer"
      tool.write_text("#!/bin/sh\n", encoding="utf-8")
      tool.chmod(0o755)
      compatible, detail = oracle_kit_compatibility(tool)
      self.assertFalse(compatible)
      self.assertTrue(detail.startswith("oracle kit metadata invalid:"))
