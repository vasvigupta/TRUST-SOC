"""
Unit Tests — Canonical Schema & Ground Truth Isolation (Section 5)
===================================================================
Stdlib unittest tests verifying:
1. Canonical Alert Schema validation rules.
2. Ground Truth Isolation:
   CRITICAL RULE: No agent module (Detection, Verification, Scoring, Reporting)
   may import or read `ground_truth` to make a decision.
"""

import os
import ast
import unittest
from pathlib import Path

from src.schemas.alert import create_empty_alert, validate_alert


class TestSchemaAndGroundTruthIsolation(unittest.TestCase):

    def test_valid_alert_schema(self):
        """Verify that a compliant alert passes validate_alert()."""
        alert = create_empty_alert(
            source_file="test_flow.csv",
            row_index=1,
            fields_available={"Protocol": 6, "Destination Port": 80},
            features={"Flow Duration": 120.0},
            ground_truth={"original_label": "BENIGN", "project_class": "Benign", "is_attack": False}
        )
        self.assertTrue(validate_alert(alert))

    def test_schema_rejects_missing_keys(self):
        """Verify validator catches missing top-level blocks."""
        alert = create_empty_alert(
            source_file="test_flow.csv",
            row_index=1,
            fields_available={},
            features={}
        )
        del alert["detection"]
        with self.assertRaises(ValueError):
            validate_alert(alert)

    def test_schema_rejects_invalid_probability(self):
        """Verify validator enforces probability bounds in [0, 1]."""
        alert = create_empty_alert(
            source_file="test_flow.csv",
            row_index=1,
            fields_available={},
            features={}
        )
        alert["detection"]["probability"] = 1.5
        with self.assertRaises(ValueError):
            validate_alert(alert)

    def test_strict_ground_truth_isolation(self):
        """
        CRITICAL TEST:
        Scans all operational agent source files (detection, verification, scoring)
        and asserts that NO agent reads or accesses alert['ground_truth'] or ground_truth
        to compute a verdict or probability.
        """
        agent_dirs = ["detection", "verification", "scoring", "reporting"]
        src_root = Path(__file__).resolve().parents[1] / "src"

        for adir in agent_dirs:
            target_dir = src_root / adir
            if not target_dir.exists():
                continue

            for py_file in target_dir.glob("*.py"):
                if py_file.name.startswith("__"):
                    continue

                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read()

                # Parse AST
                tree = ast.parse(content, filename=str(py_file))

                # Check for subscript access like alert["ground_truth"] or .get("ground_truth")
                for node in ast.walk(tree):
                    if isinstance(node, ast.Subscript):
                        if isinstance(node.slice, ast.Constant) and node.slice.value == "ground_truth":
                            self.fail(
                                f"ISOLATION VIOLATION: File '{py_file.name}' in '{adir}' directly "
                                f"accesses alert['ground_truth']! Operational agents must never read ground truth."
                            )
                    elif isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                            if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "ground_truth":
                                self.fail(
                                    f"ISOLATION VIOLATION: File '{py_file.name}' in '{adir}' calls "
                                    f".get('ground_truth')! Operational agents must never read ground truth."
                                )


if __name__ == "__main__":
    unittest.main()
