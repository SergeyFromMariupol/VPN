"""Portfolio command and rollback failures expose fixed codes, never child output."""

import importlib.util
import io
import ast
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "portfolio_failure_install", ROOT / "bundle/portfolio/install.py")
MODULE = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {"grp": types.ModuleType("grp"),
                              "pwd": types.ModuleType("pwd")}):
    SPEC.loader.exec_module(MODULE)
ERROR_SPEC = importlib.util.spec_from_file_location(
    "portfolio_failure_errors", ROOT / "tools/errors.py")
ERRORS = importlib.util.module_from_spec(ERROR_SPEC)
ERROR_SPEC.loader.exec_module(ERRORS)


class PortfolioFailureReporting(unittest.TestCase):
    def render(self, error):
        output = io.StringIO()
        MODULE.report_failure(error, output)
        return output.getvalue()

    def test_command_failure_identifies_step_without_child_stderr_or_argv(self):
        secret = "vless://private-token@127.0.0.1:30000"
        failure = subprocess.CalledProcessError(
            7, ["xray", "--secret", secret], output=secret.encode(),
            stderr=("bad config " + secret).encode())
        with patch.object(MODULE.subprocess, "run", side_effect=failure):
            with self.assertRaises(MODULE.CommandFailure) as caught:
                MODULE.command(["xray", "--secret", secret],
                               step="XRAY_STAGED_PREFLIGHT")
        self.assertEqual(self.render(caught.exception),
                         "PORTFOLIO_ERROR=PORTFOLIO_STEP_XRAY_STAGED_PREFLIGHT\n")
        self.assertNotIn(secret, self.render(caught.exception))

    def test_timeout_and_launch_failure_keep_safe_step(self):
        for failure in (subprocess.TimeoutExpired(["xray", "private-token"], 1),
                        FileNotFoundError("private-token")):
            with self.subTest(failure=type(failure).__name__):
                with patch.object(MODULE.subprocess, "run", side_effect=failure):
                    with self.assertRaises(MODULE.CommandFailure) as caught:
                        MODULE.command(["xray", "private-token"],
                                       step="SERVICE_START")
                self.assertEqual(self.render(caught.exception),
                                 "PORTFOLIO_ERROR=PORTFOLIO_STEP_SERVICE_START\n")

    def test_failed_rollback_reports_original_and_separate_safe_code(self):
        original = MODULE.CommandFailure("SERVICE_START")
        with patch.object(MODULE, "STATE", Mock(exists=lambda: True)), \
                patch.object(MODULE, "rollback",
                             side_effect=MODULE.CommandFailure("ROLLBACK_UFW_DELETE")):
            with self.assertRaises(MODULE.RollbackFailure) as caught:
                MODULE.compensate_after_failure({}, {"phase": "pending"}, original)
        self.assertEqual(self.render(caught.exception),
                         "PORTFOLIO_ERROR=PORTFOLIO_STEP_SERVICE_START\n"
                         "PORTFOLIO_ROLLBACK_ERROR=PORTFOLIO_STEP_ROLLBACK_UFW_DELETE\n")

    def test_untrusted_exception_text_is_never_reflected(self):
        secret = "PORTFOLIO_STEP_PRIVATE_TOKEN"
        self.assertEqual(self.render(RuntimeError(secret)),
                         "PORTFOLIO_ERROR=PORTFOLIO_UNEXPECTED\n")
        failure = MODULE.RollbackFailure(MODULE.CommandFailure("SERVICE_START"),
                                         RuntimeError(secret))
        output = self.render(failure)
        self.assertIn("PORTFOLIO_ERROR=PORTFOLIO_STEP_SERVICE_START", output)
        self.assertIn("PORTFOLIO_ROLLBACK_ERROR=PORTFOLIO_UNEXPECTED", output)
        self.assertNotIn(secret, output)

    def test_all_command_steps_have_user_facing_allowlist_entries(self):
        tree = ast.parse((ROOT / "bundle/portfolio/install.py").read_text(encoding="utf-8"))
        literal_steps = {keyword.value.value for node in ast.walk(tree)
                         if isinstance(node, ast.Call)
                         for keyword in node.keywords
                         if keyword.arg == "step" and
                         isinstance(keyword.value, ast.Constant)}
        dynamic_steps = {"ROUTE_" + name for name in
                         ("IP4_ROUTE", "IP6_ROUTE", "IP4_RULE", "IP6_RULE")}
        dynamic_steps |= {"SERVICE_SHOW_" + name for name in
                          ("USER", "GROUP", "FRAGMENTPATH", "DROPINPATHS", "MAINPID")}
        self.assertEqual({"PORTFOLIO_STEP_" + step for step in
                          literal_steps | dynamic_steps}, ERRORS.PORTFOLIO_STEPS)


if __name__ == "__main__":
    unittest.main()
