"""
Unit tests for backend/utils/executor.py (ToolExecutor + run_tool).
Phase 11: Error Handling
"""

import subprocess
import time
from unittest.mock import patch, MagicMock, call
import pytest

from backend.utils.executor import ToolExecutor, ToolResult, run_tool


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_completed(returncode=0, stdout="output", stderr=""):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


# ──────────────────────────────────────────────────────────────────────────────
# ToolResult dataclass
# ──────────────────────────────────────────────────────────────────────────────

class TestToolResult:
    def test_default_values(self):
        r = ToolResult(tool_name="test", success=True)
        assert r.stdout == ""
        assert r.stderr == ""
        assert r.returncode == -1
        assert r.error is None
        assert r.attempts == 1
        assert r.duration_s == 0.0

    def test_failed_result(self):
        r = ToolResult(tool_name="foo", success=False, error="timeout after 10s")
        assert not r.success
        assert "timeout" in r.error


# ──────────────────────────────────────────────────────────────────────────────
# ToolExecutor.is_available
# ──────────────────────────────────────────────────────────────────────────────

class TestIsAvailable:
    def test_available_when_which_returns_path(self):
        with patch("shutil.which", return_value="/usr/bin/echo"):
            ex = ToolExecutor("echo")
            assert ex.is_available() is True

    def test_not_available_when_which_returns_none(self):
        with patch("shutil.which", return_value=None):
            ex = ToolExecutor("notreal")
            assert ex.is_available() is False

    def test_uses_first_token_of_tool_name(self):
        with patch("shutil.which", return_value="/usr/bin/foo") as mock_which:
            ToolExecutor("foo --some-flag").is_available()
            mock_which.assert_called_once_with("foo")


# ──────────────────────────────────────────────────────────────────────────────
# Successful runs
# ──────────────────────────────────────────────────────────────────────────────

class TestSuccessfulRun:
    def test_returns_stdout_on_success(self):
        with patch("subprocess.run", return_value=_make_completed(0, "hello\n")):
            ex = ToolExecutor("echo")
            r = ex.run(["echo", "hello"])
        assert r.success is True
        assert r.stdout == "hello\n"
        assert r.returncode == 0
        assert r.error is None

    def test_attempts_is_one_on_first_success(self):
        with patch("subprocess.run", return_value=_make_completed()):
            r = ToolExecutor("t").run(["t"])
        assert r.attempts == 1

    def test_duration_is_populated(self):
        with patch("subprocess.run", return_value=_make_completed()):
            r = ToolExecutor("t").run(["t"])
        assert r.duration_s >= 0

    def test_non_zero_returncode_sets_success_false(self):
        with patch("subprocess.run", return_value=_make_completed(returncode=1)):
            r = ToolExecutor("t").run(["t"])
        assert r.success is False
        assert r.error == "exit code 1"


# ──────────────────────────────────────────────────────────────────────────────
# Retry logic
# ──────────────────────────────────────────────────────────────────────────────

class TestRetry:
    def test_retries_on_nonzero_exit(self):
        fail = _make_completed(returncode=1)
        ok   = _make_completed(returncode=0, stdout="ok")
        with patch("subprocess.run", side_effect=[fail, ok]):
            with patch("time.sleep"):
                r = ToolExecutor("t", max_retries=1).run(["t"])
        assert r.success is True
        assert r.attempts == 2

    def test_all_retries_exhausted_returns_failure(self):
        fail = _make_completed(returncode=1)
        with patch("subprocess.run", return_value=fail):
            with patch("time.sleep"):
                r = ToolExecutor("t", max_retries=2).run(["t"])
        assert r.success is False

    def test_sleep_called_between_retries(self):
        fail = _make_completed(returncode=1)
        ok   = _make_completed(returncode=0)
        with patch("subprocess.run", side_effect=[fail, ok]):
            with patch("time.sleep") as mock_sleep:
                ToolExecutor("t", max_retries=1, initial_wait=3).run(["t"])
        mock_sleep.assert_called_once_with(3)

    def test_backoff_doubles_sleep_time(self):
        fail = _make_completed(returncode=1)
        ok   = _make_completed(returncode=0)
        with patch("subprocess.run", side_effect=[fail, fail, ok]):
            with patch("time.sleep") as mock_sleep:
                ToolExecutor("t", max_retries=2, initial_wait=1, backoff=2.0).run(["t"])
        assert mock_sleep.call_count == 2
        calls = [c.args[0] for c in mock_sleep.call_args_list]
        assert calls[0] == 1
        assert calls[1] == 2.0

    def test_file_not_found_no_retry(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with patch("time.sleep") as mock_sleep:
                r = ToolExecutor("t", max_retries=3).run(["t"])
        mock_sleep.assert_not_called()
        assert r.returncode == -2
        assert "not found" in r.error


# ──────────────────────────────────────────────────────────────────────────────
# Timeout handling
# ──────────────────────────────────────────────────────────────────────────────

class TestTimeout:
    def test_timeout_returns_failure(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["t"], timeout=5)):
            r = ToolExecutor("t", timeout=5).run(["t"])
        assert r.success is False
        assert "timeout" in r.error

    def test_timeout_includes_duration_in_seconds(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["t"], timeout=10)):
            r = ToolExecutor("t", timeout=10).run(["t"])
        assert "10" in r.error


# ──────────────────────────────────────────────────────────────────────────────
# OS error
# ──────────────────────────────────────────────────────────────────────────────

class TestOSError:
    def test_os_error_returns_failure(self):
        with patch("subprocess.run", side_effect=OSError("permission denied")):
            r = ToolExecutor("t").run(["t"])
        assert r.success is False
        assert r.returncode == -3
        assert "OS error" in r.error


# ──────────────────────────────────────────────────────────────────────────────
# run_tool convenience function
# ──────────────────────────────────────────────────────────────────────────────

class TestRunTool:
    def test_returns_stdout_on_success(self):
        with patch("subprocess.run", return_value=_make_completed(0, "output")):
            result = run_tool(["echo", "output"], tool_name="echo")
        assert result == "output"

    def test_returns_empty_string_on_failure(self):
        with patch("subprocess.run", return_value=_make_completed(1, "")):
            result = run_tool(["t"], tool_name="t")
        assert result == ""

    def test_returns_empty_string_on_file_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = run_tool(["nonexistent"], tool_name="nonexistent")
        assert result == ""

    def test_uses_cmd_first_token_as_tool_name(self):
        # Should not raise even without explicit tool_name
        with patch("subprocess.run", return_value=_make_completed()):
            result = run_tool(["mybin", "--flag"])
        assert isinstance(result, str)

    def test_timeout_returns_empty_string(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["t"], 1)):
            result = run_tool(["t"], timeout=1)
        assert result == ""


# ──────────────────────────────────────────────────────────────────────────────
# Integration-style: verify subprocess.run receives correct kwargs
# ──────────────────────────────────────────────────────────────────────────────

class TestSubprocessKwargs:
    def test_run_passes_timeout_to_subprocess(self):
        with patch("subprocess.run", return_value=_make_completed()) as mock_run:
            ToolExecutor("t", timeout=42).run(["t", "arg"])
        _, kwargs = mock_run.call_args
        assert kwargs["timeout"] == 42

    def test_run_uses_capture_output(self):
        with patch("subprocess.run", return_value=_make_completed()) as mock_run:
            ToolExecutor("t").run(["t"])
        _, kwargs = mock_run.call_args
        assert kwargs["capture_output"] is True

    def test_run_passes_env(self):
        env = {"PATH": "/custom"}
        with patch("subprocess.run", return_value=_make_completed()) as mock_run:
            ToolExecutor("t").run(["t"], env=env)
        _, kwargs = mock_run.call_args
        assert kwargs["env"] == env
