"""
ReconXploit - ToolExecutor
Phase 11: Centralised subprocess runner with retry + exponential backoff.

Usage:
    from backend.utils.executor import ToolExecutor, ToolResult

    ex = ToolExecutor(tool_name="subfinder", timeout=120, max_retries=2)
    res = ex.run(["subfinder", "-d", "example.com"])
    if res.success:
        print(res.stdout)
    else:
        print(res.error)
"""

import subprocess
import time
import logging
import shutil
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Result container
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ToolResult:
    tool_name: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    error: Optional[str] = None      # human-readable failure reason
    attempts: int = 1
    duration_s: float = 0.0


# ──────────────────────────────────────────────────────────────────────────────
# ToolExecutor
# ──────────────────────────────────────────────────────────────────────────────

class ToolExecutor:
    """
    Run an external binary with retry + exponential backoff.

    Args:
        tool_name   : display name used in log messages
        timeout     : per-attempt timeout in seconds (default 300)
        max_retries : number of *extra* attempts after the first (default 0)
        backoff     : multiplier applied to wait between retries (default 2.0)
        initial_wait: seconds to wait before the first retry (default 1)
    """

    def __init__(
        self,
        tool_name: str,
        timeout: int = 300,
        max_retries: int = 0,
        backoff: float = 2.0,
        initial_wait: float = 1.0,
    ):
        self.tool_name    = tool_name
        self.timeout      = timeout
        self.max_retries  = max_retries
        self.backoff      = backoff
        self.initial_wait = initial_wait

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def is_available(self) -> bool:
        """Return True if the binary exists somewhere in PATH."""
        return shutil.which(self.tool_name.split()[0]) is not None

    def run(self, cmd: List[str], env: Optional[dict] = None) -> ToolResult:
        """Execute cmd, retrying on transient failures. Always returns ToolResult."""
        total_attempts = 1 + self.max_retries
        wait = self.initial_wait

        for attempt in range(1, total_attempts + 1):
            result = self._run_once(cmd, attempt, env)
            if result.success:
                return result

            # Don't retry on "tool not found" — it won't appear next attempt
            if result.returncode == -2:
                return result

            if attempt < total_attempts:
                logger.info(
                    f"[{self.tool_name}] attempt {attempt}/{total_attempts} failed "
                    f"({result.error}), retrying in {wait:.1f}s"
                )
                time.sleep(wait)
                wait *= self.backoff

        # All attempts exhausted
        result.attempts = total_attempts
        return result

    # ──────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────

    def _run_once(self, cmd: List[str], attempt: int, env: Optional[dict]) -> ToolResult:
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )
            duration = time.monotonic() - t0
            success = proc.returncode == 0

            if not success:
                logger.warning(
                    f"[{self.tool_name}] exited {proc.returncode} "
                    f"(attempt {attempt}): {proc.stderr[:300]}"
                )

            return ToolResult(
                tool_name   = self.tool_name,
                success     = success,
                stdout      = proc.stdout,
                stderr      = proc.stderr,
                returncode  = proc.returncode,
                error       = None if success else f"exit code {proc.returncode}",
                attempts    = attempt,
                duration_s  = round(duration, 2),
            )

        except subprocess.TimeoutExpired:
            duration = time.monotonic() - t0
            logger.warning(f"[{self.tool_name}] timed out after {self.timeout}s (attempt {attempt})")
            return ToolResult(
                tool_name  = self.tool_name,
                success    = False,
                error      = f"timeout after {self.timeout}s",
                returncode = -1,
                attempts   = attempt,
                duration_s = round(duration, 2),
            )

        except FileNotFoundError:
            logger.warning(
                f"[{self.tool_name}] binary not found in PATH. "
                "Install with scripts/install_tools.sh"
            )
            return ToolResult(
                tool_name  = self.tool_name,
                success    = False,
                error      = "binary not found in PATH",
                returncode = -2,
                attempts   = attempt,
            )

        except OSError as exc:
            duration = time.monotonic() - t0
            logger.error(f"[{self.tool_name}] OS error (attempt {attempt}): {exc}")
            return ToolResult(
                tool_name  = self.tool_name,
                success    = False,
                error      = f"OS error: {exc}",
                returncode = -3,
                attempts   = attempt,
                duration_s = round(duration, 2),
            )


# ──────────────────────────────────────────────────────────────────────────────
# Convenience: module-level run helper (no retry, matches old _execute() style)
# ──────────────────────────────────────────────────────────────────────────────

def run_tool(
    cmd: List[str],
    tool_name: str = "",
    timeout: int = 300,
) -> str:
    """
    Drop-in replacement for the old one-off `_execute()` helpers.
    Returns stdout or "" on any failure.
    """
    name = tool_name or (cmd[0] if cmd else "unknown")
    ex = ToolExecutor(tool_name=name, timeout=timeout, max_retries=0)
    return ex.run(cmd).stdout
