"""Integration tests for Phase 9 — Scheduler."""
import json
import threading
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from backend.modules.scheduler import (
    ScanScheduler, SchedulerState, load_targets_from_file
)


class TestSchedulerIntegration:
    def test_full_lifecycle(self, tmp_path):
        """Add target → mark running → mark done → verify state."""
        sf = tmp_path / "state.json"
        s  = SchedulerState(sf)

        s.upsert_target("lifecycle.com", mode="full", interval_h=24)
        assert s.get_target("lifecycle.com")["status"] == "idle"

        s.mark_running("lifecycle.com")
        assert s.get_target("lifecycle.com")["status"] == "running"
        assert "lifecycle.com" not in s.get_due()

        s.mark_done("lifecycle.com", score=65, interval_h=12)
        t = s.get_target("lifecycle.com")
        assert t["status"] == "idle"
        assert t["last_score"] == 65
        assert t["run_count"] == 1

        # next_run should be ~12h from now
        next_run = datetime.fromisoformat(t["next_run"])
        diff = next_run - datetime.utcnow()
        assert 11 <= diff.total_seconds() / 3600 <= 13

    def test_state_persists_to_disk(self, tmp_path):
        sf = tmp_path / "state.json"
        s1 = SchedulerState(sf)
        s1.upsert_target("persist.com", mode="deep")
        del s1

        s2 = SchedulerState(sf)
        t = s2.get_target("persist.com")
        assert t is not None
        assert t["mode"] == "deep"

    def test_multiple_targets_due_and_one_running(self, tmp_path):
        sf = tmp_path / "state.json"
        s  = SchedulerState(sf)
        s.upsert_target("a.com")  # due
        s.upsert_target("b.com")  # due
        s.upsert_target("c.com", status="running")  # not due

        due = s.get_due()
        assert "a.com" in due
        assert "b.com" in due
        assert "c.com" not in due

    @patch("backend.modules.scheduler.ScanScheduler._execute_scan", return_value=55)
    def test_scan_thread_marks_done(self, mock_exec, tmp_path):
        sf = tmp_path / "state.json"
        sched = ScanScheduler(state_file=sf, default_interval_h=24)
        sched.state.upsert_target("thread.com")
        sched._run_scan_thread("thread.com", "full", 24)

        t = sched.state.get_target("thread.com")
        assert t["status"] == "idle"
        assert t["last_score"] == 55
        assert t["run_count"] == 1

    @patch("backend.modules.scheduler.ScanScheduler._execute_scan", side_effect=Exception("scan failed"))
    def test_scan_thread_marks_error_on_exception(self, mock_exec, tmp_path):
        sf = tmp_path / "state.json"
        sched = ScanScheduler(state_file=sf)
        sched.state.upsert_target("errored.com")
        sched._run_scan_thread("errored.com", "full", 24)

        t = sched.state.get_target("errored.com")
        assert t["status"] == "error"

    def test_targets_file_parsed_and_synced(self, tmp_path):
        tf = tmp_path / "targets.txt"
        tf.write_text(
            "alpha.com | prog | full   | active | 6\n"
            "beta.com  | prog | quick  | active | 24\n"
            "gamma.com | prog | passive| paused | 48\n",
            encoding="utf-8",
        )
        sf = tmp_path / "state.json"
        sched = ScanScheduler(state_file=sf)

        # Call load_targets_from_file directly with our temp file, then sync manually
        targets = load_targets_from_file(tf)
        for t in targets:
            sched.state.upsert_target(t["domain"], mode=t["mode"], interval_h=t["interval_h"])

        assert sched.state.get_target("alpha.com") is not None
        assert sched.state.get_target("beta.com")  is not None
        assert sched.state.get_target("gamma.com") is None  # paused — not loaded

    def test_adaptive_interval_applied(self, tmp_path):
        """High-risk score should reduce next scan interval."""
        sf = tmp_path / "state.json"
        s  = SchedulerState(sf)
        s.upsert_target("risky.com", interval_h=24)
        s.mark_done("risky.com", score=90, interval_h=6)   # CRITICAL → 6h

        t = s.get_target("risky.com")
        next_run = datetime.fromisoformat(t["next_run"])
        diff = (next_run - datetime.utcnow()).total_seconds() / 3600
        assert 5 <= diff <= 7
