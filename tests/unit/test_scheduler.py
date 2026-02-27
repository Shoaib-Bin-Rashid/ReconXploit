"""Unit tests for Phase 9 — Scheduler module."""
import json
import threading
import pytest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

from backend.modules.scheduler import (
    SchedulerState,
    ScanScheduler,
    load_targets_from_file,
    _mode_to_phases,
    _interval_for_score,
    _humanize,
)


# ─────────────────────────────────────────────
# SchedulerState
# ─────────────────────────────────────────────

class TestSchedulerState:
    def test_creates_empty_state(self, tmp_path):
        s = SchedulerState(tmp_path / "state.json")
        assert s.all_targets() == {}

    def test_state_file_created(self, tmp_path):
        sf = tmp_path / "state.json"
        s = SchedulerState(sf)
        s.upsert_target("example.com")
        assert sf.exists()

    def test_upsert_creates_target(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        s.upsert_target("example.com", mode="quick")
        t = s.get_target("example.com")
        assert t is not None
        assert t["mode"] == "quick"

    def test_upsert_updates_existing(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        s.upsert_target("example.com", mode="full")
        s.upsert_target("example.com", mode="passive")
        assert s.get_target("example.com")["mode"] == "passive"

    def test_get_target_none_for_unknown(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        assert s.get_target("unknown.com") is None

    def test_mark_running_sets_status(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        s.upsert_target("example.com")
        s.mark_running("example.com")
        assert s.get_target("example.com")["status"] == "running"

    def test_mark_done_sets_idle(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        s.upsert_target("example.com")
        s.mark_running("example.com")
        s.mark_done("example.com", score=50, interval_h=24)
        t = s.get_target("example.com")
        assert t["status"] == "idle"
        assert t["last_score"] == 50
        assert t["run_count"] == 1

    def test_mark_done_increments_total_runs(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        s.upsert_target("example.com")
        s.mark_done("example.com", score=0, interval_h=24)
        assert s.summary()["total_runs"] == 1

    def test_mark_error_sets_status(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        s.upsert_target("example.com")
        s.mark_error("example.com", "network timeout")
        assert s.get_target("example.com")["status"] == "error"

    def test_get_due_never_run(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        s.upsert_target("never.com", next_run=None)
        assert "never.com" in s.get_due()

    def test_get_due_past_next_run(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        past = (datetime.utcnow() - timedelta(hours=2)).isoformat()
        s.upsert_target("past.com", next_run=past)
        assert "past.com" in s.get_due()

    def test_not_due_future_next_run(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        future = (datetime.utcnow() + timedelta(hours=10)).isoformat()
        s.upsert_target("future.com", next_run=future)
        assert "future.com" not in s.get_due()

    def test_running_target_not_in_due(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        s.upsert_target("busy.com", status="running", next_run=None)
        assert "busy.com" not in s.get_due()

    def test_get_running_count(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        s.upsert_target("a.com", status="running")
        s.upsert_target("b.com", status="running")
        s.upsert_target("c.com", status="idle")
        assert s.get_running_count() == 2

    def test_summary_keys(self, tmp_path):
        s = SchedulerState(tmp_path / "s.json")
        summary = s.summary()
        for key in ("total_targets", "running", "idle", "error", "total_runs"):
            assert key in summary

    def test_persists_across_instances(self, tmp_path):
        sf = tmp_path / "s.json"
        s1 = SchedulerState(sf)
        s1.upsert_target("example.com", mode="deep")

        s2 = SchedulerState(sf)
        t = s2.get_target("example.com")
        assert t is not None
        assert t["mode"] == "deep"

    def test_corrupt_file_starts_fresh(self, tmp_path):
        sf = tmp_path / "s.json"
        sf.write_text("INVALID JSON", encoding="utf-8")
        s = SchedulerState(sf)
        assert s.all_targets() == {}

    def test_thread_safety(self, tmp_path):
        """Multiple threads writing to state should not corrupt it."""
        s = SchedulerState(tmp_path / "s.json")
        errors = []

        def write(domain):
            try:
                s.upsert_target(domain, mode="full")
                s.mark_done(domain, score=50, interval_h=24)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=write, args=(f"t{i}.com",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(s.all_targets()) == 10


# ─────────────────────────────────────────────
# load_targets_from_file
# ─────────────────────────────────────────────

class TestLoadTargetsFromFile:
    def test_returns_empty_for_missing_file(self, tmp_path):
        result = load_targets_from_file(tmp_path / "missing.txt")
        assert result == []

    def test_parses_simple_line(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n", encoding="utf-8")
        result = load_targets_from_file(f)
        assert len(result) == 1
        assert result[0]["domain"] == "example.com"

    def test_parses_pipe_delimited(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("example.com | HackerOne | quick | active | 12\n", encoding="utf-8")
        result = load_targets_from_file(f)
        assert result[0]["mode"] == "quick"
        assert result[0]["interval_h"] == 12

    def test_skips_inactive_targets(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text(
            "active.com | prog | full | active\n"
            "paused.com | prog | full | paused\n",
            encoding="utf-8",
        )
        result = load_targets_from_file(f)
        assert len(result) == 1
        assert result[0]["domain"] == "active.com"

    def test_skips_comments(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text(
            "# this is a comment\n"
            "example.com\n",
            encoding="utf-8",
        )
        result = load_targets_from_file(f)
        assert len(result) == 1

    def test_skips_blank_lines(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("\n\nexample.com\n\n", encoding="utf-8")
        result = load_targets_from_file(f)
        assert len(result) == 1

    def test_defaults_mode_full(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n", encoding="utf-8")
        result = load_targets_from_file(f)
        assert result[0]["mode"] == "full"

    def test_defaults_interval_24(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n", encoding="utf-8")
        result = load_targets_from_file(f)
        assert result[0]["interval_h"] == 24

    def test_invalid_interval_uses_default(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("example.com | prog | full | active | notanumber\n", encoding="utf-8")
        result = load_targets_from_file(f)
        assert result[0]["interval_h"] == 24


# ─────────────────────────────────────────────
# Adaptive Interval
# ─────────────────────────────────────────────

class TestIntervalForScore:
    def test_critical_quartered(self):
        result = _interval_for_score(80, 24)
        assert result == 6

    def test_high_halved(self):
        result = _interval_for_score(65, 24)
        assert result == 12

    def test_medium_unchanged(self):
        result = _interval_for_score(30, 24)
        assert result == 24

    def test_never_below_minimum(self):
        result = _interval_for_score(99, 1)
        assert result >= 1

    def test_zero_score_default(self):
        result = _interval_for_score(0, 48)
        assert result == 48


# ─────────────────────────────────────────────
# Mode to phases
# ─────────────────────────────────────────────

class TestModeToPhases:
    def test_full_has_all_phases(self):
        phases = _mode_to_phases("full")
        for p in ("discovery", "live_hosts", "vulns", "js", "changes", "risk", "alerts"):
            assert p in phases

    def test_passive_only_discovery(self):
        assert _mode_to_phases("passive") == ["discovery"]

    def test_quick_minimal(self):
        phases = _mode_to_phases("quick")
        assert "discovery" in phases
        assert "live_hosts" in phases
        assert "vulns" not in phases

    def test_unknown_mode_defaults_to_full(self):
        phases = _mode_to_phases("nonexistent")
        assert "discovery" in phases
        assert "vulns" in phases


# ─────────────────────────────────────────────
# Humanize
# ─────────────────────────────────────────────

class TestHumanize:
    def test_overdue(self):
        assert _humanize(timedelta(seconds=-100)) == "overdue"

    def test_minutes_only(self):
        result = _humanize(timedelta(minutes=45))
        assert "45m" in result

    def test_hours_and_minutes(self):
        result = _humanize(timedelta(hours=3, minutes=20))
        assert "3h" in result
        assert "20m" in result

    def test_zero(self):
        result = _humanize(timedelta(0))
        assert result == "0m"


# ─────────────────────────────────────────────
# ScanScheduler
# ─────────────────────────────────────────────

class TestScanScheduler:
    def test_add_target(self, tmp_path):
        sched = ScanScheduler(state_file=tmp_path / "s.json")
        sched.add_target("example.com", mode="quick", interval_h=12)
        t = sched.state.get_target("example.com")
        assert t["mode"] == "quick"
        assert t["interval_h"] == 12

    def test_get_summary_keys(self, tmp_path):
        sched = ScanScheduler(state_file=tmp_path / "s.json")
        s = sched.get_summary()
        assert "total_targets" in s
        assert "running" in s

    def test_get_status_empty(self, tmp_path):
        sched = ScanScheduler(state_file=tmp_path / "s.json")
        rows = sched.get_status()
        assert rows == []

    def test_get_status_has_eta(self, tmp_path):
        sched = ScanScheduler(state_file=tmp_path / "s.json")
        sched.add_target("example.com")
        rows = sched.get_status()
        assert len(rows) == 1
        assert "eta" in rows[0]

    @patch("backend.modules.scheduler.ScanScheduler._launch_scan")
    def test_run_now_triggers_scan(self, mock_launch, tmp_path):
        sched = ScanScheduler(state_file=tmp_path / "s.json")
        sched.add_target("example.com")
        result = sched.run_now("example.com", mode="quick")
        assert result is True
        mock_launch.assert_called_once_with("example.com", "quick", sched.default_interval_h)

    @patch("backend.modules.scheduler.ScanScheduler._launch_scan")
    def test_run_now_skips_running(self, mock_launch, tmp_path):
        sched = ScanScheduler(state_file=tmp_path / "s.json")
        sched.state.upsert_target("example.com", status="running")
        result = sched.run_now("example.com")
        assert result is False
        mock_launch.assert_not_called()

    @patch("backend.modules.scheduler.ScanScheduler._sync_targets")
    @patch("backend.modules.scheduler.ScanScheduler._launch_scan")
    def test_tick_launches_due_targets(self, mock_launch, mock_sync, tmp_path):
        sched = ScanScheduler(state_file=tmp_path / "s.json", max_concurrent=3)
        sched.add_target("a.com")   # no next_run → due immediately
        sched.add_target("b.com")
        sched._tick()
        assert mock_launch.call_count == 2

    @patch("backend.modules.scheduler.ScanScheduler._sync_targets")
    @patch("backend.modules.scheduler.ScanScheduler._launch_scan")
    def test_tick_respects_max_concurrent(self, mock_launch, mock_sync, tmp_path):
        sched = ScanScheduler(state_file=tmp_path / "s.json", max_concurrent=1)
        sched.add_target("a.com")
        sched.add_target("b.com")
        sched.state.upsert_target("a.com", status="running")  # 1 already running
        sched._tick()
        # max_concurrent=1, 1 already running → 0 slots → no new launch
        mock_launch.assert_not_called()

    @patch("backend.modules.scheduler.ScanScheduler._sync_targets")
    @patch("backend.modules.scheduler.ScanScheduler._launch_scan")
    def test_tick_skips_future_targets(self, mock_launch, mock_sync, tmp_path):
        future = (datetime.utcnow() + timedelta(hours=100)).isoformat()
        sched = ScanScheduler(state_file=tmp_path / "s.json")
        sched.state.upsert_target("future.com", next_run=future)
        sched._tick()
        mock_launch.assert_not_called()

    def test_stop_event_set(self, tmp_path):
        sched = ScanScheduler(state_file=tmp_path / "s.json")
        sched.stop()
        assert sched._stop_event.is_set()

    def test_sync_targets_from_file(self, tmp_path):
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("new-target.com | prog | full | active | 24\n", encoding="utf-8")
        sched = ScanScheduler(state_file=tmp_path / "s.json")
        # load_targets_from_file() uses module-level default; call it directly
        from backend.modules.scheduler import load_targets_from_file as ltf
        for t in ltf(targets_file):
            sched.state.upsert_target(t["domain"], mode=t["mode"], interval_h=t["interval_h"])
        assert sched.state.get_target("new-target.com") is not None
