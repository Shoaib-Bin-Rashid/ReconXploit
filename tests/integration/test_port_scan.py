"""
Integration tests for Phase 3 — Port & Service Scanning.
Uses SQLite in-memory DB. All subprocess calls mocked.
"""

import json
import pytest
from unittest.mock import patch, MagicMock


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" extrainfo=""/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9" extrainfo=""/>
      </port>
    </ports>
  </host>
</nmaprun>"""

SAMPLE_LIVE_HOSTS = [
    {"url": "https://api.example.com", "ip": "93.184.216.34", "status_code": 200},
]


@pytest.mark.integration
class TestPortScanDBStorage:

    def test_ports_stored_in_db(self, sqlite_session):
        from backend.modules.port_scan import PortScanner
        from backend.models.models import Port, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()

        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        port_scanner = PortScanner("example.com", scan.id)

        def nmap_side(cmd, **kwargs):
            if "naabu" in cmd[0]:
                raise FileNotFoundError
            return MagicMock(returncode=0, stdout=SAMPLE_NMAP_XML, stderr="")

        with patch("subprocess.run", side_effect=nmap_side), \
             patch("backend.modules.port_scan.save_ports"), \
             patch("backend.modules.port_scan.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            port_scanner.run(SAMPLE_LIVE_HOSTS)

        stored = sqlite_session.query(Port).filter(Port.scan_id == scan.id).all()
        assert len(stored) == 2

    def test_port_fields_correct(self, sqlite_session):
        from backend.modules.port_scan import PortScanner
        from backend.models.models import Port, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()

        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        port_scanner = PortScanner("example.com", scan.id)

        def nmap_side(cmd, **kwargs):
            if "naabu" in cmd[0]:
                raise FileNotFoundError
            return MagicMock(returncode=0, stdout=SAMPLE_NMAP_XML, stderr="")

        with patch("subprocess.run", side_effect=nmap_side), \
             patch("backend.modules.port_scan.save_ports"), \
             patch("backend.modules.port_scan.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            port_scanner.run(SAMPLE_LIVE_HOSTS)

        ssh = sqlite_session.query(Port).filter(
            Port.scan_id == scan.id,
            Port.port == 22
        ).first()

        assert ssh is not None
        assert ssh.service_name == "ssh"
        assert "OpenSSH" in ssh.service_version
        assert ssh.is_sensitive is True

    def test_no_duplicate_ports_in_same_scan(self, sqlite_session):
        from backend.modules.port_scan import PortScanner
        from backend.models.models import Port, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()

        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        port_scanner = PortScanner("example.com", scan.id)

        def nmap_side(cmd, **kwargs):
            if "naabu" in cmd[0]:
                raise FileNotFoundError
            return MagicMock(returncode=0, stdout=SAMPLE_NMAP_XML, stderr="")

        with patch("subprocess.run", side_effect=nmap_side), \
             patch("backend.modules.port_scan.save_ports"), \
             patch("backend.modules.port_scan.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            port_scanner.run(SAMPLE_LIVE_HOSTS)
            port_scanner.run(SAMPLE_LIVE_HOSTS)  # run twice

        stored = sqlite_session.query(Port).filter(
            Port.scan_id == scan.id,
            Port.port == 80
        ).all()
        assert len(stored) == 1

    def test_sensitive_flag_stored(self, sqlite_session):
        from backend.modules.port_scan import PortScanner
        from backend.models.models import Port, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()

        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        port_scanner = PortScanner("example.com", scan.id)

        def nmap_side(cmd, **kwargs):
            if "naabu" in cmd[0]:
                raise FileNotFoundError
            return MagicMock(returncode=0, stdout=SAMPLE_NMAP_XML, stderr="")

        with patch("subprocess.run", side_effect=nmap_side), \
             patch("backend.modules.port_scan.save_ports"), \
             patch("backend.modules.port_scan.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            port_scanner.run(SAMPLE_LIVE_HOSTS)

        http = sqlite_session.query(Port).filter(Port.port == 80).first()
        ssh = sqlite_session.query(Port).filter(Port.port == 22).first()

        assert http.is_sensitive is False
        assert ssh.is_sensitive is True


@pytest.mark.integration
class TestPhase3Pipeline:

    def test_phase3_returns_results(self):
        with patch("backend.modules.port_scan.PortScanner") as MockScanner:
            instance = MagicMock()
            instance.run.return_value = 3
            instance.get_sensitive_ports.return_value = [{"port": 22}]
            instance.get_results.return_value = [
                {"ip": "1.1.1.1", "port": 80},
                {"ip": "1.1.1.1", "port": 443},
                {"ip": "1.1.1.1", "port": 22},
            ]
            MockScanner.return_value = instance

            from reconxp import run_phase_ports
            results = run_phase_ports("example.com", "scan-123", SAMPLE_LIVE_HOSTS)

        assert len(results) == 3

    def test_phase3_with_no_live_hosts(self):
        with patch("backend.modules.port_scan.PortScanner") as MockScanner:
            instance = MagicMock()
            instance.run.return_value = 0
            instance.get_sensitive_ports.return_value = []
            instance.get_results.return_value = []
            MockScanner.return_value = instance

            from reconxp import run_phase_ports
            results = run_phase_ports("example.com", "scan-123", [])

        assert results == []
