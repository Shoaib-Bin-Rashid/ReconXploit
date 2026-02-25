"""
Unit tests for backend/modules/port_scan.py

All subprocess calls and DB operations are mocked.
No real nmap/naabu binary required.
"""

import json
import pytest
from unittest.mock import patch, MagicMock


# ─────────────────────────────────────────────
# SAMPLE DATA
# ─────────────────────────────────────────────

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
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18.0" extrainfo=""/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9" extrainfo="protocol 2.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

SAMPLE_NMAP_XML_CLOSED = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

SAMPLE_NAABU_OUTPUT = "\n".join([
    json.dumps({"ip": "93.184.216.34", "port": 80}),
    json.dumps({"ip": "93.184.216.34", "port": 443}),
    json.dumps({"ip": "93.184.216.34", "port": 22}),
])

SAMPLE_LIVE_HOSTS = [
    {"url": "https://api.example.com", "ip": "93.184.216.34", "status_code": 200},
    {"url": "https://admin.example.com", "ip": "93.184.216.35", "status_code": 401},
]


@pytest.fixture
def scanner():
    from backend.modules.port_scan import PortScanner
    return PortScanner("example.com", "scan-xyz-456")


# ─────────────────────────────────────────────
# INIT TESTS
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestPortScannerInit:

    def test_init_domain(self, scanner):
        assert scanner.domain == "example.com"

    def test_init_scan_id(self, scanner):
        assert scanner.scan_id == "scan-xyz-456"

    def test_init_empty_results(self, scanner):
        assert scanner.results == []

    def test_get_results_empty(self, scanner):
        assert scanner.get_results() == []

    def test_get_sensitive_ports_empty(self, scanner):
        assert scanner.get_sensitive_ports() == []

    def test_get_open_ports_summary_empty(self, scanner):
        assert scanner.get_open_ports_summary() == {}


# ─────────────────────────────────────────────
# IP EXTRACTION TESTS
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestExtractIPs:

    def test_extracts_ips_from_live_hosts(self, scanner):
        ips = scanner._extract_ips(SAMPLE_LIVE_HOSTS)
        assert "93.184.216.34" in ips
        assert "93.184.216.35" in ips

    def test_deduplicates_ips(self, scanner):
        hosts = [
            {"ip": "1.2.3.4"},
            {"ip": "1.2.3.4"},
            {"ip": "5.6.7.8"},
        ]
        ips = scanner._extract_ips(hosts)
        assert ips.count("1.2.3.4") == 1
        assert len(ips) == 2

    def test_skips_empty_ips(self, scanner):
        hosts = [{"ip": ""}, {"ip": None}, {"ip": "1.2.3.4"}]
        ips = scanner._extract_ips(hosts)
        assert ips == ["1.2.3.4"]

    def test_empty_live_hosts(self, scanner):
        assert scanner._extract_ips([]) == []


# ─────────────────────────────────────────────
# PORT RANGE TESTS
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestPortRange:

    def test_quick_mode_uses_top_ports(self, scanner):
        r = scanner._get_port_range("quick")
        assert "80" in r and "443" in r
        assert "-" not in r  # not a range, comma separated

    def test_full_mode_uses_1_to_10000(self, scanner):
        assert scanner._get_port_range("full") == "1-10000"

    def test_deep_mode_uses_full_range(self, scanner):
        assert scanner._get_port_range("deep") == "1-65535"

    def test_unknown_mode_defaults_to_full(self, scanner):
        assert scanner._get_port_range("anything") == "1-10000"


# ─────────────────────────────────────────────
# NAABU PARSER TESTS
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestNaabuParser:

    def test_parses_json_output(self, scanner):
        result = scanner._parse_naabu_output(SAMPLE_NAABU_OUTPUT)
        assert 80 in result["93.184.216.34"]
        assert 443 in result["93.184.216.34"]

    def test_parses_plain_text_ip_port(self, scanner):
        plain = "93.184.216.34:8080\n93.184.216.34:3000\n"
        result = scanner._parse_naabu_output(plain)
        assert 8080 in result["93.184.216.34"]
        assert 3000 in result["93.184.216.34"]

    def test_empty_output_returns_empty(self, scanner):
        assert scanner._parse_naabu_output("") == {}

    def test_skips_invalid_lines(self, scanner):
        result = scanner._parse_naabu_output("invalid\ngarbage\n")
        assert result == {}

    def test_groups_ports_by_ip(self, scanner):
        multi = "\n".join([
            json.dumps({"ip": "1.1.1.1", "port": 80}),
            json.dumps({"ip": "1.1.1.1", "port": 443}),
            json.dumps({"ip": "2.2.2.2", "port": 22}),
        ])
        result = scanner._parse_naabu_output(multi)
        assert len(result["1.1.1.1"]) == 2
        assert 22 in result["2.2.2.2"]


# ─────────────────────────────────────────────
# NMAP XML PARSER TESTS
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestNmapParser:

    def test_parses_open_ports(self, scanner):
        results = scanner._parse_nmap_xml(SAMPLE_NMAP_XML)
        ports = [r["port"] for r in results]
        assert 80 in ports
        assert 443 in ports
        assert 22 in ports

    def test_parses_ip(self, scanner):
        results = scanner._parse_nmap_xml(SAMPLE_NMAP_XML)
        assert all(r["ip"] == "93.184.216.34" for r in results)

    def test_parses_service_name(self, scanner):
        results = scanner._parse_nmap_xml(SAMPLE_NMAP_XML)
        http_port = next(r for r in results if r["port"] == 80)
        assert http_port["service"] == "http"

    def test_parses_service_version(self, scanner):
        results = scanner._parse_nmap_xml(SAMPLE_NMAP_XML)
        ssh_port = next(r for r in results if r["port"] == 22)
        assert "OpenSSH" in ssh_port["version"]

    def test_skips_closed_ports(self, scanner):
        results = scanner._parse_nmap_xml(SAMPLE_NMAP_XML_CLOSED)
        assert results == []

    def test_empty_xml_returns_empty(self, scanner):
        assert scanner._parse_nmap_xml("") == []

    def test_invalid_xml_returns_empty(self, scanner):
        assert scanner._parse_nmap_xml("not xml at all") == []

    def test_parses_protocol(self, scanner):
        results = scanner._parse_nmap_xml(SAMPLE_NMAP_XML)
        assert all(r["protocol"] == "tcp" for r in results)


# ─────────────────────────────────────────────
# SENSITIVE PORT MARKING TESTS
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestSensitivePorts:

    def test_ssh_marked_sensitive(self, scanner):
        scanner.results = [{"ip": "1.1.1.1", "port": 22, "protocol": "tcp"}]
        scanner._mark_sensitive()
        assert scanner.results[0]["is_sensitive"] is True

    def test_http_not_sensitive(self, scanner):
        scanner.results = [{"ip": "1.1.1.1", "port": 80, "protocol": "tcp"}]
        scanner._mark_sensitive()
        assert scanner.results[0]["is_sensitive"] is False

    def test_mysql_marked_sensitive(self, scanner):
        scanner.results = [{"ip": "1.1.1.1", "port": 3306, "protocol": "tcp"}]
        scanner._mark_sensitive()
        assert scanner.results[0]["is_sensitive"] is True

    def test_redis_marked_sensitive(self, scanner):
        scanner.results = [{"ip": "1.1.1.1", "port": 6379, "protocol": "tcp"}]
        scanner._mark_sensitive()
        assert scanner.results[0]["is_sensitive"] is True

    def test_get_sensitive_ports_filters_correctly(self, scanner):
        scanner.results = [
            {"ip": "1.1.1.1", "port": 22, "is_sensitive": True},
            {"ip": "1.1.1.1", "port": 80, "is_sensitive": False},
            {"ip": "1.1.1.1", "port": 3306, "is_sensitive": True},
        ]
        sensitive = scanner.get_sensitive_ports()
        assert len(sensitive) == 2
        ports = [p["port"] for p in sensitive]
        assert 22 in ports and 3306 in ports


# ─────────────────────────────────────────────
# RUN METHOD TESTS
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestRunMethod:

    def test_returns_zero_when_no_live_hosts(self, scanner):
        with patch("backend.modules.port_scan.save_ports"):
            count = scanner.run([])
        assert count == 0

    def test_returns_zero_when_no_ips(self, scanner):
        with patch("backend.modules.port_scan.save_ports"):
            count = scanner.run([{"url": "https://x.com", "ip": ""}])
        assert count == 0

    def test_run_with_naabu_available(self, scanner):
        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.port_scan.save_ports"), \
             patch.object(scanner, "_store_results", return_value=3):
            # First call = naabu, second+ = nmap
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=SAMPLE_NAABU_OUTPUT, stderr=""),
                MagicMock(returncode=0, stdout=SAMPLE_NMAP_XML, stderr=""),
            ]
            count = scanner.run(SAMPLE_LIVE_HOSTS)
        assert count == 3

    def test_run_falls_back_when_naabu_missing(self, scanner):
        import subprocess as sp

        def side_effect(cmd, **kwargs):
            if "naabu" in cmd[0]:
                raise FileNotFoundError
            return MagicMock(returncode=0, stdout=SAMPLE_NMAP_XML, stderr="")

        with patch("subprocess.run", side_effect=side_effect), \
             patch("backend.modules.port_scan.save_ports"), \
             patch.object(scanner, "_store_results", return_value=3):
            count = scanner.run(SAMPLE_LIVE_HOSTS)
        assert count == 3

    def test_file_storage_always_called(self, scanner):
        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.port_scan.save_ports") as mock_save, \
             patch.object(scanner, "_store_results", return_value=3):
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=SAMPLE_NAABU_OUTPUT, stderr=""),
                MagicMock(returncode=0, stdout=SAMPLE_NMAP_XML, stderr=""),
            ]
            scanner.run(SAMPLE_LIVE_HOSTS)
        mock_save.assert_called_once()

    def test_get_open_ports_summary(self, scanner):
        scanner.results = [
            {"ip": "1.1.1.1", "port": 80},
            {"ip": "1.1.1.1", "port": 443},
            {"ip": "2.2.2.2", "port": 22},
        ]
        summary = scanner.get_open_ports_summary()
        assert 80 in summary["1.1.1.1"]
        assert 443 in summary["1.1.1.1"]
        assert 22 in summary["2.2.2.2"]
