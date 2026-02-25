"""
Unit tests for backend/modules/discovery.py

All external tool calls (subprocess, HTTP) are mocked.
No real network or tool installations required.
"""

import json
import pytest
from unittest.mock import patch, MagicMock, call
from urllib.error import URLError


@pytest.mark.unit
class TestSubdomainDiscoveryInit:
    """Tests for SubdomainDiscovery initialization."""

    def test_init_sets_domain(self):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        assert sd.domain == "example.com"

    def test_init_sets_scan_id(self):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        assert sd.scan_id == "scan-123"

    def test_init_empty_results(self):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        assert len(sd.results) == 0

    def test_get_subdomains_initially_empty(self):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        assert sd.get_subdomains() == []


@pytest.mark.unit
class TestSubfinderIntegration:
    """Tests for the subfinder runner."""

    def test_parses_plain_text_output(self, mock_subprocess_success):
        """subfinder plain text: one subdomain per line."""
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd._run_subfinder()
        assert ("sub1.example.com", "subfinder") in sd.results
        assert ("sub2.example.com", "subfinder") in sd.results
        assert ("sub3.example.com", "subfinder") in sd.results

    def test_parses_json_output(self):
        """subfinder JSON output: each line is a JSON object."""
        json_lines = "\n".join([
            json.dumps({"host": "api.example.com"}),
            json.dumps({"host": "admin.example.com"}),
        ])
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=json_lines, stderr="")
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_subfinder()
        assert ("api.example.com", "subfinder") in sd.results
        assert ("admin.example.com", "subfinder") in sd.results

    def test_skips_unrelated_domains(self):
        """Subdomains not containing target domain are ignored."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="api.example.com\nunrelated.org\n",
                stderr=""
            )
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_subfinder()
        subdomains = [r[0] for r in sd.results]
        assert "unrelated.org" not in subdomains

    def test_tool_not_found_does_not_raise(self, mock_subprocess_failure):
        """FileNotFoundError is caught gracefully."""
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd._run_subfinder()  # should not raise
        assert len(sd.results) == 0

    def test_timeout_returns_empty(self):
        """Timeout is caught gracefully."""
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="subfinder", timeout=300)):
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_subfinder()
        assert len(sd.results) == 0

    def test_normalizes_to_lowercase(self):
        """Subdomains should be stored lowercase."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="API.EXAMPLE.COM\n", stderr=""
            )
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_subfinder()
        subdomains = [r[0] for r in sd.results]
        assert "api.example.com" in subdomains

    def test_deduplicates_results(self):
        """Same subdomain found twice should be stored once."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="api.example.com\napi.example.com\napi.example.com\n",
                stderr=""
            )
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_subfinder()
        count = sum(1 for r in sd.results if r[0] == "api.example.com")
        assert count == 1


@pytest.mark.unit
class TestAssetfinderIntegration:
    """Tests for the assetfinder runner."""

    def test_parses_output_correctly(self, mock_subprocess_success):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd._run_assetfinder()
        assert ("sub1.example.com", "assetfinder") in sd.results

    def test_source_tagged_correctly(self, mock_subprocess_success):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd._run_assetfinder()
        sources = [r[1] for r in sd.results]
        assert all(s == "assetfinder" for s in sources)

    def test_empty_lines_ignored(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="\n\napi.example.com\n\n", stderr=""
            )
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_assetfinder()
        assert len(sd.results) == 1

    def test_tool_not_found_handled(self, mock_subprocess_failure):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd._run_assetfinder()  # should not raise
        assert len(sd.results) == 0


@pytest.mark.unit
class TestCrtshIntegration:
    """Tests for the crt.sh certificate transparency runner."""

    def test_parses_crtsh_response(self):
        fake_response = json.dumps([
            {"name_value": "api.example.com"},
            {"name_value": "admin.example.com\nwww.example.com"},
            {"name_value": "*.example.com"},
        ]).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_crtsh()

        subdomains = [r[0] for r in sd.results]
        assert "api.example.com" in subdomains
        assert "admin.example.com" in subdomains
        assert "www.example.com" in subdomains

    def test_wildcard_stripped(self):
        """*.example.com → example.com after stripping wildcard."""
        fake_response = json.dumps([
            {"name_value": "*.example.com"},
        ]).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_crtsh()

        subdomains = [r[0] for r in sd.results]
        assert "example.com" in subdomains
        assert "*.example.com" not in subdomains

    def test_network_error_handled_gracefully(self):
        with patch("urllib.request.urlopen", side_effect=URLError("timeout")):
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_crtsh()  # should not raise
        assert len(sd.results) == 0

    def test_source_tagged_as_crtsh(self):
        fake_response = json.dumps([
            {"name_value": "api.example.com"},
        ]).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_crtsh()

        sources = [r[1] for r in sd.results if r[0] == "api.example.com"]
        assert sources[0] == "crt.sh"


@pytest.mark.unit
class TestDiscoveryAggregation:
    """Tests for combined multi-tool result aggregation."""

    def test_results_aggregated_across_tools(self, mock_subprocess_success):
        """Results from all tools should be combined."""
        fake_crt = json.dumps([{"name_value": "mail.example.com"}]).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_crt
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_subfinder()
            sd._run_assetfinder()
            sd._run_crtsh()

        subdomains = sd.get_subdomains()
        assert "sub1.example.com" in subdomains  # from subprocess mock
        assert "mail.example.com" in subdomains  # from crt.sh mock

    def test_get_subdomains_returns_unique_list(self):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd.results.add(("api.example.com", "subfinder"))
        sd.results.add(("api.example.com", "assetfinder"))  # same domain, different source
        sd.results.add(("admin.example.com", "subfinder"))

        unique = sd.get_subdomains()
        assert unique.count("api.example.com") == 1
        assert len(unique) == 2

    def test_run_continues_if_one_tool_fails(self):
        """If subfinder fails, assetfinder and crt.sh should still run."""
        import subprocess

        call_count = {"count": 0}

        def side_effect(cmd, **kwargs):
            # First call (subfinder) raises FileNotFoundError
            if call_count["count"] == 0:
                call_count["count"] += 1
                raise FileNotFoundError("subfinder not found")
            # Second call (assetfinder) succeeds
            call_count["count"] += 1
            return MagicMock(returncode=0, stdout="api.example.com\n", stderr="")

        fake_crt = json.dumps([]).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_crt
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("subprocess.run", side_effect=side_effect), \
             patch("urllib.request.urlopen", return_value=mock_resp):
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_subfinder()
            sd._run_assetfinder()

        assert ("api.example.com", "assetfinder") in sd.results


@pytest.mark.unit
class TestExecuteHelper:
    """Tests for the internal _execute() helper method."""

    def test_returns_stdout_on_success(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="hello\n", stderr="")
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            result = sd._execute(["echo", "hello"], "test-tool")
        assert result == "hello\n"

    def test_returns_empty_on_file_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            result = sd._execute(["missing-tool"], "missing-tool")
        assert result == ""

    def test_returns_empty_on_timeout(self):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="tool", timeout=300)):
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            result = sd._execute(["slow-tool"], "slow-tool")
        assert result == ""

    def test_still_returns_stdout_on_nonzero_exit(self):
        """Even if tool returns non-zero, any stdout should be returned."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="partial-output\n", stderr="some error"
            )
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            result = sd._execute(["tool"], "tool")
        assert result == "partial-output\n"


@pytest.mark.unit
class TestAmassIntegration:
    """Tests for the amass runner."""

    def test_parses_plain_text_output(self, mock_subprocess_success):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd._run_amass()
        assert ("sub1.example.com", "amass") in sd.results
        assert ("sub2.example.com", "amass") in sd.results

    def test_source_tagged_as_amass(self, mock_subprocess_success):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd._run_amass()
        sources = [r[1] for r in sd.results]
        assert all(s == "amass" for s in sources)

    def test_skips_unrelated_domains(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="api.example.com\nunrelated.net\n", stderr=""
            )
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_amass()
        assert all("example.com" in r[0] for r in sd.results)

    def test_tool_not_found_handled(self, mock_subprocess_failure):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd._run_amass()  # should not raise
        assert len(sd.results) == 0

    def test_normalizes_to_lowercase(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="VPN.EXAMPLE.COM\n", stderr=""
            )
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_amass()
        assert ("vpn.example.com", "amass") in sd.results

    def test_timeout_returns_empty(self):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="amass", timeout=300)):
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_amass()
        assert len(sd.results) == 0


@pytest.mark.unit
class TestFinddomainIntegration:
    """Tests for the findomain runner."""

    def test_parses_plain_text_output(self, mock_subprocess_success):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd._run_findomain()
        assert ("sub1.example.com", "findomain") in sd.results
        assert ("sub2.example.com", "findomain") in sd.results

    def test_source_tagged_as_findomain(self, mock_subprocess_success):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd._run_findomain()
        sources = [r[1] for r in sd.results]
        assert all(s == "findomain" for s in sources)

    def test_skips_unrelated_domains(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="api.example.com\nothersite.io\n", stderr=""
            )
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_findomain()
        assert all("example.com" in r[0] for r in sd.results)

    def test_tool_not_found_handled(self, mock_subprocess_failure):
        from backend.modules.discovery import SubdomainDiscovery
        sd = SubdomainDiscovery("example.com", "scan-123")
        sd._run_findomain()  # should not raise
        assert len(sd.results) == 0

    def test_normalizes_to_lowercase(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="MAIL.EXAMPLE.COM\n", stderr=""
            )
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_findomain()
        assert ("mail.example.com", "findomain") in sd.results

    def test_timeout_returns_empty(self):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="findomain", timeout=300)):
            from backend.modules.discovery import SubdomainDiscovery
            sd = SubdomainDiscovery("example.com", "scan-123")
            sd._run_findomain()
        assert len(sd.results) == 0
