"""
ReconXploit - Port & Service Scanning Module
Phase 3: Discover open ports and identify running services.

Two-stage scan:
  Stage 1 - naabu: fast port discovery across all IPs
            (if not installed, falls back to nmap directly)
  Stage 2 - nmap:  service/version detection on discovered open ports

Sensitive port detection:
  SSH, FTP, Telnet, databases, Redis, Elasticsearch, etc.
  These are flagged is_sensitive=True for priority review.

Output:
  - Stored in ports DB table
  - Saved to data/ports/{domain}.txt
"""

import subprocess
import logging
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Set

from backend.core.config import settings
from backend.models.database import get_db_context
from backend.utils.file_storage import save_ports

logger = logging.getLogger(__name__)

# Ports that always get flagged as sensitive
SENSITIVE_PORTS: Set[int] = {
    21, 22, 23,           # FTP, SSH, Telnet
    25, 110, 143,         # Mail
    3306, 5432, 1433,     # MySQL, PostgreSQL, MSSQL
    1521, 27017, 6379,    # Oracle, MongoDB, Redis
    9200, 5601, 8500,     # Elasticsearch, Kibana, Consul
    2375, 2376,           # Docker
    5900, 5901,           # VNC
    11211,                # Memcached
    4848, 8161,           # GlassFish, ActiveMQ
}

# Ports to scan in full/deep mode
TOP_PORTS_QUICK = "21,22,23,25,80,443,8080,8443,3000,5000,8000,8888,9000,3306,5432,6379,27017,9200"
TOP_PORTS_FULL  = "1-10000"
TOP_PORTS_DEEP  = "1-65535"


class PortScanner:
    """
    Runs naabu (fast) then nmap (deep) against live hosts.
    """

    def __init__(self, domain: str, scan_id: str):
        self.domain = domain
        self.scan_id = scan_id
        self.results: List[Dict] = []

    def run(self, live_hosts: List[Dict], mode: str = "full") -> int:
        """
        Scan all live hosts for open ports.

        Args:
            live_hosts: list of dicts from Phase 2 (must have 'ip' key)
            mode:       quick / full / deep (controls port range)

        Returns:
            count of open ports found
        """
        ips = self._extract_ips(live_hosts)
        if not ips:
            logger.warning("No IPs to scan in Phase 3")
            return 0

        logger.info(f"Starting port scan on {len(ips)} IPs for {self.domain} (mode={mode})")

        port_range = self._get_port_range(mode)

        # Stage 1: naabu fast discovery (optional)
        open_ports_by_ip = self._run_naabu(ips, port_range)

        # Stage 2: nmap service detection
        if open_ports_by_ip:
            self.results = self._run_nmap_targeted(open_ports_by_ip)
        else:
            # naabu not available or found nothing — run nmap directly
            self.results = self._run_nmap_direct(ips, port_range)

        self._mark_sensitive()
        count = self._store_results()
        save_ports(self.domain, self.results)
        logger.info(f"Port scan complete: {count} open ports for {self.domain}")
        return count

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────

    def _extract_ips(self, live_hosts: List[Dict]) -> List[str]:
        """Extract unique IPs from Phase 2 live host results."""
        seen = set()
        ips = []
        for h in live_hosts:
            ip = (h.get("ip") or "").strip()
            if ip and ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips

    def _get_port_range(self, mode: str) -> str:
        if mode == "quick":
            return TOP_PORTS_QUICK
        elif mode == "deep":
            return TOP_PORTS_DEEP
        else:
            return TOP_PORTS_FULL

    def _mark_sensitive(self):
        """Flag ports that match the sensitive port list."""
        for result in self.results:
            result["is_sensitive"] = result.get("port") in SENSITIVE_PORTS

    # ─────────────────────────────────────────────
    # STAGE 1 — NAABU (fast port discovery)
    # ─────────────────────────────────────────────

    def _run_naabu(self, ips: List[str], port_range: str) -> Dict[str, List[int]]:
        """
        Run naabu for fast port discovery.
        Returns dict of {ip: [port, port, ...]} for open ports.
        Returns empty dict if naabu not installed.
        """
        cmd = [
            settings.tool_naabu,
            "-p", port_range,
            "-silent",
            "-json",
            "-rate", "1000",
            "-timeout", "5",
        ]
        stdin_data = "\n".join(ips)

        try:
            result = subprocess.run(
                cmd,
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=300,
            )
            return self._parse_naabu_output(result.stdout)

        except FileNotFoundError:
            logger.info("naabu not found — falling back to nmap direct scan")
            return {}
        except subprocess.TimeoutExpired:
            logger.warning("naabu timed out after 300s")
            return {}

    def _parse_naabu_output(self, raw: str) -> Dict[str, List[int]]:
        """Parse naabu JSON output. Returns {ip: [ports]}."""
        result: Dict[str, List[int]] = {}
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                ip = data.get("ip", "").strip()
                port = data.get("port", 0)
                if ip and port:
                    result.setdefault(ip, []).append(int(port))
            except (json.JSONDecodeError, ValueError):
                # naabu sometimes outputs "ip:port" plain text
                if ":" in line:
                    parts = line.split(":")
                    if len(parts) == 2:
                        ip, port_str = parts[0].strip(), parts[1].strip()
                        try:
                            result.setdefault(ip, []).append(int(port_str))
                        except ValueError:
                            pass
        return result

    # ─────────────────────────────────────────────
    # STAGE 2A — NMAP targeted (after naabu)
    # ─────────────────────────────────────────────

    def _run_nmap_targeted(self, open_ports_by_ip: Dict[str, List[int]]) -> List[Dict]:
        """
        Run nmap service detection only on ports naabu found open.
        Much faster than scanning all ports with nmap.
        """
        all_results = []
        for ip, ports in open_ports_by_ip.items():
            port_str = ",".join(str(p) for p in sorted(ports))
            cmd = [
                settings.tool_nmap,
                "-p", port_str,
                "-sV",          # service/version detection
                "--open",
                "-oX", "-",     # XML output to stdout
                "--host-timeout", "60s",
                ip,
            ]
            raw_xml = self._execute_nmap(cmd, ip)
            all_results.extend(self._parse_nmap_xml(raw_xml))
        return all_results

    # ─────────────────────────────────────────────
    # STAGE 2B — NMAP direct (no naabu)
    # ─────────────────────────────────────────────

    def _run_nmap_direct(self, ips: List[str], port_range: str) -> List[Dict]:
        """
        Run nmap directly when naabu is not available.
        Uses -F (fast) for reasonable speed.
        """
        all_results = []
        for ip in ips:
            cmd = [
                settings.tool_nmap,
                "-p", port_range,
                "-sV",
                "--open",
                "-oX", "-",
                "--host-timeout", "120s",
                ip,
            ]
            raw_xml = self._execute_nmap(cmd, ip)
            all_results.extend(self._parse_nmap_xml(raw_xml))
        return all_results

    def _execute_nmap(self, cmd: List[str], target: str) -> str:
        """Execute an nmap command and return stdout XML."""
        logger.debug(f"nmap: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0 and result.stderr:
                logger.warning(f"nmap stderr for {target}: {result.stderr[:200]}")
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.warning(f"nmap timed out for {target}")
            return ""
        except FileNotFoundError:
            logger.warning("nmap not found in PATH. Install: brew install nmap")
            return ""

    # ─────────────────────────────────────────────
    # NMAP XML PARSER
    # ─────────────────────────────────────────────

    def _parse_nmap_xml(self, xml_output: str) -> List[Dict]:
        """Parse nmap XML output into list of port dicts."""
        results = []
        if not xml_output.strip():
            return results

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            logger.warning(f"Failed to parse nmap XML: {e}")
            return results

        for host in root.findall("host"):
            # Get IP
            ip = ""
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")
                    break

            if not ip:
                continue

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None:
                    continue
                state = state_elem.get("state", "")
                if state != "open":
                    continue

                port_num = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")

                service_elem = port_elem.find("service")
                service_name = ""
                service_version = ""
                banner = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    extra = service_elem.get("extrainfo", "")
                    parts = [p for p in [product, version, extra] if p]
                    service_version = " ".join(parts)
                    banner = service_elem.get("servicefp", "")

                results.append({
                    "ip": ip,
                    "port": port_num,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "version": service_version,
                    "banner": banner,
                    "is_sensitive": False,  # set later by _mark_sensitive
                })

        return results

    # ─────────────────────────────────────────────
    # DATABASE STORAGE
    # ─────────────────────────────────────────────

    def _store_results(self) -> int:
        """Store open ports in the database. Returns count stored."""
        if not self.results:
            return 0

        try:
            from backend.models.models import Port
        except Exception as e:
            logger.warning(f"DB import failed, skipping DB store: {e}")
            return len(self.results)

        stored = 0
        try:
            with get_db_context() as db:
                for p in self.results:
                    existing = db.query(Port).filter(
                        Port.scan_id == self.scan_id,
                        Port.ip_address == p["ip"],
                        Port.port == p["port"],
                        Port.protocol == p["protocol"],
                    ).first()

                    if not existing:
                        record = Port(
                            scan_id=self.scan_id,
                            ip_address=p["ip"],
                            port=p["port"],
                            protocol=p["protocol"],
                            state=p.get("state", "open"),
                            service_name=p.get("service", ""),
                            service_version=p.get("version", ""),
                            banner=p.get("banner", ""),
                            is_sensitive=p.get("is_sensitive", False),
                            first_seen=datetime.utcnow(),
                            last_seen=datetime.utcnow(),
                        )
                        db.add(record)
                        stored += 1
                    else:
                        existing.last_seen = datetime.utcnow()
                        existing.service_version = p.get("version", "")
        except Exception as e:
            logger.warning(f"DB store failed: {e}. Results still saved to file.")
            return len(self.results)

        return stored

    # ─────────────────────────────────────────────
    # ACCESSORS
    # ─────────────────────────────────────────────

    def get_results(self) -> List[Dict]:
        return self.results

    def get_sensitive_ports(self) -> List[Dict]:
        return [p for p in self.results if p.get("is_sensitive")]

    def get_open_ports_summary(self) -> Dict[str, List[int]]:
        """Returns {ip: [open_port_numbers]} summary."""
        summary: Dict[str, List[int]] = {}
        for p in self.results:
            summary.setdefault(p["ip"], []).append(p["port"])
        return summary
