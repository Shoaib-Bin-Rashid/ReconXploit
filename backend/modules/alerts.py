"""
ReconXploit - Alerts Module
Phase 7b: Send notifications when significant findings are detected.

Supports:
  Telegram  — Bot API (sendMessage)
  Discord   — Webhook POST
  Slack     — Webhook POST

Triggered by:
  - Significant changes from Phase 6 (new_sensitive_port, new_js_secret, etc.)
  - New critical/high vulnerabilities
  - Risk score above threshold

Config (config/settings.yaml):
  notifications:
    telegram:  { enabled: true, bot_token: "...", chat_id: "..." }
    discord:   { enabled: true, webhook_url: "..." }
    slack:     { enabled: true, webhook_url: "..." }
"""

import json
import logging
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Risk score threshold to trigger an alert
ALERT_SCORE_THRESHOLD = 40

# Max findings to list in one alert message
MAX_FINDINGS_IN_MSG = 10


class AlertManager:
    """
    Sends alerts to configured channels when significant findings are detected.
    """

    def __init__(self, domain: str, scan_id: str):
        self.domain  = domain
        self.scan_id = scan_id
        self._config = self._load_config()
        self.sent: List[Dict] = []   # log of sent alerts

    # ─────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────

    def run(
        self,
        risk_score:  int,
        scan_data:   Dict,
        changes:     List[Dict],
    ) -> int:
        """
        Evaluate findings and send alerts if warranted.

        Args:
            risk_score:  overall score from RiskScorer (0-100)
            scan_data:   { subdomains, live_hosts, ports, vulnerabilities, js_findings }
            changes:     list of change dicts from ChangeDetector

        Returns:
            Number of alert messages sent.
        """
        sig_changes  = [c for c in changes if c.get("is_significant")]
        critical_vulns = [
            v for v in scan_data.get("vulnerabilities", [])
            if v.get("severity") == "critical"
        ]
        high_vulns = [
            v for v in scan_data.get("vulnerabilities", [])
            if v.get("severity") == "high"
        ]
        js_secrets = [
            f for f in scan_data.get("js_findings", [])
            if f.get("secret_type")
        ]

        # Decide if we should alert
        should_alert = (
            risk_score >= ALERT_SCORE_THRESHOLD
            or sig_changes
            or critical_vulns
            or js_secrets
        )

        if not should_alert:
            logger.info(f"[Phase 7b] No significant findings — no alert sent for {self.domain}")
            return 0

        # Build message
        message = self._build_message(
            risk_score, scan_data, sig_changes,
            critical_vulns, high_vulns, js_secrets,
        )

        # Send to all enabled channels
        sent = 0
        if self._is_enabled("telegram"):
            if self._send_telegram(message):
                sent += 1
        if self._is_enabled("discord"):
            if self._send_discord(message):
                sent += 1
        if self._is_enabled("slack"):
            if self._send_slack(message):
                sent += 1

        if sent == 0:
            logger.info("[Phase 7b] No alert channels configured — skipping")
        else:
            logger.info(f"[Phase 7b] Alert sent to {sent} channel(s) for {self.domain}")

        # Store to DB
        self._store_alert(message, risk_score, sent)

        return sent

    def get_sent(self) -> List[Dict]:
        return self.sent

    # ─────────────────────────────────────────────────
    # MESSAGE BUILDER
    # ─────────────────────────────────────────────────

    def _build_message(
        self,
        risk_score:    int,
        scan_data:     Dict,
        sig_changes:   List[Dict],
        critical_vulns: List[Dict],
        high_vulns:    List[Dict],
        js_secrets:    List[Dict],
    ) -> str:
        label = self._risk_label(risk_score)
        now   = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        lines = [
            f"🚨 ReconXploit Alert",
            f"",
            f"🎯 Target:      {self.domain}",
            f"📊 Risk Score:  {risk_score}/100  [{label}]",
            f"🕐 Time:        {now}",
            f"",
        ]

        # Significant changes
        if sig_changes:
            lines.append(f"⚠️  SIGNIFICANT CHANGES ({len(sig_changes)}):")
            icons = {
                "new_vulnerability_critical": "🔴",
                "new_vulnerability_high":     "🟠",
                "new_sensitive_port":         "🔌",
                "new_js_secret":              "🔑",
                "new_admin_endpoint":         "🛡",
                "new_debug_endpoint":         "🐛",
                "new_s3_bucket":              "🪣",
                "waf_removed":                "🛡❌",
            }
            for c in sig_changes[:MAX_FINDINGS_IN_MSG]:
                icon = icons.get(c["change_type"], "⚡")
                lines.append(f"  {icon} [{c['severity'].upper()}] {c['change_type']}")
                lines.append(f"     → {c['asset_id']}")
            if len(sig_changes) > MAX_FINDINGS_IN_MSG:
                lines.append(f"  ... and {len(sig_changes) - MAX_FINDINGS_IN_MSG} more")
            lines.append("")

        # Critical vulns
        if critical_vulns:
            lines.append(f"💣 CRITICAL VULNERABILITIES ({len(critical_vulns)}):")
            for v in critical_vulns[:5]:
                name = v.get("vulnerability_name") or v.get("name", "Unknown")
                cve  = v.get("cve_id", "")
                url  = v.get("matched_at") or v.get("url", "")
                cve_str = f" [{cve}]" if cve else ""
                lines.append(f"  🔴 {name}{cve_str}")
                if url:
                    lines.append(f"     → {url}")
            lines.append("")

        # High vulns (summary only)
        if high_vulns:
            lines.append(f"🟠 HIGH vulnerabilities: {len(high_vulns)}")
            lines.append("")

        # JS Secrets
        if js_secrets:
            lines.append(f"🔑 SECRETS FOUND IN JS ({len(js_secrets)}):")
            seen_types: set = set()
            for s in js_secrets[:5]:
                stype = s.get("secret_type") or s.get("finding_type", "unknown")
                if stype not in seen_types:
                    seen_types.add(stype)
                    lines.append(f"  ⚠️  {stype.replace('_', ' ').upper()}")
            lines.append("")

        # Summary stats
        lines.append("📈 Scan Summary:")
        lines.append(f"  Subdomains:  {len(scan_data.get('subdomains', []))}")
        lines.append(f"  Live hosts:  {len(scan_data.get('live_hosts', []))}")
        lines.append(f"  Open ports:  {len(scan_data.get('ports', []))}")
        vulns = scan_data.get("vulnerabilities", [])
        sev_counts = {}
        for v in vulns:
            s = v.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        vuln_str = ", ".join(f"{c} {s}" for s, c in sorted(sev_counts.items()))
        lines.append(f"  Vulns:       {len(vulns)} ({vuln_str or 'none'})")
        lines.append(f"  JS findings: {len(scan_data.get('js_findings', []))}")
        lines.append("")
        lines.append(f"📁 Results: data/ folder")

        return "\n".join(lines)

    @staticmethod
    def _risk_label(score: int) -> str:
        if score >= 80: return "🔴 CRITICAL"
        if score >= 60: return "🟠 HIGH"
        if score >= 40: return "🟡 MEDIUM"
        if score >= 20: return "🟢 LOW"
        return "⚪ INFO"

    # ─────────────────────────────────────────────────
    # CHANNEL SENDERS
    # ─────────────────────────────────────────────────

    def _send_telegram(self, message: str) -> bool:
        """Send message via Telegram Bot API."""
        try:
            token   = self._config.get("telegram", {}).get("bot_token", "")
            chat_id = self._config.get("telegram", {}).get("chat_id", "")
            if not token or not chat_id:
                logger.warning("[Phase 7b] Telegram bot_token or chat_id not set")
                return False

            url  = f"https://api.telegram.org/bot{token}/sendMessage"
            data = json.dumps({
                "chat_id":    chat_id,
                "text":       message,
                "parse_mode": "Markdown",
            }).encode("utf-8")

            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
                if result.get("ok"):
                    logger.info("[Phase 7b] Telegram alert sent ✓")
                    return True
                logger.warning(f"[Phase 7b] Telegram error: {result}")
                return False
        except Exception as e:
            logger.warning(f"[Phase 7b] Telegram send error: {e}")
            return False

    def _send_discord(self, message: str) -> bool:
        """Send message to Discord webhook."""
        try:
            webhook_url = self._config.get("discord", {}).get("webhook_url", "")
            if not webhook_url:
                return False

            data = json.dumps({
                "content":  f"```\n{message}\n```",
                "username": "ReconXploit",
            }).encode("utf-8")

            req = urllib.request.Request(
                webhook_url, data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                logger.info("[Phase 7b] Discord alert sent ✓")
                return True
        except Exception as e:
            logger.warning(f"[Phase 7b] Discord send error: {e}")
            return False

    def _send_slack(self, message: str) -> bool:
        """Send message to Slack webhook."""
        try:
            webhook_url = self._config.get("slack", {}).get("webhook_url", "")
            if not webhook_url:
                return False

            data = json.dumps({
                "text": f"*ReconXploit Alert*\n```{message}```",
            }).encode("utf-8")

            req = urllib.request.Request(
                webhook_url, data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                logger.info("[Phase 7b] Slack alert sent ✓")
                return True
        except Exception as e:
            logger.warning(f"[Phase 7b] Slack send error: {e}")
            return False

    # ─────────────────────────────────────────────────
    # CONFIG + DB
    # ─────────────────────────────────────────────────

    def _is_enabled(self, channel: str) -> bool:
        return bool(self._config.get(channel, {}).get("enabled", False))

    def _load_config(self) -> Dict:
        """Load notification config from settings."""
        try:
            from backend.core.config import settings
            notif = getattr(settings, "notifications", None)
            if notif and isinstance(notif, dict):
                return notif
        except Exception:
            pass
        return {}

    def _store_alert(self, message: str, risk_score: int, channels_sent: int) -> None:
        """Store alert record in the alerts table."""
        try:
            from backend.models.models import Alert, Target
            with get_db_context() as session:
                target = session.query(Target).filter(Target.domain == self.domain).first()
                if not target:
                    return
                alert = Alert(
                    target_id  = target.id,
                    scan_id    = self.scan_id,
                    alert_type = "scan_findings",
                    title      = f"ReconXploit Alert — {self.domain} (score: {risk_score})",
                    message    = message[:2000],
                    severity   = "critical" if risk_score >= 80 else
                                 "high"     if risk_score >= 60 else
                                 "medium"   if risk_score >= 40 else "low",
                    channels   = [c for c in ["telegram", "discord", "slack"]
                                  if self._is_enabled(c)],
                    status     = "sent" if channels_sent > 0 else "pending",
                )
                session.add(alert)
                session.commit()
        except Exception as e:
            logger.debug(f"[Phase 7b] DB store alert: {e}")


# Import needed for _store_alert
from backend.models.database import get_db_context  # noqa: E402
