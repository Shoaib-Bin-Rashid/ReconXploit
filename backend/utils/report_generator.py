"""
ReconXploit - HTML Report Generator
Generates a standalone, beautiful HTML report from scan data.
"""

import json
from pathlib import Path
from datetime import datetime
from jinja2 import Template

def generate_html_report(domain: str, scan_id: str, scan_data: dict) -> Path:
    """
    Generate a standalone HTML report for the scan.
    """
    from backend.core.config import settings
    
    report_dir = settings.base_path / "data" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    filepath = report_dir / f"{domain}_{scan_id[:8]}.html"
    
    # Prepare data for the template
    summary = {
        "domain": domain,
        "scan_id": scan_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains_count": len(scan_data.get("subdomains", [])),
        "live_hosts_count": len(scan_data.get("live_hosts", [])),
        "ports_count": len(scan_data.get("ports", [])),
        "vulns_count": len(scan_data.get("vulnerabilities", [])),
        "js_findings_count": len(scan_data.get("js_findings", [])),
        "risk_score": scan_data.get("risk_score", 0),
    }
    
    # Calculate severity breakdown
    vulns = scan_data.get("vulnerabilities", [])
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev = v.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        summary=summary,
        severity_counts=severity_counts,
        scan_data=scan_data,
        domain=domain
    )
    
    filepath.write_text(html_content, encoding="utf-8")
    return filepath

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconXploit Report - {{ domain }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #f1f5f9; }
        .card { background-color: #1e293b; border: 1px border #334155; border-radius: 0.75rem; }
        .severity-critical { border-left: 4px solid #ef4444; }
        .severity-high { border-left: 4px solid #f97316; }
        .severity-medium { border-left: 4px solid #eab308; }
        .severity-low { border-left: 4px solid #22c55e; }
        .severity-info { border-left: 4px solid #3b82f6; }
    </style>
</head>
<body class="p-4 md:p-8">
    <div class="max-w-7xl mx-auto">
        <!-- Header -->
        <header class="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
            <div>
                <h1 class="text-3xl font-bold text-white flex items-center gap-3">
                    <i class="fas fa-crosshair text-cyan-400"></i>
                    ReconXploit Report
                </h1>
                <p class="text-slate-400 mt-1">Target: <span class="text-cyan-400 font-mono">{{ domain }}</span></p>
            </div>
            <div class="text-right">
                <p class="text-sm text-slate-400">Scan ID: <span class="font-mono">{{ summary.scan_id }}</span></p>
                <p class="text-sm text-slate-400">Generated: {{ summary.timestamp }}</p>
            </div>
        </header>

        <!-- Stats Overview -->
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
            <div class="card p-4 text-center">
                <p class="text-slate-400 text-xs uppercase font-semibold mb-1">Subdomains</p>
                <p class="text-2xl font-bold text-white">{{ summary.subdomains_count }}</p>
            </div>
            <div class="card p-4 text-center">
                <p class="text-slate-400 text-xs uppercase font-semibold mb-1">Live Hosts</p>
                <p class="text-2xl font-bold text-green-400">{{ summary.live_hosts_count }}</p>
            </div>
            <div class="card p-4 text-center">
                <p class="text-slate-400 text-xs uppercase font-semibold mb-1">Open Ports</p>
                <p class="text-2xl font-bold text-cyan-400">{{ summary.ports_count }}</p>
            </div>
            <div class="card p-4 text-center">
                <p class="text-slate-400 text-xs uppercase font-semibold mb-1">Vulns</p>
                <p class="text-2xl font-bold text-red-400">{{ summary.vulns_count }}</p>
            </div>
            <div class="card p-4 text-center">
                <p class="text-slate-400 text-xs uppercase font-semibold mb-1">JS Findings</p>
                <p class="text-2xl font-bold text-yellow-400">{{ summary.js_findings_count }}</p>
            </div>
            <div class="card p-4 text-center">
                <p class="text-slate-400 text-xs uppercase font-semibold mb-1">Risk Score</p>
                <p class="text-2xl font-bold {% if summary.risk_score >= 70 %}text-red-500{% elif summary.risk_score >= 40 %}text-yellow-500{% else %}text-green-500{% endif %}">
                    {{ summary.risk_score }}/100
                </p>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
            <!-- Severity Chart -->
            <div class="card p-6 lg:col-span-1">
                <h2 class="text-lg font-bold mb-4">Vulnerability Severity</h2>
                <canvas id="severityChart" height="200"></canvas>
            </div>

            <!-- Top Findings -->
            <div class="card p-6 lg:col-span-2">
                <h2 class="text-lg font-bold mb-4">Top Findings</h2>
                <div class="space-y-3">
                    {% for v in scan_data.vulnerabilities[:5] %}
                    <div class="p-3 bg-slate-800/50 rounded-lg severity-{{ v.severity.lower() }}">
                        <div class="flex justify-between items-center">
                            <span class="font-semibold text-sm">{{ v.name }}</span>
                            <span class="text-[10px] px-2 py-0.5 rounded uppercase font-bold 
                                {% if v.severity.lower() == 'critical' %}bg-red-900 text-red-200
                                {% elif v.severity.lower() == 'high' %}bg-orange-900 text-orange-200
                                {% elif v.severity.lower() == 'medium' %}bg-yellow-900 text-yellow-200
                                {% else %}bg-blue-900 text-blue-200{% endif %}">
                                {{ v.severity }}
                            </span>
                        </div>
                        <p class="text-xs text-slate-400 mt-1 truncate">{{ v.matched_at or v.url }}</p>
                    </div>
                    {% endfor %}
                    {% if not scan_data.vulnerabilities %}
                    <p class="text-slate-500 text-sm italic">No vulnerabilities found.</p>
                    {% endif %}
                </div>
            </div>
        </div>

        <!-- Detailed Sections -->
        <div class="space-y-8">
            <!-- Ports & Services -->
            <section id="ports">
                <h2 class="text-xl font-bold mb-4 flex items-center gap-2">
                    <i class="fas fa-plug text-cyan-400"></i> Open Ports & Services
                </h2>
                <div class="card overflow-hidden">
                    <table class="w-full text-left text-sm">
                        <thead class="bg-slate-800 text-slate-300 uppercase text-[10px] font-bold">
                            <tr>
                                <th class="px-6 py-3">Host</th>
                                <th class="px-6 py-3">Port</th>
                                <th class="px-6 py-3">Service</th>
                                <th class="px-6 py-3">Version</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-700">
                            {% for p in scan_data.ports %}
                            <tr class="hover:bg-slate-800/50 transition-colors">
                                <td class="px-6 py-4 font-mono text-slate-300">{{ p.ip or p.host }}</td>
                                <td class="px-6 py-4"><span class="px-2 py-1 bg-cyan-900/30 text-cyan-400 rounded">{{ p.port }}/{{ p.protocol }}</span></td>
                                <td class="px-6 py-4 text-white font-medium">{{ p.service }}</td>
                                <td class="px-6 py-4 text-slate-400">{{ p.version }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <!-- Live Hosts -->
            <section id="hosts">
                <h2 class="text-xl font-bold mb-4 flex items-center gap-2">
                    <i class="fas fa-globe text-green-400"></i> Live Hosts
                </h2>
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {% for h in scan_data.live_hosts %}
                    <div class="card p-4 hover:border-slate-500 transition-all">
                        <div class="flex justify-between items-start mb-2">
                            <span class="text-xs px-2 py-0.5 bg-green-900/30 text-green-400 rounded font-bold">{{ h.status_code }}</span>
                            <span class="text-[10px] text-slate-500 font-mono">{{ h.ip }}</span>
                        </div>
                        <h3 class="font-bold text-white truncate text-sm mb-1">{{ h.url }}</h3>
                        <p class="text-xs text-slate-400 italic truncate">{{ h.title or "No Title" }}</p>
                        <div class="mt-3 flex flex-wrap gap-1">
                            {% if h.waf %}<span class="text-[9px] px-1.5 py-0.5 bg-red-900/20 text-red-400 border border-red-900/30 rounded">WAF: {{ h.waf }}</span>{% endif %}
                            {% if h.cdn %}<span class="text-[9px] px-1.5 py-0.5 bg-blue-900/20 text-blue-400 border border-blue-900/30 rounded">CDN: {{ h.cdn }}</span>{% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </section>
        </div>

        <!-- Footer -->
        <footer class="mt-16 pt-8 border-t border-slate-800 text-center text-slate-500 text-xs">
            Generated by ReconXploit v0.1.0 — Bug Bounty Intelligence Engine
        </footer>
    </div>

    <script>
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [
                        {{ severity_counts.critical }}, 
                        {{ severity_counts.high }}, 
                        {{ severity_counts.medium }}, 
                        {{ severity_counts.low }}, 
                        {{ severity_counts.info }}
                    ],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'],
                    borderWidth: 0
                }]
            },
            options: {
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 12, padding: 15 } }
                },
                cutout: '70%'
            }
        });
    </script>
</body>
</html>
"""
