"use client";
import { useEffect, useState } from "react";
import { api, Vuln } from "@/lib/api";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { Table } from "@/components/ui/Table";
import { LoadingSpinner, ErrorBanner } from "@/components/DashboardOverview";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export function VulnsSection() {
  const [vulns,    setVulns]    = useState<Vuln[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState<string | null>(null);
  const [severity, setSeverity] = useState("");
  const [domain,   setDomain]   = useState("");

  const load = () => {
    setLoading(true);
    api.vulns.list({ severity: severity || undefined, domain: domain || undefined, limit: 100 })
      .then(setVulns)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [severity, domain]);

  return (
    <div className="space-y-5">
      {error && <ErrorBanner message={error} />}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="Filter by domain…"
          className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-cyan-600"
        />
        <div className="flex gap-1.5">
          <button
            onClick={() => setSeverity("")}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              severity === "" ? "bg-gray-700 text-white" : "text-gray-400 hover:text-gray-200"
            }`}
          >
            All
          </button>
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(s === severity ? "" : s)}
              className={`px-3 py-1 rounded text-xs font-medium capitalize transition-colors ${
                severity === s ? "bg-gray-700 text-white" : "text-gray-500 hover:text-gray-200"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        <span className="text-xs text-gray-500 ml-auto">{vulns.length} results</span>
      </div>

      {loading ? <LoadingSpinner /> : (
        <Table
          columns={[
            { key: "severity",    label: "Severity", render: (v) => <SeverityBadge severity={v.severity} /> },
            { key: "name",        label: "Name",     render: (v) => <span className="font-medium text-gray-200">{v.name ?? v.template_id ?? "—"}</span> },
            { key: "domain",      label: "Domain" },
            { key: "url",         label: "URL",      render: (v) => v.url ? <a href={v.url} target="_blank" className="text-cyan-400 hover:underline font-mono text-xs truncate max-w-xs block">{v.url}</a> : <span className="text-gray-500">—</span> },
            { key: "first_seen",  label: "Found",    render: (v) => v.first_seen ? new Date(v.first_seen).toLocaleDateString() : "—" },
          ]}
          data={vulns}
          emptyText="No vulnerabilities found."
        />
      )}
    </div>
  );
}
