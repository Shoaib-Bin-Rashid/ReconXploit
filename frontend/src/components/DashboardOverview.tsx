"use client";
import React from "react";
import { useEffect, useState } from "react";
import { api, Overview, RiskItem, ChangeItem } from "@/lib/api";
import { StatCard } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import {
  Globe, Shield, AlertTriangle, Activity, Target, Zap
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const SEVERITY_BAR_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#60a5fa",
  info:     "#6b7280",
};

export function DashboardOverview() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [risks, setRisks]       = useState<RiskItem[]>([]);
  const [changes, setChanges]   = useState<ChangeItem[]>([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      api.dashboard.overview(),
      api.dashboard.topRisks(8),
      api.dashboard.recentChanges(10),
    ])
      .then(([ov, r, ch]) => { setOverview(ov); setRisks(r); setChanges(ch); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <LoadingSpinner />;
  if (error)   return <ErrorBanner message={error} />;
  if (!overview) return null;

  const barData = Object.entries(
    risks.reduce<Record<string, number>>((acc, r) => {
      acc[r.label] = (acc[r.label] ?? 0) + 1;
      return acc;
    }, {})
  ).map(([name, count]) => ({ name, count }));

  return (
    <div className="space-y-6">
      {/* ── Stat cards ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard title="Targets"       value={overview.total_targets}   icon={<Target size={18}/>}        color="text-cyan-400" />
        <StatCard title="Subdomains"    value={overview.total_subdomains} icon={<Globe size={18}/>}         color="text-blue-400" />
        <StatCard title="Live Hosts"    value={overview.live_hosts}       icon={<Activity size={18}/>}      color="text-green-400" />
        <StatCard title="Total Vulns"   value={overview.total_vulns}      icon={<Shield size={18}/>}        color="text-yellow-400" />
        <StatCard title="Critical"      value={overview.critical_vulns}   icon={<AlertTriangle size={18}/>} color="text-red-400" />
        <StatCard title="Scans Today"   value={overview.scans_today}      icon={<Zap size={18}/>}           color="text-purple-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ── Risk distribution ──────────────────────────────────────── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">Risk Distribution</h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={barData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fill: "#9ca3af", fontSize: 11 }} />
              <YAxis tick={{ fill: "#9ca3af", fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", color: "#f3f4f6" }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {barData.map((entry, i) => (
                  <Cell key={i} fill={SEVERITY_BAR_COLORS[entry.name.toLowerCase()] ?? "#6b7280"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* ── Top risks table ───────────────────────────────────────── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-4">Top Risk Targets</h3>
          <div className="space-y-2">
            {risks.slice(0, 6).map((r) => (
              <div key={r.domain} className="flex items-center justify-between text-sm">
                <span className="text-gray-300 truncate max-w-[55%]">{r.domain}</span>
                <div className="flex items-center gap-3">
                  <span className="text-gray-500 text-xs">{r.vuln_count} vulns</span>
                  <RiskBar score={r.score} label={r.label} />
                </div>
              </div>
            ))}
            {risks.length === 0 && <p className="text-gray-500 text-sm">No risk data yet.</p>}
          </div>
        </div>
      </div>

      {/* ── Recent changes ──────────────────────────────────────────────── */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-gray-300 mb-4">Recent Changes</h3>
        <Table
          columns={[
            { key: "domain",      label: "Domain" },
            { key: "change_type", label: "Type",   render: (r) => <ChangeTypeBadge type={r.change_type} /> },
            { key: "asset",       label: "Asset",  className: "font-mono text-xs" },
            { key: "detected_at", label: "When",   render: (r) => <RelTime ts={r.detected_at} /> },
          ]}
          data={changes}
          emptyText="No changes detected yet."
        />
      </div>
    </div>
  );
}

// ── Small helpers ─────────────────────────────────────────────────────────────

function RiskBar({ score, label }: { score: number; label: string }) {
  const COLOR: Record<string, string> = {
    CRITICAL: "bg-red-500",
    HIGH:     "bg-orange-500",
    MEDIUM:   "bg-yellow-500",
    LOW:      "bg-blue-400",
    INFO:     "bg-gray-500",
  };
  const color = COLOR[label.toUpperCase()] ?? "bg-gray-500";
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-20 h-1.5 bg-gray-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-gray-400 w-6 text-right">{score}</span>
    </div>
  );
}

function ChangeTypeBadge({ type }: { type: string }) {
  const COLORS: Record<string, string> = {
    new_subdomain:  "bg-green-900/40 text-green-400",
    new_port:       "bg-blue-900/40 text-blue-400",
    new_vuln:       "bg-red-900/40 text-red-400",
    removed:        "bg-gray-800 text-gray-400",
  };
  const style = COLORS[type] ?? "bg-gray-800 text-gray-400";
  return (
    <span className={`text-xs px-2 py-0.5 rounded font-mono ${style}`}>{type}</span>
  );
}

function RelTime({ ts }: { ts: string }) {
  if (!ts) return <span className="text-gray-500">—</span>;
  const d   = new Date(ts);
  const ago = Math.round((Date.now() - d.getTime()) / 60000);
  const label = ago < 1 ? "just now" : ago < 60 ? `${ago}m ago` : ago < 1440 ? `${Math.round(ago/60)}h ago` : `${Math.round(ago/1440)}d ago`;
  return <span className="text-gray-400 text-xs">{label}</span>;
}

export function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center py-20">
      <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="bg-red-900/20 border border-red-800 rounded-xl p-4 text-red-400 text-sm">
      ⚠ {message}
    </div>
  );
}
