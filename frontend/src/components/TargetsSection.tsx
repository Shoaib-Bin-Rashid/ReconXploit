"use client";
import { useEffect, useState } from "react";
import { api, Target } from "@/lib/api";
import { Table } from "@/components/ui/Table";
import { LoadingSpinner, ErrorBanner } from "@/components/DashboardOverview";
import { Plus, Trash2, Play } from "lucide-react";

export function TargetsSection() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);
  const [newDomain, setNewDomain] = useState("");
  const [adding,    setAdding]    = useState(false);
  const [scanningId, setScanningId] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    api.targets.list()
      .then(setTargets)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const addTarget = async () => {
    if (!newDomain.trim()) return;
    setAdding(true);
    try {
      await api.targets.add(newDomain.trim());
      setNewDomain("");
      load();
    } catch (e: unknown) {
      setError((e as Error).message);
    } finally {
      setAdding(false);
    }
  };

  const deleteTarget = async (domain: string) => {
    if (!confirm(`Delete ${domain}?`)) return;
    try {
      await api.targets.delete(domain);
      load();
    } catch (e: unknown) {
      setError((e as Error).message);
    }
  };

  const triggerScan = async (domain: string) => {
    setScanningId(domain);
    try {
      const r = await api.scans.trigger(domain, "full");
      alert(`Scan queued (${r.dispatched_via}): ${r.scan_id}`);
    } catch (e: unknown) {
      setError((e as Error).message);
    } finally {
      setScanningId(null);
    }
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-5">
      {error && <ErrorBanner message={error} />}

      {/* Add target form */}
      <div className="flex gap-3">
        <input
          type="text"
          value={newDomain}
          onChange={(e) => setNewDomain(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && addTarget()}
          placeholder="example.com"
          className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-600"
        />
        <button
          onClick={addTarget}
          disabled={adding}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm rounded-lg font-medium transition-colors disabled:opacity-50"
        >
          <Plus size={16} /> Add Target
        </button>
      </div>

      <Table
        columns={[
          { key: "domain",         label: "Domain",     render: (t) => <span className="font-mono">{t.domain}</span> },
          { key: "status",         label: "Status",     render: (t) => <StatusDot status={t.status} /> },
          { key: "subdomain_count",label: "Subdomains", render: (t) => t.subdomain_count ?? "—" },
          { key: "live_host_count",label: "Live Hosts", render: (t) => t.live_host_count ?? "—" },
          { key: "vuln_count",     label: "Vulns",      render: (t) => t.vuln_count ?? "—" },
          { key: "last_scan",      label: "Last Scan",  render: (t) => t.last_scan ? new Date(t.last_scan).toLocaleDateString() : "—" },
          {
            key: "actions", label: "",
            render: (t) => (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => triggerScan(t.domain)}
                  disabled={scanningId === t.domain}
                  title="Trigger scan"
                  className="p-1.5 text-green-400 hover:bg-green-900/30 rounded transition-colors disabled:opacity-40"
                >
                  <Play size={14} />
                </button>
                <button
                  onClick={() => deleteTarget(t.domain)}
                  title="Delete target"
                  className="p-1.5 text-red-400 hover:bg-red-900/30 rounded transition-colors"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ),
          },
        ]}
        data={targets}
        emptyText="No targets yet. Add one above."
      />
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const COLOR: Record<string, string> = {
    active:   "bg-green-500",
    paused:   "bg-yellow-500",
    disabled: "bg-gray-500",
  };
  return (
    <div className="flex items-center gap-1.5">
      <div className={`w-2 h-2 rounded-full ${COLOR[status] ?? "bg-gray-500"}`} />
      <span className="text-xs text-gray-400 capitalize">{status}</span>
    </div>
  );
}
