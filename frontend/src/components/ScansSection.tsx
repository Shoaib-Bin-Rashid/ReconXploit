"use client";
import { useEffect, useState } from "react";
import { api, Scan } from "@/lib/api";
import { Table } from "@/components/ui/Table";
import { LoadingSpinner, ErrorBanner } from "@/components/DashboardOverview";
import { RefreshCw } from "lucide-react";

const STATUS_STYLES: Record<string, string> = {
  completed: "bg-green-900/40 text-green-400",
  running:   "bg-blue-900/40 text-blue-400",
  pending:   "bg-yellow-900/40 text-yellow-400",
  failed:    "bg-red-900/40 text-red-400",
};

export function ScansSection() {
  const [scans,   setScans]   = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    api.scans.list()
      .then(setScans)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  return (
    <div className="space-y-5">
      {error && <ErrorBanner message={error} />}
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-400">{scans.length} scans</span>
        <button
          onClick={load}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 hover:text-white bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
        >
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} /> Refresh
        </button>
      </div>

      {loading ? <LoadingSpinner /> : (
        <Table
          columns={[
            { key: "target_domain", label: "Target",   render: (s) => <span className="font-mono">{s.target_domain ?? "—"}</span> },
            { key: "scan_type",     label: "Mode",     render: (s) => <span className="capitalize">{s.scan_type ?? "full"}</span> },
            { key: "status",        label: "Status",   render: (s) => <StatusBadge status={s.status} /> },
            { key: "started_at",    label: "Started",  render: (s) => s.started_at ? new Date(s.started_at).toLocaleString() : "—" },
            { key: "completed_at",  label: "Finished", render: (s) => s.completed_at ? new Date(s.completed_at).toLocaleString() : "—" },
            { key: "findings_count",label: "Findings", render: (s) => s.findings_count ?? "—" },
          ]}
          data={scans}
          emptyText="No scans yet. Trigger one from the Targets tab."
        />
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const style = STATUS_STYLES[status] ?? "bg-gray-800 text-gray-400";
  return (
    <span className={`text-xs px-2 py-0.5 rounded font-medium capitalize ${style}`}>
      {status}
    </span>
  );
}
