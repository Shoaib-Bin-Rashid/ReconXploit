"use client";
import { useState } from "react";
import { DashboardOverview } from "@/components/DashboardOverview";
import { TargetsSection }    from "@/components/TargetsSection";
import { VulnsSection }      from "@/components/VulnsSection";
import { ScansSection }      from "@/components/ScansSection";
import {
  LayoutDashboard, Target, ShieldAlert, ScanLine, Menu, Crosshair
} from "lucide-react";

type Tab = "overview" | "targets" | "scans" | "vulns";

const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: "overview", label: "Overview",        icon: <LayoutDashboard size={16} /> },
  { id: "targets",  label: "Targets",         icon: <Target size={16} /> },
  { id: "scans",    label: "Scans",           icon: <ScanLine size={16} /> },
  { id: "vulns",    label: "Vulnerabilities", icon: <ShieldAlert size={16} /> },
];

export default function Home() {
  const [tab,         setTab]         = useState<Tab>("overview");
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside
        className={[
          "fixed inset-y-0 left-0 z-40 w-56 bg-gray-900 border-r border-gray-800 flex flex-col",
          "transform transition-transform duration-200",
          sidebarOpen ? "translate-x-0" : "-translate-x-full",
          "lg:relative lg:translate-x-0",
        ].join(" ")}
      >
        <div className="flex items-center gap-3 px-5 py-5 border-b border-gray-800">
          <Crosshair size={22} className="text-cyan-400" />
          <span className="font-bold text-lg text-white">ReconXploit</span>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => { setTab(t.id); setSidebarOpen(false); }}
              className={[
                "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
                tab === t.id
                  ? "bg-cyan-900/40 text-cyan-400"
                  : "text-gray-400 hover:bg-gray-800 hover:text-gray-100",
              ].join(" ")}
            >
              {t.icon}{t.label}
            </button>
          ))}
        </nav>
        <div className="px-5 py-4 border-t border-gray-800 text-xs text-gray-600">v0.1.0</div>
      </aside>

      {sidebarOpen && (
        <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="flex items-center gap-4 px-6 py-4 border-b border-gray-800 bg-gray-950">
          <button className="lg:hidden text-gray-400 hover:text-white" onClick={() => setSidebarOpen(true)}>
            <Menu size={20} />
          </button>
          <h1 className="text-base font-semibold text-white">
            {TABS.find((t) => t.id === tab)?.label}
          </h1>
          <div className="ml-auto flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-xs text-gray-500">API Connected</span>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-6">
          {tab === "overview" && <DashboardOverview />}
          {tab === "targets"  && <TargetsSection />}
          {tab === "scans"    && <ScansSection />}
          {tab === "vulns"    && <VulnsSection />}
        </main>
      </div>
    </div>
  );
}
