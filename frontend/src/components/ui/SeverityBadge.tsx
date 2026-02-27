"use client";
import { SEVERITY_BG } from "@/lib/types";

interface Props {
  severity: string;
  className?: string;
}

export function SeverityBadge({ severity, className = "" }: Props) {
  const s = severity.toLowerCase();
  const style = SEVERITY_BG[s] ?? SEVERITY_BG.info;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase ${style} ${className}`}>
      {s}
    </span>
  );
}
