"use client";
import React from "react";

interface StatCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color?: string;   // Tailwind text color class e.g. "text-red-400"
  subtitle?: string;
}

export function StatCard({ title, value, icon, color = "text-cyan-400", subtitle }: StatCardProps) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 flex items-start gap-4">
      <div className={`p-2 rounded-lg bg-gray-800 ${color}`}>{icon}</div>
      <div>
        <p className="text-sm text-gray-400">{title}</p>
        <p className={`text-2xl font-bold mt-0.5 ${color}`}>{value}</p>
        {subtitle && <p className="text-xs text-gray-500 mt-0.5">{subtitle}</p>}
      </div>
    </div>
  );
}
