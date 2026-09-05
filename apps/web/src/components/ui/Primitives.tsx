"use client";

import type { CSSProperties, ReactNode } from "react";

export function DataTable({
  columns,
  rows,
  empty,
}: {
  columns: { key: string; label: string; mono?: boolean }[];
  rows: Record<string, ReactNode>[];
  empty?: string;
}) {
  if (rows.length === 0) {
    return <div className="btos-state">{empty ?? "No rows."}</div>;
  }
  return (
    <table className="btos-table">
      <thead>
        <tr>
          {columns.map((col) => (
            <th key={col.key}>{col.label}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, idx) => (
          <tr key={idx}>
            {columns.map((col) => (
              <td key={col.key} className={col.mono ? "mono" : undefined}>
                {row[col.key]}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function MetricTile({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="btos-metric">
      <div className="btos-metric__label">{label}</div>
      <div className="btos-metric__value">{value}</div>
    </div>
  );
}

export function Grid({
  cols = 2,
  children,
}: {
  cols?: 2 | 3 | 4;
  children: ReactNode;
}) {
  const style: CSSProperties = {
    display: "grid",
    gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))`,
    gap: "var(--btos-space-3)",
  };
  return <div style={style}>{children}</div>;
}
