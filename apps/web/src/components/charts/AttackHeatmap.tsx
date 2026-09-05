"use client";

import dynamic from "next/dynamic";
import { useMemo } from "react";
import { tokens, severityColor } from "@/lib/tokens.generated";
import { StateBox } from "@/components/AppShell";

const ReactECharts = dynamic(() => import("echarts-for-react"), { ssr: false });

type Technique = {
  technique_id: string;
  name: string;
  tactic: string;
  coverage_score: number;
  gap_severity: string;
  detections: string[];
};

export function AttackHeatmap({ techniques }: { techniques: Technique[] }) {
  const tactics = useMemo(() => {
    const set = new Set(techniques.map((item) => item.tactic));
    return Array.from(set).sort();
  }, [techniques]);

  const option = useMemo(() => {
    const byTactic = new Map<string, Technique[]>();
    for (const tech of techniques) {
      const list = byTactic.get(tech.tactic) ?? [];
      list.push(tech);
      byTactic.set(tech.tactic, list);
    }
    const maxCols = Math.max(1, ...Array.from(byTactic.values()).map((list) => list.length));
    const data: [number, number, number, string, string][] = [];
    tactics.forEach((tactic, y) => {
      const list = byTactic.get(tactic) ?? [];
      list.forEach((tech, x) => {
        data.push([x, y, tech.coverage_score, tech.technique_id, tech.gap_severity]);
      });
    });

    return {
      backgroundColor: "transparent",
      tooltip: {
        formatter: (params: { data: [number, number, number, string, string] }) => {
          const [, , score, id, severity] = params.data;
          return `${id}<br/>coverage ${score}<br/>gap ${severity}`;
        },
      },
      grid: { left: 140, right: 24, top: 16, bottom: 24 },
      xAxis: {
        type: "category",
        data: Array.from({ length: maxCols }, (_, idx) => `T${idx + 1}`),
        axisLabel: { show: false },
        splitArea: { show: false },
      },
      yAxis: {
        type: "category",
        data: tactics,
        axisLabel: { color: tokens.color.muted, fontSize: 11, width: 120, overflow: "truncate" },
      },
      visualMap: {
        min: 0,
        max: 1,
        calculable: true,
        orient: "horizontal",
        left: "center",
        bottom: 0,
        textStyle: { color: tokens.color.muted },
        inRange: {
          color: [tokens.color.critical, tokens.color.medium, tokens.color.accent],
        },
      },
      series: [
        {
          type: "heatmap",
          data: data.map(([x, y, score, id, severity]) => ({
            value: [x, y, score],
            id,
            itemStyle: {
              borderColor: tokens.color.bg,
              borderWidth: 2,
              color: severityColor(severity),
            },
          })),
          label: {
            show: true,
            formatter: (params: { data: { id: string } }) => params.data.id.replace("T", ""),
            color: tokens.color.text,
            fontSize: 10,
            fontFamily: tokens.font.mono,
          },
        },
      ],
    };
  }, [tactics, techniques]);

  if (techniques.length === 0) {
    return <StateBox kind="empty" text="No ATT&CK techniques in coverage set." />;
  }

  return (
    <div>
      <ReactECharts option={option} style={{ height: Math.max(280, tactics.length * 36), width: "100%" }} />
      <table className="btos-table" aria-label="ATT&CK coverage fallback">
        <thead>
          <tr>
            <th>Technique</th>
            <th>Tactic</th>
            <th>Score</th>
            <th>Gap</th>
            <th>Detections</th>
          </tr>
        </thead>
        <tbody>
          {techniques.slice(0, 40).map((tech) => (
            <tr key={tech.technique_id}>
              <td className="mono">
                {tech.technique_id} · {tech.name}
              </td>
              <td>{tech.tactic}</td>
              <td className="mono">{tech.coverage_score}</td>
              <td style={{ color: severityColor(tech.gap_severity) }}>{tech.gap_severity}</td>
              <td className="mono">{tech.detections.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
