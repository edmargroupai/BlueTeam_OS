"use client";

import dynamic from "next/dynamic";
import { useMemo } from "react";
import { tokens, severityColor } from "@/lib/tokens.generated";
import { StateBox } from "@/components/AppShell";

const ReactECharts = dynamic(() => import("echarts-for-react"), { ssr: false });

export function SeverityDonut({
  severity,
  height = 240,
}: {
  severity: Record<string, number>;
  height?: number;
}) {
  const entries = useMemo(
    () => Object.entries(severity).filter(([, value]) => value > 0),
    [severity],
  );
  const option = useMemo(
    () => ({
      backgroundColor: "transparent",
      tooltip: { trigger: "item" },
      series: [
        {
          type: "pie",
          radius: ["48%", "72%"],
          avoidLabelOverlap: true,
          itemStyle: { borderColor: tokens.color.surface, borderWidth: 2 },
          label: {
            color: tokens.color.muted,
            fontFamily: tokens.font.mono,
            formatter: "{b}: {c}",
          },
          data: entries.map(([name, value]) => ({
            name,
            value,
            itemStyle: { color: severityColor(name) },
          })),
        },
      ],
    }),
    [entries],
  );

  if (entries.length === 0) {
    return <StateBox kind="empty" text="No severity distribution yet — no alerts/findings scored." />;
  }

  return <ReactECharts option={option} style={{ height, width: "100%" }} opts={{ renderer: "svg" }} />;
}

export function RiskBars({
  items,
  height = 260,
}: {
  items: { name: string; value: number }[];
  height?: number;
}) {
  const option = useMemo(
    () => ({
      backgroundColor: "transparent",
      grid: { left: 12, right: 16, top: 12, bottom: 28, containLabel: true },
      xAxis: {
        type: "value",
        axisLabel: { color: tokens.color.muted },
        splitLine: { lineStyle: { color: tokens.color.border } },
      },
      yAxis: {
        type: "category",
        data: items.map((item) => item.name),
        axisLabel: { color: tokens.color.text, fontFamily: tokens.font.mono, fontSize: 11 },
      },
      series: [
        {
          type: "bar",
          data: items.map((item) => item.value),
          itemStyle: { color: tokens.color.accent },
          barWidth: 14,
        },
      ],
      tooltip: { trigger: "axis" },
    }),
    [items],
  );

  if (items.length === 0) {
    return <StateBox kind="empty" text="No risk entities to chart." />;
  }

  return <ReactECharts option={option} style={{ height, width: "100%" }} opts={{ renderer: "svg" }} />;
}
