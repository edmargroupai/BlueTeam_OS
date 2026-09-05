"use client";

import { useEffect, useMemo, useRef } from "react";
import cytoscape, { type Core } from "cytoscape";
import { tokens } from "@/lib/tokens.generated";
import { StateBox } from "@/components/AppShell";

type Entity = {
  id: string;
  entity_type: string;
  display_name: string;
  risk_score: number;
};

type Rel = {
  id: string;
  src_id: string;
  dst_id: string;
  relation: string;
  manufactured: boolean;
};

const TYPE_COLOR: Record<string, string> = {
  user: tokens.color.accent,
  host: tokens.color.low,
  ip: tokens.color.medium,
  domain: tokens.color.high,
  process: tokens.color.info,
  cloud_resource: tokens.color.evidenceAi,
};

export function EntityGraphView({
  entities,
  relationships,
}: {
  entities: Entity[];
  relationships: Rel[];
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  const elements = useMemo(() => {
    const nodes = entities.map((entity) => ({
      data: {
        id: entity.id,
        label: entity.display_name,
        type: entity.entity_type,
        risk: entity.risk_score,
      },
    }));
    const edges = relationships
      .filter((rel) => !rel.manufactured)
      .map((rel) => ({
        data: {
          id: rel.id,
          source: rel.src_id,
          target: rel.dst_id,
          label: rel.relation,
        },
      }));
    return [...nodes, ...edges];
  }, [entities, relationships]);

  useEffect(() => {
    if (!containerRef.current || entities.length === 0) return;
    if (cyRef.current) {
      cyRef.current.destroy();
      cyRef.current = null;
    }
    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            color: tokens.color.text,
            "background-color": tokens.color.accent,
            "font-family": tokens.font.mono,
            "font-size": 10,
            "text-valign": "bottom",
            "text-margin-y": 6,
            width: 28,
            height: 28,
            "border-width": 1,
            "border-color": tokens.color.border,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": tokens.color.border,
            "target-arrow-color": tokens.color.border,
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            color: tokens.color.muted,
            "font-size": 9,
            "font-family": tokens.font.mono,
          },
        },
      ],
      layout: { name: "cose", animate: false, padding: 24 },
    });

    cy.nodes().forEach((node) => {
      const type = String(node.data("type") || "");
      node.style("background-color", TYPE_COLOR[type] ?? tokens.color.accent);
      const risk = Number(node.data("risk") || 0);
      node.style("width", 24 + Math.min(risk, 40) / 2);
      node.style("height", 24 + Math.min(risk, 40) / 2);
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements, entities.length]);

  if (entities.length === 0) {
    return <StateBox kind="empty" text="No entities. Ingest telemetry so the graph can be projected." />;
  }

  return (
    <div>
      <div
        ref={containerRef}
        style={{
          height: 420,
          border: "1px solid var(--border)",
          background: "var(--surface-raised)",
        }}
        role="img"
        aria-label="Entity relationship graph"
      />
      <table className="btos-table" aria-label="Entity graph accessible summary">
        <thead>
          <tr>
            <th>Entity</th>
            <th>Type</th>
            <th>Risk</th>
          </tr>
        </thead>
        <tbody>
          {entities
            .slice()
            .sort((a, b) => b.risk_score - a.risk_score)
            .slice(0, 30)
            .map((entity) => (
              <tr key={entity.id}>
                <td>{entity.display_name}</td>
                <td className="mono">{entity.entity_type}</td>
                <td className="mono">{entity.risk_score}</td>
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}
