/* GENERATED from packages/design-tokens/tokens.json — do not edit by hand */
export const tokens = {
  color: {
    bg: "#0B0E14",
    surface: "#12161F",
    surfaceRaised: "#181D28",
    border: "#243044",
    text: "#E8EDF5",
    muted: "#8B95A8",
    accent: "#3D9C8C",
    accentDim: "#1F3D38",
    critical: "#E24B4B",
    high: "#E08A2A",
    medium: "#D4B43C",
    low: "#4C8DDB",
    info: "#8B95A8",
    ok: "#3D9C8C",
    evidencePrimary: "#3D9C8C",
    evidenceDerived: "#4C8DDB",
    evidenceStatistical: "#D4B43C",
    evidenceAi: "#8A6FBF",
    evidenceAnalyst: "#E08A2A",
  },
  font: {
    sans: '"IBM Plex Sans", "Segoe UI", sans-serif',
    mono: '"IBM Plex Mono", ui-monospace, monospace',
  },
  space: {
    "1": "4px",
    "2": "8px",
    "3": "12px",
    "4": "16px",
    "5": "20px",
    "6": "24px",
    "8": "32px",
    "10": "40px",
  },
  motion: {
    fast: "120ms",
    base: "200ms",
    slow: "320ms",
    ease: "cubic-bezier(0.2, 0.8, 0.2, 1)",
  },
  density: {
    compact: { row: "28px", pad: "8px" },
    comfortable: { row: "36px", pad: "12px" },
    spacious: { row: "44px", pad: "16px" },
  },
  type: {
    display: { size: "28px", weight: "560", lineHeight: "1.2" },
    title: { size: "22px", weight: "560", lineHeight: "1.25" },
    body: { size: "14px", weight: "400", lineHeight: "1.45" },
    label: { size: "12px", weight: "500", lineHeight: "1.35", tracking: "0.08em" },
    mono: { size: "12px", weight: "400", lineHeight: "1.4" },
  },
  severity: {
    critical: "#E24B4B",
    high: "#E08A2A",
    medium: "#D4B43C",
    low: "#4C8DDB",
    info: "#8B95A8",
  },
} as const;

export type SeverityTone = keyof typeof tokens.severity;

export function severityColor(value: string): string {
  const key = value.toLowerCase() as SeverityTone;
  return tokens.severity[key] ?? tokens.color.info;
}
