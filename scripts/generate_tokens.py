#!/usr/bin/env python3
"""Generate CSS + TypeScript artefacts from tokens.json (source of truth)."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKENS = ROOT / "packages" / "design-tokens" / "tokens.json"
OUT_CSS = ROOT / "packages" / "design-tokens" / "tokens.css"
OUT_WEB_CSS = ROOT / "apps" / "web" / "src" / "styles" / "tokens.generated.css"
OUT_TS = ROOT / "apps" / "web" / "src" / "lib" / "tokens.generated.ts"


def main() -> None:
    data = json.loads(TOKENS.read_text(encoding="utf-8"))
    colors = data["color"]
    fonts = data["font"]
    spaces = data["space"]
    motion = data["motion"]
    density = data["density"]
    typography = data["type"]

    css_lines = [
        "/* GENERATED from packages/design-tokens/tokens.json — do not edit by hand */",
        ":root {",
    ]
    for key, meta in colors.items():
        var_name = meta.get("css") or f"--btos-{key}"
        css_lines.append(f"  {var_name}: {meta['value']};")
    # Compat aliases used by existing pages
    aliases = {
        "--bg": "var(--btos-bg)",
        "--surface": "var(--btos-surface)",
        "--surface-raised": "var(--btos-surface-raised)",
        "--border": "var(--btos-border)",
        "--text": "var(--btos-text)",
        "--muted": "var(--btos-muted)",
        "--accent": "var(--btos-accent)",
        "--accent-dim": "var(--btos-accent-dim)",
        "--critical": "var(--btos-critical)",
        "--high": "var(--btos-high)",
        "--medium": "var(--btos-medium)",
        "--low": "var(--btos-low)",
        "--info": "var(--btos-info)",
        "--font-sans": "var(--btos-font-sans)",
        "--font-mono": "var(--btos-font-mono)",
    }
    for key, meta in fonts.items():
        css_lines.append(f"  {meta['css']}: {meta['value']};")
    for key, meta in spaces.items():
        css_lines.append(f"  --btos-space-{key}: {meta['value']};")
    for key, meta in motion.items():
        css_lines.append(f"  --btos-motion-{key}: {meta['value']};")
    for key, meta in density.items():
        css_lines.append(f"  --btos-density-{key}-row: {meta['row']};")
        css_lines.append(f"  --btos-density-{key}-pad: {meta['pad']};")
    for key, meta in typography.items():
        css_lines.append(f"  --btos-type-{key}-size: {meta['size']};")
        css_lines.append(f"  --btos-type-{key}-weight: {meta['weight']};")
    for alias, value in aliases.items():
        css_lines.append(f"  {alias}: {value};")
    css_lines.append("  --btos-density-row: var(--btos-density-comfortable-row);")
    css_lines.append("  --btos-density-pad: var(--btos-density-comfortable-pad);")
    css_lines.append("}")
    css_lines.append("")
    css_lines.append('[data-density="compact"] {')
    css_lines.append("  --btos-density-row: var(--btos-density-compact-row);")
    css_lines.append("  --btos-density-pad: var(--btos-density-compact-pad);")
    css_lines.append("}")
    css_lines.append('[data-density="spacious"] {')
    css_lines.append("  --btos-density-row: var(--btos-density-spacious-row);")
    css_lines.append("  --btos-density-pad: var(--btos-density-spacious-pad);")
    css_lines.append("}")
    css_lines.append("")
    css_lines.append("@media (prefers-reduced-motion: reduce) {")
    css_lines.append("  :root {")
    css_lines.append("    --btos-motion-fast: 0ms;")
    css_lines.append("    --btos-motion-base: 0ms;")
    css_lines.append("    --btos-motion-slow: 0ms;")
    css_lines.append("  }")
    css_lines.append("}")
    css_lines.append("")

    css = "\n".join(css_lines)
    OUT_CSS.write_text(css, encoding="utf-8")
    OUT_WEB_CSS.parent.mkdir(parents=True, exist_ok=True)
    OUT_WEB_CSS.write_text(css, encoding="utf-8")

    severity = {
        "critical": colors["critical"]["value"],
        "high": colors["high"]["value"],
        "medium": colors["medium"]["value"],
        "low": colors["low"]["value"],
        "info": colors["info"]["value"],
    }
    ts = f"""/* GENERATED from packages/design-tokens/tokens.json — do not edit by hand */
export const tokens = {json.dumps({
        "color": {k: v["value"] for k, v in colors.items()},
        "font": {k: v["value"] for k, v in fonts.items()},
        "space": {k: v["value"] for k, v in spaces.items()},
        "motion": {k: v["value"] for k, v in motion.items()},
        "density": density,
        "type": typography,
        "severity": severity,
    }, indent=2)} as const;

export type SeverityTone = keyof typeof tokens.severity;

export function severityColor(value: string): string {{
  const key = value.toLowerCase() as SeverityTone;
  return tokens.severity[key] ?? tokens.color.info;
}}
"""
    OUT_TS.parent.mkdir(parents=True, exist_ok=True)
    OUT_TS.write_text(ts, encoding="utf-8")
    print(f"wrote {OUT_CSS}")
    print(f"wrote {OUT_WEB_CSS}")
    print(f"wrote {OUT_TS}")


if __name__ == "__main__":
    main()
