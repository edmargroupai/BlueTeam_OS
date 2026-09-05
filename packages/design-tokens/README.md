# UI visual pack (Phases 37–40)

Source of truth: `packages/design-tokens/tokens.json`

Generate CSS/TS artefacts:

```bash
python scripts/generate_tokens.py
# or from apps/web:
npm run tokens
```

## Stack delivered

| Capability | Library | Surfaces |
|---|---|---|
| Tokens + density + motion | generated CSS/TS | AppShell, globals |
| Severity / risk charts | Apache ECharts | Command |
| ATT&CK heatmap | ECharts | Attack |
| Entity graph | Cytoscape.js | Graph |
| Playbook / architecture DAG | React Flow (`@xyflow/react`) | Playbooks, Architecture |
| Motion tokens | CSS vars (+ Motion package installed) | reduced-motion respected |
| Component gallery | Storybook 8 | `npm run storybook` / `build-storybook` |

## Rules

- Charts encode API/tenant data only — empty/loading/error states required.
- Graphs include an accessible table fallback.
- Do not hard-code production metrics in pages.
- PixiJS / Rive / Playwright golden diffs remain deferred (Phase 39/40 partial).
