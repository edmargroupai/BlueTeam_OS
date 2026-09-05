# Blue Team OS Center — Cursor Build Specification

## 1. Cursor Mission
Build Blue Team OS Center as a production-grade, Python-first defensive cybersecurity operating system.

Do not build a mock dashboard disconnected from real services. Every completed phase must create working backend logic, persistence, tests, observability, security controls, and a usable interface.

The system must remain operational without AI.

**GSE-calibre engineering directive:** implement and review every defensive workflow with the breadth, evidence discipline, technical depth, and operational judgement expected from an elite senior defensive-security practitioner. GSE is a practitioner certification, not a software certification; use the phrase only as an internal quality benchmark. Never claim a UI page or stub equals a defensive capability. Every capability must be proven by backend behaviour, tests, replay, evidence, and measurable acceptance criteria.

---

## 2. Non-Negotiable Engineering Rules

1. Python is the primary backend and security-engine language.
2. Use FastAPI for control APIs.
3. Use TypeScript only for frontend and limited support tooling.
4. Never put detection logic only in the UI.
5. Never allow direct frontend-to-database privileged access.
6. Never call an AI provider directly from feature code.
7. All AI calls go through `services/ai-gateway`.
8. Never send every raw event to AI.
9. Never allow AI to execute Tier-2 actions directly.
10. All state-changing actions require audit records.
11. Every tenant-owned record requires `tenant_id`.
12. Every API route must enforce tenant scope.
13. Every rule must be versioned and testable.
14. All background jobs must be idempotent where possible.
15. High-volume telemetry must not use PostgreSQL as the primary event store.
16. Use ClickHouse/OpenSearch for security-event workloads.
17. Use PostgreSQL for control plane, configuration, incidents, metadata, policies, workflow, and audit references.
18. Use typed schemas everywhere.
19. No secrets in source code.
20. CI must block merges on critical test or security failures.
21. Raw/primary evidence must be preserved and traceable through every derived conclusion.
22. AI-generated incident claims must cite valid internal evidence IDs or be rejected.
23. Every production detection requires replay/regression validation and a quality score.
24. Every high-impact response must support verification and rollback where technically possible.
25. No visual phase is complete without golden-reference comparison and automated screenshot tests.
26. Security graphics must be data-driven, typed, accessible, and useful; decorative complexity is not a substitute for information.
27. Use PixiJS/WebGL only where data density justifies it; use semantic DOM/SVG for ordinary interface content.
28. Respect reduced-motion and keyboard accessibility across interactive graphs and motion.
29. Blue Range defensive validation scenarios must execute in CI.
30. The final product quality index must be computed from evidence-backed tests, never manually inflated.

---

## 3. Monorepo Structure

Create:

```text
blue-team-os/
├── apps/
│   ├── web/
│   └── docs/
├── services/
│   ├── api/
│   ├── ingestion/
│   ├── normalizer/
│   ├── enrichment/
│   ├── detection-engine/
│   ├── correlation-engine/
│   ├── risk-engine/
│   ├── hunting-engine/
│   ├── incident-engine/
│   ├── soar-engine/
│   ├── replay-engine/
│   ├── telemetry-health/
│   ├── threat-intel/
│   ├── vulnerability-engine/
│   ├── self-improvement/
│   └── ai-gateway/
├── packages/
│   ├── schemas/
│   ├── python-common/
│   ├── detection-sdk/
│   ├── playbook-sdk/
│   ├── connectors-sdk/
│   ├── ui/
│   ├── visual-system/
│   ├── graph-engine/
│   ├── chart-engine/
│   └── design-tokens/
├── detections/
│   ├── sigma/
│   ├── yara/
│   └── python/
├── playbooks/
├── connectors/
├── infra/
│   ├── docker/
│   ├── kubernetes/
│   ├── terraform/
│   └── observability/
├── migrations/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── tenant-isolation/
│   ├── replay/
│   ├── detection/
│   ├── security/
│   └── e2e/
├── scripts/
├── docs/
├── .github/workflows/
├── pyproject.toml
├── package.json
├── docker-compose.yml
└── README.md
```

---

## 4. Standard Python Service Layout

Every Python service should use:

```text
service-name/
├── app/
│   ├── api/
│   ├── core/
│   ├── domain/
│   ├── models/
│   ├── repositories/
│   ├── services/
│   ├── workers/
│   └── main.py
├── tests/
├── pyproject.toml
└── README.md
```

Use:
- Ruff
- Black or Ruff formatter
- mypy or pyright
- pytest
- pytest-asyncio
- coverage

---

## 5. Build Phases

### Phase 0 — Repository and Engineering Foundation
Deliver:
- monorepo
- Python workspace
- Next.js app
- linting
- formatting
- pre-commit
- CI
- Docker Compose
- environment templates
- secrets policy
- coding standards
- architectural decision records

Acceptance:
- fresh clone starts local stack
- frontend loads
- API health endpoint works
- CI green

---

### Phase 1 — Identity, Multi-Tenancy, RBAC, Audit
Deliver:
- tenants
- users
- roles
- permissions
- memberships
- tenant middleware
- audit middleware
- OIDC-ready auth abstraction
- API keys for connectors
- strict tenant isolation tests

Acceptance:
- cross-tenant reads fail
- cross-tenant writes fail
- role permissions verified
- audit events created

---

### Phase 2 — Core Data Plane
Deliver local development instances of:
- PostgreSQL
- ClickHouse
- OpenSearch
- Redis
- Redpanda/Kafka
- S3-compatible object storage

Deliver:
- health checks
- migrations
- indexes
- retention policies
- connection libraries

Acceptance:
- all services connect
- test telemetry can be written and queried
- dead-letter queue works

---

### Phase 3 — Unified Event Schema and Ingestion
Deliver:
- canonical event schema
- schema versioning
- ingestion API
- Kafka topics
- tenant partition keys
- idempotency keys
- raw event storage path
- dead-letter flow

Create adapters for:
- generic JSON
- syslog
- webhook

Acceptance:
- events accepted
- invalid events rejected safely
- duplicate handling verified
- tenant context preserved

---

### Phase 4 — Normalisation and Enrichment
Deliver:
- source parsers
- normaliser workers
- GeoIP enrichment abstraction
- asset enrichment
- identity enrichment
- threat-intel enrichment interface
- schema drift handling

Acceptance:
- raw source events produce canonical events
- failed parsing is observable
- enrichment is deterministic and testable

---

### Phase 5 — Detection Engine v1
Deliver:
- detection SDK
- Python rule interface
- Sigma ingestion/compiler abstraction
- YARA scanning interface
- threshold rules
- scheduled rules
- real-time rules
- suppression and exceptions
- alert creation

Acceptance:
- sample detections fire from test telemetry
- all detection outputs include explainable evidence
- detection unit tests pass

---

### Phase 6 — Detection-as-Code
Deliver:
- Git-backed rule structure
- rule linting
- versioning
- rule status workflow
- CI rule tests
- performance budget metadata
- ATT&CK metadata validation

Acceptance:
- invalid rule blocks CI
- rule version history visible
- tested rule can be promoted

---

### Phase 7 — Correlation Engine and Attack Storylines
Deliver:
- correlation rule model
- temporal windows
- entity joins
- cross-source correlation
- attack storyline object
- incident grouping logic

Acceptance:
- multiple low-level alerts correlate into one storyline
- correlation result is explainable
- duplicate incident inflation is controlled

---

### Phase 8 — Risk Engine and Entity Graph
Deliver:
- users
- hosts
- IPs
- domains
- processes
- cloud resources
- relationships
- entity risk scores
- asset criticality
- graph API

Acceptance:
- risk updates from detections and intel
- graph relationship queries work
- score components are explainable

---

### Phase 9 — Command Center UI
Build:
- Security Command Center
- Live Operations
- top incidents
- top-risk users/assets
- ATT&CK overview
- telemetry health
- detection health
- automation queue

Rules:
- no fake data in production code
- loading, empty, error states required

---

### Phase 10 — Incident Response and Investigation
Deliver:
- incidents
- assignments
- statuses
- severity
- evidence
- notes
- timeline
- related entities
- analyst tasks
- root cause
- lessons learned
- chain of custody

Acceptance:
- alert converts to incident
- evidence references are immutable/audited
- timeline reconstructs correctly

---

### Phase 11 — Threat Hunting
Deliver:
- structured query interface
- saved hunts
- IOC lookup
- entity lookup
- time filters
- process-tree view
- network-session search
- authentication history
- export controls

Acceptance:
- analyst can search across supported telemetry stores
- query history is auditable

---

### Phase 12 — Threat Intelligence
Deliver:
- IOC model
- sources
- confidence
- TTL
- deduplication
- sightings
- malware
- actors
- campaigns
- ATT&CK mapping

Acceptance:
- new IOC enriches incoming event
- expired IOC handling works
- provenance remains visible

---

### Phase 13 — ATT&CK Coverage Center
Deliver:
- ATT&CK technique catalogue
- detection-to-technique mapping
- telemetry-to-technique mapping
- coverage scoring
- gap severity
- validation state

Acceptance:
- technique shows telemetry, detections, validation, and gaps

---

### Phase 14 — Wazuh Connector
Deliver:
- connector framework
- Wazuh adapter
- endpoint inventory
- alerts
- agent health
- endpoint actions abstraction

No direct high-impact response without policy engine.

---

### Phase 15 — Zeek and Suricata Connectors
Deliver:
- Zeek parser
- Suricata parser
- network sessions
- DNS
- HTTP
- TLS
- IDS findings

Acceptance:
- network events normalised
- detections correlate endpoint + network signals

---

### Phase 16 — Identity Threat Detection
Deliver code-first detections for:
- password spraying
- brute force
- repeated failed login
- unusual successful login
- impossible travel abstraction
- MFA fatigue
- dormant account activity
- privilege changes
- service account misuse

Acceptance:
- deterministic detection tests with synthetic event fixtures

---

### Phase 17 — Cloud Security
Build connector abstraction and first implementation for one cloud before expanding.

Capabilities:
- audit events
- identities
- assets
- risky configurations
- public exposure
- privileged operations

Do not implement all three clouds simultaneously in first pass.

---

### Phase 18 — Vulnerability and Exposure Engine
Deliver:
- CVE data model
- scanner import framework
- CVSS
- exploitability
- asset criticality
- threat activity weighting
- remediation priority
- SLA tracking

Risk formula must be deterministic and documented.

---

### Phase 19 — Telemetry Health Center
Deliver:
- silent sensors
- parser failures
- ingestion lag
- event volume anomaly
- schema drift
- missing expected data source
- stale integration

Acceptance:
- platform warns when required telemetry is absent

---

### Phase 20 — SOAR / Playbook Engine
Deliver:
- Python playbook SDK
- DAG execution
- retries
- idempotency
- approvals
- action tiers
- execution logs
- rollback hooks

Tier rules:
- T0 automatic
- T1 policy-controlled
- T2 explicit human approval

---

### Phase 21 — Replay and Validation Lab
Deliver:
- replay dataset registration
- replay jobs
- candidate rule comparison
- performance metrics
- regression suite
- promotion gating

Acceptance:
- current vs candidate detection metrics visible
- failed regression blocks promotion

---

### Phase 22 — Self-Improvement Engine
Deliver:
- rule performance analytics
- noisy-rule detection
- duplicate-rule detection
- ATT&CK gap detection
- telemetry gap detection
- improvement candidate creation
- replay integration
- promotion state machine

AI can suggest candidates but cannot promote directly.

---

### Phase 23 — AI Gateway
Deliver:
- provider interface
- local model interface
- policy engine
- AI-needed classifier
- redaction
- caching
- cost tracking
- token budgets
- structured output validation
- audit trail

Acceptance:
- feature code cannot call provider SDK directly
- provider outage does not break detection pipeline

---

### Phase 24 — AI SOC Analyst
Capabilities:
- incident summary
- explain alert
- explain risk
- suggest investigation queries
- translate natural-language hunt to approved query DSL
- draft rule candidates
- summarise threat intel

Must use retrieved evidence only.
Never fabricate security facts.

---

### Phase 25 — Blue Autopilot
Deliver:
- automated investigation DAGs
- evidence gathering
- risk updates
- safe response suggestions
- Tier-0 automatic actions
- Tier-1 policy-based actions
- Tier-2 approval requests

Acceptance:
- all actions policy checked
- all decisions auditable
- deterministic fallback exists

---

### Phase 26 — DFIR Expansion
Deliver:
- forensic evidence registry
- process trees
- host timelines
- network timelines
- file hashes
- browser artefacts abstraction
- memory artefact abstraction
- evidence export

---

### Phase 27 — Security Hardening
Perform:
- threat model
- SAST
- dependency scan
- secret scan
- container scan
- IaC scan
- API fuzzing
- RBAC review
- tenant isolation review
- auth review
- audit integrity review

No production readiness until high/critical findings are resolved or formally accepted.

---

### Phase 28 — Observability and SRE
Deliver:
- OpenTelemetry traces
- service metrics
- queue metrics
- detection latency
- ingestion lag
- worker saturation
- replay duration
- AI cost metrics
- dashboards
- alerts

---

### Phase 29 — Production Infrastructure
Deliver:
- Terraform
- production Kubernetes or equivalent deployment architecture
- secrets manager
- backup strategy
- restore test
- database HA plan
- object storage durability
- network policies
- WAF/API gateway

---

### Phase 30 — Production Readiness Gate
Required evidence:
- CI green
- E2E green
- tenant isolation green
- replay tests green
- security tests green
- load test completed
- recovery tested
- audit completeness reviewed
- secrets review complete
- AI failover verified
- incident-response runbook written

---

### Phase 31 — Evidence Provenance and Confidence Engine
Deliver:
- immutable evidence metadata model
- integrity hashes and object-storage references
- chain-of-custody events
- claim/evidence relationship model
- confidence hierarchy
- contradicting-evidence support
- evidence IDs in incident APIs
- AI evidence-reference validator

Acceptance:
- every derived claim can be traced to primary evidence
- invalid AI evidence IDs are rejected
- evidence transformation history is inspectable
- tampered evidence fails integrity verification

---

### Phase 32 — Deep DFIR Workbench
Deliver:
- forensic evidence UI and APIs
- process-tree view
- timeline reconstruction
- file/hash artefact views
- registry/persistence artefact adapters
- memory-analysis adapter contract
- Velociraptor/osquery/Volatility integration interfaces
- Plaso/Timesketch-compatible timeline import/export adapters
- chain-of-custody UI

Acceptance:
- synthetic incident can be reconstructed from multiple evidence sources
- evidence remains tenant-isolated
- timeline links back to raw artefacts
- analyst can export an evidence manifest with hashes

---

### Phase 33 — Packet and Session Investigation
Deliver:
- PCAP/session reference model
- Zeek/Suricata drill-down
- DNS/TLS/HTTP metadata views
- flow-to-entity correlation
- beaconing and tunnelling analytics
- network investigation timeline
- packet/session evidence links

Acceptance:
- network alert drills down to supporting session/telemetry evidence
- synthetic C2 and lateral-movement scenarios are correctly correlated
- large flow datasets meet performance budget

---

### Phase 34 — Defensive Architecture Center
Deliver:
- typed architecture graph schema
- zones, trust boundaries, assets, identities, controls, sensors, dependencies
- React Flow architecture editor
- control/telemetry overlays
- vulnerability overlays
- incident overlays
- ATT&CK technique overlays
- detection-gap analysis

Acceptance:
- architecture graph persists and versions cleanly
- attack paths can be explained using real relationships
- missing telemetry/control gaps are surfaced deterministically

---

### Phase 35 — Blue Range and GSE-Calibre Validation Harness
Deliver:
- isolated synthetic telemetry generator
- scenario fixture format
- expected-event assertions
- expected-detection assertions
- expected-correlation assertions
- ATT&CK mapping assertions
- detection-latency measurement
- incident-storyline validation
- response-recommendation validation
- CI execution

Initial scenario families:
- suspicious authentication/password spraying
- privilege escalation
- script/PowerShell abuse telemetry
- persistence indicators
- lateral movement indicators
- command-and-control indicators
- data staging/exfiltration indicators
- ransomware-like file activity
- cloud identity compromise indicators

Acceptance:
- Blue Range runs without external offensive targets
- scenarios are deterministic/reproducible
- failures block release gates where configured
- quality index consumes real Blue Range results

---

### Phase 36 — Quality Scoring and Defensive Learning Metrics
Deliver:
- 1,000-point Blue Team OS Quality Index
- Detection Quality Score
- Incident Handling Quality Score
- evidence-completeness score
- telemetry health contribution
- replay/regression contribution
- score history/trends
- signed calculation version

Acceptance:
- every score is reproducible from stored evidence
- UI cannot directly edit calculated scores
- score model/version is recorded
- missing evidence reduces confidence rather than being silently treated as pass

---

### Phase 37 — Premium Visual System Foundation
Deliver:
- source-of-truth design tokens
- generated Tailwind/CSS/TypeScript token artefacts
- typography scale
- semantic severity/confidence/evidence palettes
- icon rules
- density modes
- responsive grid
- panel/card/table primitives
- graph primitives
- chart primitives
- motion rules
- reduced-motion implementation
- Storybook

Required stack:
- Apache ECharts
- Cytoscape.js
- React Flow
- Motion for React
- SVG/SVGR
- PixiJS v8 for justified GPU visualisations
- Rive for curated stateful illustrations/micro-interactions

Acceptance:
- no random hard-coded visual values in feature pages
- Storybook builds in CI
- tokens are generated automatically
- all core primitives have loading/empty/error/disabled states
- accessibility checks pass

---

### Phase 38 — Golden Reference Security Screens
Create production-quality reference implementations for:
1. Security Command Center
2. Incident Investigation
3. Entity/Attack Graph
4. Threat Hunting Workbench
5. Detection Engineering
6. ATT&CK Coverage Center
7. Network Investigation
8. Endpoint Investigation
9. Identity Investigation
10. DFIR Workbench
11. SOAR Playbook Builder
12. Defensive Architecture Center
13. Blue Range
14. Self-Improvement Center
15. Executive Security Posture

Rules:
- use realistic synthetic datasets
- no placeholder charts when the real component can be built
- no duplicated page title/header patterns that waste vertical space
- visual hierarchy must remain consistent across all screens
- critical actions and evidence must be obvious
- graphs and charts must encode actual meaning

Acceptance:
- each reference has approved desktop screenshots
- browser console has no errors
- keyboard paths work
- reduced-motion view works
- realistic dense data remains readable

---

### Phase 39 — Automated Visual Quality Gate
Deliver CI jobs for:
- Storybook build
- component interaction tests
- Playwright route tests
- screenshot capture
- golden-image visual diff
- axe accessibility checks
- Lighthouse CI on representative routes
- console-error detection
- missing asset detection
- responsive viewport checks
- reduced-motion checks

Acceptance:
- material unexplained screenshot drift fails CI
- pages with broken assets fail CI
- serious accessibility violations fail CI
- performance regression beyond agreed budget fails CI

---

### Phase 40 — High-Density Security Graphics
Deliver data-driven advanced visualisations:
- Cytoscape entity/attack graph
- React Flow SOAR builder
- React Flow defensive architecture graph
- ECharts ATT&CK heatmap/coverage matrix
- ECharts timelines and risk distributions
- PixiJS live telemetry/network canvas where justified
- optional Rive operational state assets

Acceptance:
- each visual has semantic fallback/table or accessible summary where appropriate
- graph filters are deterministic and testable
- large synthetic datasets remain interactive
- no visual shows fabricated production data

---

### Phase 41 — Final GSE-Calibre Readiness Gate
A release candidate must demonstrate, with evidence, all of the following:
- network detection and packet/session investigation
- endpoint process-tree investigation
- identity investigation
- cloud investigation
- threat hunting
- incident response lifecycle
- DFIR evidence preservation
- detection-as-code validation
- replay/regression
- telemetry health failure detection
- ATT&CK coverage validation
- policy-controlled response
- rollback/verification where supported
- self-improvement candidate creation and safe promotion workflow
- AI-offline operation
- AI evidence-grounding enforcement
- multi-tenant isolation
- Blue Range execution
- quality index calculation
- visual-regression pass
- accessibility pass
- high-density UI performance pass

Target internal quality band for production maturity: **925+/1000**, with no critical domain below its minimum gate. The score is not sufficient by itself; all mandatory critical tests must pass.

---

## 6. Data Storage Responsibility

### PostgreSQL
Use for:
- tenants
- users
- roles
- integrations
- assets metadata
- detection metadata
- alerts metadata
- incidents
- playbooks
- approvals
- policies
- AI usage records
- audit references

### ClickHouse
Use for:
- high-volume telemetry
- aggregated event analytics
- historical detection queries
- replay datasets where appropriate

### OpenSearch
Use for:
- full-text event search
- incident search
- IOC search
- analyst exploration
- detection query execution where appropriate

### Object Storage
Use for:
- raw evidence
- forensic artefacts
- exported reports
- replay bundles
- large attachments

---

## 7. Event Topics

Initial topic design:
```text
raw.events
normalized.events
enriched.events
detection.findings
alerts
correlation.events
incidents.events
threatintel.updates
telemetry.health
soar.commands
soar.results
replay.commands
replay.results
improvement.candidates
audit.events
```

Every message must include:
- event_id
- tenant_id
- timestamp
- schema_version
- correlation_id
- trace_id

---

## 8. API Conventions

Base:
```text
/api/v1/
```

Requirements:
- OpenAPI generated
- Pydantic request/response models
- pagination
- filtering
- sorting
- stable error schema
- request ID header
- tenant context middleware
- rate limits
- audit hooks

Error model:
```json
{
  "error": {
    "code": "STRING_CODE",
    "message": "Human-readable message",
    "request_id": "..."
  }
}
```

---

## 9. Security Action Policy Model

Every response action includes:
```text
action_type
target_type
target_id
tenant_id
tier
risk
reason
source_incident
requested_by
policy_result
approval_required
approval_id
status
created_at
executed_at
result
```

Policy engine returns:
```text
ALLOW
DENY
REQUIRE_APPROVAL
```

---

## 10. Detection SDK Interface

Create a Python abstraction similar to:

```python
class DetectionRule(Protocol):
    rule_id: str
    version: str

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        ...
```

Rules must not perform network calls directly.
Enrichment must be injected through context/services.

---

## 11. Playbook SDK Interface

Use typed steps:

```python
class PlaybookStep(Protocol):
    async def execute(self, ctx: PlaybookContext) -> StepResult:
        ...
```

Requirements:
- retries
- timeout
- idempotency
- input schema
- output schema
- audit event
- compensation hook where possible

---

## 12. AI Gateway Contract

Feature code submits:
```text
task_type
context_refs
requested_capability
max_cost
max_tokens
sensitivity
structured_output_schema
```

Gateway decides:
- no AI needed
- local model
- lower-cost model
- frontier model
- deny due to policy/budget

Never pass unbounded raw telemetry directly to a model.

---

## 13. Self-Improvement Safety Rules

The engine may automatically:
- calculate metrics
- create candidate changes
- run replay
- run regression tests
- rank proposals

The engine may not automatically:
- push untested rule changes to production
- disable detections
- weaken policy controls
- increase response permissions
- execute destructive remediation

Promotion must use explicit state transitions and audit events.

---

## 14. Frontend Requirements

Every page must include:
- clear page title
- contextual description
- filters
- loading state
- empty state
- error state
- permission-aware actions
- tenant-aware requests
- audit-safe user actions

Core screens:
1. Security Command Center
2. Live Alerts
3. Detection Engineering
4. ATT&CK Coverage
5. Incidents
6. Investigation Workbench
7. Entity Graph
8. Threat Hunting
9. Threat Intelligence
10. Endpoints
11. Network
12. Identity
13. Cloud
14. Vulnerabilities
15. Attack Surface
16. Telemetry Health
17. Automation
18. Approval Queue
19. Replay Lab
20. Self-Improvement
21. Blue Autopilot
22. AI SOC Analyst
23. Integrations
24. Platform Health
25. Audit

---

## 15. CI/CD Requirements

GitHub Actions must run:
- Python lint
- Python type check
- Python unit tests
- frontend lint
- frontend type check
- frontend tests
- migration tests
- API tests
- detection rule tests
- replay smoke tests
- tenant isolation tests
- secret scanning
- dependency scanning
- container scanning
- IaC scanning

Production deployment requires protected environment approval.

---

## 16. Initial Local Development Stack

Docker Compose services:
- postgres
- clickhouse
- opensearch
- redis
- redpanda
- minio
- api
- detection-engine
- correlation-engine
- web

Optional later:
- wazuh
- zeek test feed
- suricata test feed

Provide synthetic telemetry fixtures so the platform can be tested without real customer data.

---

## 17. Synthetic Security Dataset

Create fixtures covering:
- normal authentication
- brute force
- password spray
- impossible travel
- suspicious PowerShell
- malicious DNS
- command-and-control beaconing
- privilege escalation
- lateral movement
- suspicious download
- exfiltration-like traffic
- benign admin activity

Each fixture must declare expected detections.

---

## 18. Documentation Requirements

Maintain:
- architecture.md
- local-development.md
- deployment.md
- security-model.md
- multi-tenancy.md
- event-schema.md
- detection-sdk.md
- playbook-sdk.md
- ai-gateway.md
- self-improvement.md
- incident-response.md
- disaster-recovery.md
- evidence-provenance.md
- dfir-workbench.md
- blue-range.md
- quality-index.md
- visual-system.md
- design-tokens.md
- golden-reference-screens.md
- visual-regression.md

---

## 19. Cursor Working Protocol

For each phase Cursor must:
1. inspect existing repository first
2. identify what already exists
3. avoid unnecessary rewrites
4. implement smallest complete vertical slice
5. add tests with implementation
6. run tests
7. fix failures
8. update documentation
9. report files changed
10. report commands run
11. report tests passed/failed
12. report blockers truthfully

Do not mark a phase complete if tests were not actually executed.

---

## 20. Cursor Phase Completion Report Format

At the end of every phase return:

```text
PHASE:
STATUS: PASS / PARTIAL / BLOCKED / FAIL

IMPLEMENTED:
- ...

FILES CHANGED:
- ...

DATABASE/MIGRATIONS:
- ...

TESTS RUN:
- command
- result

SECURITY CHECKS:
- ...

OPEN ISSUES:
- ...

NEXT PHASE:
- ...
```

---

## 21. Final Product Standard

The finished platform must be able to:
- ingest security telemetry
- normalise it
- enrich it
- run deterministic detections
- correlate multi-stage activity
- assign entity and incident risk
- generate alerts
- support investigations
- support threat hunting
- track ATT&CK coverage
- identify telemetry gaps
- automate safe response actions
- require approval for high-impact actions
- replay historical telemetry
- validate new detections
- identify detection weaknesses
- propose controlled improvements
- use AI selectively
- remain operational when AI is unavailable
- preserve and verify evidence provenance
- perform packet/session-level investigation
- support deep DFIR workflows
- validate defensive capability in Blue Range
- compute evidence-backed detection, incident, and platform quality scores
- render premium, high-density security visualisations using the approved visual stack
- enforce golden-reference visual regression, accessibility, and performance gates

The implementation priority remains:

**Python first → deterministic rules → statistics/ML → AI only when necessary.**
