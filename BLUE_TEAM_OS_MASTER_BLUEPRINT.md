# Blue Team OS Center — Master Blueprint

## 1. Purpose
Blue Team OS Center is a defensive cybersecurity operating system designed to ingest security telemetry, detect threats, correlate activity, investigate incidents, automate safe response actions, validate control coverage, and continuously improve detections.

The platform must be **code-first, Python-heavy, AI-gated, multi-tenant, auditable, and self-improving**.

Core principle:

**Telemetry → Normalise → Enrich → Detect → Correlate → Score → Investigate → Respond → Validate → Learn → Improve**

AI is never the default execution path. Deterministic code, rules, statistics, and local ML are preferred. Frontier AI is called only when it provides clear value.

---

## 2. Product Goals
1. Build a full defensive security operations platform, not a simple dashboard.
2. Make Python the primary backend and security-engine language.
3. Support real-time and historical security analytics.
4. Support SOC, detection engineering, threat hunting, DFIR, SOAR, ITDR, NDR, XDR, vulnerability intelligence, attack-surface management, threat intelligence, cloud defence, and security validation.
5. Support multi-tenant enterprise and MSSP operation from day one.
6. Make every high-impact action policy-controlled and fully audited.
7. Add continuous self-improvement using deterministic evaluation, replay, regression testing, canary rollout, and controlled promotion.
8. Keep AI operating cost low through strict routing and model policies.
9. Prevent AI from directly changing production security state without code validation and policy approval.
10. Maintain explainability for detections, correlations, scores, and automated response decisions.

---

## 3. Product Principles

### 3.1 Python First
Use Python for:
- ingestion workers
- parsers
- normalisation
- enrichment
- detection
- correlation
- risk scoring
- threat hunting
- vulnerability prioritisation
- telemetry health
- playbook execution
- replay testing
- detection validation
- security analytics
- self-improvement evaluation
- safe response execution

### 3.2 Rules Before AI
Priority order:
1. deterministic code
2. static rules
3. statistical models
4. lightweight/local ML
5. LLM only when needed

### 3.3 AI Last
AI may assist with:
- complex incident summaries
- analyst investigation recommendations
- natural-language hunt translation
- detection-rule drafting
- rule explanation
- threat-intelligence summarisation
- evidence summarisation
- root-cause hypotheses
- improvement proposals

AI must not directly:
- isolate a production host
- disable users
- modify firewall policies
- revoke privileged access
- push new production detections
- alter platform policies
- delete evidence

### 3.4 Every Action Is Audited
All state-changing actions must record:
- tenant_id
- actor_type
- actor_id
- request_id
- action
- target
- reason
- policy decision
- approval status
- before state
- after state
- result
- timestamp

---

## 4. High-Level Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                    BLUE TEAM OS CENTER UI                    │
│ Command │ Detect │ Investigate │ Hunt │ Defend │ Intel     │
└──────────────────────────────────────────────────────────────┘
                               │
                        Python FastAPI
                               │
┌──────────────────────────────────────────────────────────────┐
│                    SECURITY SERVICES                         │
│ Detection │ Correlation │ Risk │ Hunt │ IR │ SOAR │ Replay │
└──────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────────────────────────────────────┐
│                 EVENT PROCESSING FABRIC                      │
│ Redpanda/Kafka │ Redis │ Python Workers │ Scheduler         │
└──────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────────────────────────────────────┐
│                         DATA                                 │
│ PostgreSQL │ ClickHouse │ OpenSearch │ Object Storage       │
└──────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────────────────────────────────────┐
│                       SENSORS                                │
│ Wazuh │ Zeek │ Suricata │ Cloud │ Identity │ Email │ API   │
└──────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────────────────────────────────────┐
│                RESPONSE / CONTROL PLANE                      │
│ EDR │ IAM │ Firewall │ Email │ Cloud │ Tickets │ Playbooks │
└──────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────────────────────────────────────┐
│                 AI / INTELLIGENCE PLANE                      │
│ AI Gateway │ RAG │ Local ML │ Threat Intel │ Recommendations│
└──────────────────────────────────────────────────────────────┘
```

---

## 5. Technology Stack

### Frontend
- Next.js
- React
- TypeScript
- Tailwind CSS
- shadcn/ui
- TanStack Query
- Apache ECharts for operational charts, heatmaps, timelines, distributions, and high-density security dashboards
- Cytoscape.js for entity graphs, attack paths, lateral-movement maps, and relationship analysis
- React Flow for editable SOAR playbooks, defensive architecture maps, and analyst workflow diagrams
- PixiJS v8 for GPU-accelerated high-volume telemetry canvases, live network maps, animated packet/flow views, and dense visual scenes
- Rive for authored state-machine-driven micro-interactions, status visualisations, empty states, onboarding, and premium motion assets
- Motion for React for transitions, layout motion, gestures, drill-down continuity, and reduced-motion-aware animation
- SVGR for first-class typed SVG components
- Lucide icons for the core operational icon system
- Storybook for visual component development and review
- Playwright screenshot testing for automated visual-regression gates
- axe-core plus Lighthouse CI for accessibility and performance quality gates
- Style Dictionary or equivalent design-token build pipeline so colour, typography, spacing, radius, elevation, motion, and semantic status tokens are generated from source rather than manually duplicated

### Core Backend
- Python 3.12+
- FastAPI
- Pydantic v2
- SQLAlchemy 2
- Alembic
- httpx

### Security Engines
- Python
- Polars preferred for heavy tabular processing
- NumPy
- scikit-learn
- PyTorch only where justified
- NetworkX for graph prototypes

### Streaming and Queues
- Redpanda or Kafka
- Redis
- Dramatiq or Celery

### Storage
- PostgreSQL: control plane and application state
- ClickHouse: high-volume telemetry and analytics
- OpenSearch: search, detections, text and security-event exploration
- Redis: cache, ephemeral state, job coordination
- S3-compatible storage: evidence, exports, artefacts, replay datasets

### Security Tooling
- Wazuh
- Zeek
- Suricata
- Sigma
- YARA
- MITRE ATT&CK

### Identity
- OIDC/SAML-capable identity provider
- RBAC + ABAC
- MFA
- tenant-scoped policies

### Observability
- OpenTelemetry
- Prometheus
- Grafana
- structured JSON logging
- error tracing

### Infrastructure
- Docker
- Kubernetes when scale requires it
- Terraform
- GitHub Actions

### AI
- Provider-independent AI Gateway
- local/small models first where practical
- frontier models only when policy requires them
- structured output only
- cost budgets per tenant and feature

---

## 6. Core Domain Modules

### 6.1 Command Center
Capabilities:
- live security posture
- incident overview
- threat level
- top-risk entities
- ATT&CK coverage
- telemetry health
- automation status
- analyst workload
- risk trends

### 6.2 Detection Engineering
Capabilities:
- Sigma rules
- YARA rules
- Python detections
- sequence detections
- threshold detections
- anomaly detections
- correlation rules
- suppression rules
- exception management
- rule versioning
- detection-as-code
- rule replay
- rule performance analytics

### 6.3 Correlation and Attack Storylines
Capabilities:
- event correlation
- temporal correlation
- identity correlation
- host correlation
- cross-data-source correlation
- multi-stage attack detection
- attack storyline generation
- incident grouping

### 6.4 Security Analytics and Risk
Capabilities:
- user risk
- host risk
- identity risk
- IP risk
- cloud workload risk
- asset criticality
- alert confidence
- incident confidence
- behavioural anomaly scores

### 6.5 Threat Hunting
Capabilities:
- structured query language
- natural-language-to-query via AI gateway
- saved hunts
- IOC search
- entity search
- process trees
- DNS history
- network sessions
- authentication history
- historical replay
- hunt notebooks

### 6.6 Incident Response / DFIR
Capabilities:
- cases
- evidence
- timelines
- entity graph
- analyst notes
- chain of custody
- forensic artefacts
- affected assets
- response actions
- root cause
- lessons learned

### 6.7 SOAR and Automation
Capabilities:
- playbook builder
- Python playbook definitions
- event-triggered playbooks
- scheduled playbooks
- approval gates
- safe auto-actions
- rollback hooks where possible
- action audit trail

Action tiers:
- Tier 0: enrichment, queries, evidence gathering, notifications
- Tier 1: policy-approved safe containment
- Tier 2: human approval required

### 6.8 Threat Intelligence
Capabilities:
- IOC ingestion
- IOC scoring
- deduplication
- expiry/TTL
- actor tracking
- campaign tracking
- malware tracking
- TTP mapping
- ATT&CK mapping
- source confidence
- enrichment

### 6.9 Vulnerability and Exposure Management
Capabilities:
- CVE inventory
- CVSS
- exploitability
- threat-intel correlation
- asset criticality
- remediation priority
- external attack surface
- misconfiguration tracking
- remediation SLA

### 6.10 Endpoint Defence
Integrate with Wazuh initially.
Capabilities:
- process telemetry
- file activity
- registry changes
- services
- persistence
- endpoint health
- endpoint isolation requests

### 6.11 Network Defence
Integrate:
- Zeek
- Suricata

Capabilities:
- flow telemetry
- DNS
- HTTP
- TLS
- connection history
- IDS/IPS alerts
- beaconing
- C2 indicators
- lateral movement

### 6.12 Identity Threat Detection
Capabilities:
- password spray
- brute force
- credential stuffing
- MFA fatigue
- impossible travel
- dormant account use
- privilege escalation
- suspicious admin creation
- service account misuse
- session anomalies

### 6.13 Cloud Security
Support:
- AWS
- Azure
- GCP

Capabilities:
- cloud audit logs
- IAM anomalies
- exposed resources
- CSPM findings
- cloud workload risk
- container security
- serverless security

### 6.14 Telemetry Health Center
Capabilities:
- missing data sources
- silent agents
- parsing failures
- schema drift
- delayed events
- ingestion lag
- abnormal volume drop
- disabled audit logging
- sensor version health

### 6.15 ATT&CK Coverage Center
For each ATT&CK technique show:
- telemetry available
- detection available
- rule active
- validation status
- replay status
- last observed
- false-positive rate
- control coverage
- gap severity

### 6.16 Replay and Validation Lab
Capabilities:
- replay historical telemetry
- execute candidate detections
- compare current vs candidate
- measure TP/FP
- measure runtime cost
- regression tests
- detection canary rollout
- promotion gates

### 6.17 Blue Autopilot
Responsibilities:
- observe
- correlate
- score
- investigate
- gather evidence
- recommend
- execute Tier-0 actions
- execute Tier-1 actions only when policy allows
- request human approval for Tier-2 actions
- learn from outcomes

---

## 7. Unified Event Schema

Every source must map into a canonical internal model.

Required fields:
```text
id
tenant_id
timestamp
ingested_at
source
source_type
event_type
category
user
host
process
parent_process
src_ip
dst_ip
src_port
dst_port
protocol
domain
url
file
hash
identity
cloud_resource
action
outcome
severity
confidence
risk_score
raw_event
schema_version
```

All source-specific fields belong in an extensible attributes object.

---

## 8. Core PostgreSQL Entities

Minimum tables:
- tenants
- users
- roles
- permissions
- memberships
- integrations
- sensors
- sensor_health
- assets
- identities
- detections
- detection_versions
- detection_tests
- detection_exceptions
- detection_metrics
- alerts
- incidents
- incident_entities
- incident_events
- evidence
- investigations
- hunts
- hunt_queries
- threat_indicators
- threat_actors
- threat_campaigns
- malware_families
- vulnerabilities
- exposures
- playbooks
- playbook_versions
- playbook_runs
- response_actions
- approvals
- attack_techniques
- detection_coverage
- replay_datasets
- replay_runs
- improvement_candidates
- promotion_runs
- ai_requests
- ai_policies
- ai_budgets
- audit_logs

Every tenant-owned table must include tenant_id and enforce isolation.

---

## 9. Detection Rule Model

Required fields:
```text
rule_id
name
description
version
status
type
author
severity
confidence
mitre_tactics[]
mitre_techniques[]
data_sources[]
query_or_logic
suppression
exceptions
false_positive_notes
tests[]
performance_budget
last_validated_at
created_at
updated_at
```

Rule lifecycle:
```text
Draft → Lint → Unit Test → Replay → Review → Approved → Canary → Production → Retired
```

---

## 10. Self-Improvement Engine

### Inputs
- analyst dispositions
- alert outcomes
- false positives
- true positives
- missed detections
- rule latency
- incident outcomes
- ATT&CK gaps
- telemetry gaps
- suppression usage
- investigation results

### Python-computed metrics
- precision
- alert frequency
- false-positive rate
- detection latency
- rule cost
- duplicate rate
- analyst override rate
- coverage score

### Candidate Types
- threshold adjustment
- suppression update
- severity change
- rule merge
- new correlation
- new rule proposal
- telemetry recommendation
- ATT&CK gap recommendation

### Promotion Pipeline
```text
Candidate
→ Static Validation
→ Unit Tests
→ Historical Replay
→ Regression Tests
→ Policy Validation
→ Human Review if required
→ Canary
→ Production
```

The AI may propose improvements, but only deterministic code may validate and promote them.

---

## 11. AI Gateway Policy

All AI calls must pass through one gateway.

Decision flow:
```text
Request
→ Is AI required?
→ Can deterministic code answer?
→ Can cached result answer?
→ Can local model answer?
→ Select model
→ Redact/sanitise sensitive data
→ Apply token/cost budget
→ Call model
→ Validate structured output
→ Persist audit record
```

AI request audit fields:
- request_id
- tenant_id
- feature
- user_id
- reason
- selected_model
- provider
- prompt_hash
- redaction_applied
- input_tokens
- output_tokens
- cost
- latency
- validation_result
- created_at

---

## 12. Multi-Tenant Security

Requirements:
- tenant_id on all tenant data
- row-level application isolation
- database constraints
- per-tenant encryption strategy where applicable
- tenant-scoped API tokens
- tenant-scoped Kafka topics or partition keys
- tenant-scoped OpenSearch indices or strict filtered aliases
- tenant-scoped ClickHouse partitioning/logical separation
- cross-tenant access denied by default
- cross-tenant tests mandatory in CI

---

## 13. RBAC / ABAC Roles

Minimum roles:
- Platform Super Admin
- Tenant Owner
- Security Admin
- SOC Manager
- Senior Analyst
- Analyst
- Threat Hunter
- Detection Engineer
- Incident Responder
- Auditor
- Read Only

Use attribute-based constraints for:
- environment
- asset group
- incident severity
- response tier
- region
- business unit

---

## 14. Audit and Non-Repudiation

Audit all:
- logins
- permission changes
- detection changes
- policy changes
- response actions
- approval decisions
- evidence access
- exports
- AI requests
- automation runs
- integration changes

Audit logs should be append-only and protected against unauthorised modification.

---

## 15. UI Navigation

```text
COMMAND
- Security Command Center
- Live Operations
- Security Posture
- Executive View

DETECT
- Alerts
- Detection Engineering
- Correlations
- ATT&CK Coverage
- Detection Health

INVESTIGATE
- Incidents
- Investigation Workbench
- Entity Graph
- Timeline
- Forensics

HUNT
- Threat Hunting
- Hunt Library
- IOC Search
- Historical Search

DEFEND
- Endpoints
- Network
- Identity
- Cloud
- Email
- Applications
- Data

INTELLIGENCE
- Threat Intelligence
- Threat Actors
- Campaigns
- Malware
- Indicators
- Vulnerabilities

EXPOSURE
- Assets
- Attack Surface
- Vulnerabilities
- Misconfigurations
- Risk

AUTOMATION
- Playbooks
- Response Actions
- Automation Runs
- Approval Queue

ENGINEERING
- Rules
- Sensors
- Data Sources
- Replay Lab
- Validation
- Detection Tests

AUTONOMY
- Blue Autopilot
- Self-Improvement
- Recommendations
- Candidate Rules
- Learning History

AI
- SOC Analyst
- Investigations
- Model Gateway
- Usage
- AI Policies

ADMIN
- Organisations
- Users
- RBAC
- Integrations
- Audit
- Platform Health
```

---

## 16. Security Requirements

Mandatory:
- secure-by-default configuration
- secrets never committed
- OIDC/SAML authentication
- MFA support
- least privilege
- strict RBAC/ABAC
- CSRF/XSS/SQLi protections
- secure headers
- encrypted transport
- encryption at rest
- signed webhooks
- API rate limits
- anti-replay protections
- request IDs
- audit trail
- secure file upload pipeline
- malware scan before evidence ingestion where applicable
- dependency scanning
- secret scanning
- SAST
- container scanning
- IaC scanning
- SBOM generation
- threat modelling

---

## 17. Performance Goals

Initial architecture targets:
- API p95 under 300 ms for standard control-plane operations
- alert search p95 under 2 seconds on target development dataset
- streaming detection latency target under 5 seconds where source supports real time
- high-volume batch processing via ClickHouse/Polars
- no synchronous AI dependency for critical detection paths
- graceful degradation if AI provider fails

---

## 18. Reliability Goals

- idempotent ingestion
- dead-letter queues
- retry policies
- replay-safe consumers
- backpressure support
- health checks
- readiness checks
- structured errors
- service isolation
- disaster recovery strategy
- evidence durability

---

## 19. Testing Strategy

Required test levels:
- unit
- integration
- contract
- schema
- migration
- API
- RBAC
- tenant isolation
- detection rule tests
- replay tests
- regression tests
- performance tests
- security tests
- end-to-end
- chaos/failure tests for critical pipelines

No detection may reach production without tests.

---

## 20. Definition of Done

A feature is not complete until:
1. implementation is merged
2. unit tests pass
3. integration tests pass
4. tenant isolation is verified
5. audit events are present
6. permissions are enforced
7. errors are handled
8. telemetry exists
9. documentation is updated
10. security review passes
11. UI handles loading/empty/error states
12. no secrets are introduced
13. CI is green

---

## 21. Product Differentiators

Blue Team OS Center should differentiate through:
- Python-first defensive engine
- code-driven automated investigations
- attack storyline correlation
- entity risk graph
- telemetry health monitoring
- ATT&CK coverage graph
- historical replay lab
- detection-as-code
- controlled self-improvement
- Blue Autopilot
- AI usage only when justified
- transparent AI cost tracking
- policy-enforced response automation
- vendor-neutral sensor architecture

---

## 22. Non-Goals for Initial Versions

Do not initially build:
- custom endpoint kernel drivers
- custom packet capture engine
- custom SIEM storage engine
- unrestricted AI autonomy
- offensive security automation
- autonomous destructive response actions

Integrate strong open-source technologies first and build differentiation above them.

---

## 23. GSE-Calibre Defensive Engineering Standard

Blue Team OS Center must be engineered for the breadth, depth, practical reasoning, evidence discipline, and operational judgement expected from an elite senior defensive-security practitioner. GIAC GSE is a certification for people, not software, so the platform must never claim formal "GSE certification". Internally, however, **GSE-calibre** is the quality target.

Cursor must reason as if each security workflow will be reviewed by a practitioner capable of packet analysis, endpoint analysis, incident handling, detection engineering, continuous monitoring, threat hunting, defensive architecture, cloud/identity defence, and evidence-based response.

The platform receives no credit for a page, button, mock service, static graph, or generated narrative merely existing. Credit is earned only when the underlying defensive capability is demonstrably correct under tests and replay.

### 23.1 Twelve Defensive Quality Gates
Every production release must be evaluated across:
1. Network defence
2. Endpoint defence
3. Incident response
4. DFIR
5. Detection engineering
6. Continuous monitoring and telemetry health
7. Identity defence
8. Threat hunting
9. Defensive security architecture
10. ATT&CK validation and coverage
11. Response engineering
12. Controlled self-improvement

Each gate must have measurable tests, real backend implementation, evidence, failure cases, and an explicit quality score.

---

## 24. Deep DFIR and Evidence Workbench

Add a dedicated DFIR subsystem capable of handling or integrating evidence from:
- disk/file-system artefacts
- memory artefacts
- processes and process trees
- network sessions and PCAP references
- Windows Registry and persistence locations
- Linux and macOS persistence artefacts
- browser history where authorised
- authentication and identity evidence
- cloud audit logs
- email artefacts
- timeline reconstruction
- hashes and malware indicators
- forensic collection metadata
- chain of custody

Preferred integration targets include Velociraptor, Volatility, osquery, Plaso/Timesketch-compatible timelines, YARA, Sigma, Zeek, and Suricata. Integrations must be adapter-based; the platform must remain vendor-neutral.

### Evidence Objects
Every evidence object must record:
- evidence_id
- tenant_id
- incident_id
- source
- acquisition method
- original timestamp
- ingestion timestamp
- collector identity
- integrity hash
- immutable object-storage reference
- parser version
- transformation history
- chain-of-custody events

Evidence must never be silently rewritten.

---

## 25. Evidence Provenance and Confidence Hierarchy

All conclusions must be traceable to evidence. Use this hierarchy:

**Level 1 — Primary telemetry:** packets, endpoint events, raw logs, identity audit events, cloud audit records, forensic artefacts.

**Level 2 — Deterministic derived evidence:** Python correlation, IOC matches, parser output, rule matches, deterministic enrichment.

**Level 3 — Statistical inference:** anomaly scoring, clustering, behavioural baselines, probabilistic models.

**Level 4 — AI interpretation:** LLM summaries, hypotheses, query suggestions, narrative reconstruction.

**Level 5 — Analyst assessment:** human judgement and final disposition.

AI must never outrank contradictory primary evidence.

Every incident claim must expose:
- claim_id
- claim text
- confidence
- supporting evidence IDs
- contradicting evidence IDs
- inference type
- model/rule version
- unknowns
- analyst disposition

AI responses concerning incidents must use structured output and include valid evidence IDs. Reject unsupported evidence references.

---

## 26. Packet-Level and Session-Level Investigation

Network investigation must support a drill-down path:

**Alert → storyline → flow → connection → Zeek/Suricata evidence → PCAP/session reference → related entities → timeline.**

Required capabilities:
- PCAP metadata/reference ingestion
- DNS analysis
- TLS certificate and handshake metadata
- HTTP metadata
- NetFlow/IPFIX support through adapters
- beaconing analysis
- DNS-tunnelling indicators
- command-and-control patterns
- lateral-movement patterns
- port/service anomalies
- east-west and north-south analysis
- session reconstruction metadata

A network detection is not considered fully validated unless an analyst can inspect the evidence supporting it.

---

## 27. Defensive Architecture Center

Add a data-driven defensive architecture model representing:
- zones
- networks
- identities
- endpoints
- applications
- cloud accounts/subscriptions/projects
- workloads
- data stores
- trust boundaries
- controls
- sensors
- dependencies

The platform must overlay:
- active controls
- telemetry coverage
- known vulnerabilities
- active incidents
- ATT&CK techniques
- attack paths
- detection gaps
- trust-boundary violations

This becomes the bridge between SOC operations and defensible architecture.

---

## 28. Blue Range — Defensive Validation Environment

Create a safe, isolated **Blue Range** that generates synthetic or replayable defensive telemetry representing benign simulations of attack behaviours without providing offensive automation against external targets.

Scenarios should cover:
- phishing telemetry
- password spraying
- suspicious authentication
- privilege escalation
- PowerShell/script abuse telemetry
- persistence indicators
- lateral movement indicators
- command-and-control indicators
- data staging
- exfiltration indicators
- ransomware-like file-change telemetry
- cloud identity compromise indicators

For each scenario store:
- expected events
- expected detections
- expected correlations
- expected ATT&CK mappings
- expected incident storyline
- expected response recommendation
- allowed false-positive envelope
- maximum detection latency

Blue Range tests must run in CI and in the Replay Lab.

---

## 29. Blue Team OS Quality Index

Create an internal 1,000-point quality index:

| Domain | Points |
|---|---:|
| Network defence | 100 |
| Endpoint defence | 100 |
| Incident response | 100 |
| DFIR | 80 |
| Detection engineering | 100 |
| Threat hunting | 80 |
| Identity security | 80 |
| Cloud security | 70 |
| Defensive architecture | 70 |
| Threat intelligence | 50 |
| Response automation | 60 |
| Continuous monitoring | 50 |
| **Total** | **1,000** |

Internal maturity bands:
- 0–499: Prototype
- 500–649: Basic SOC
- 650–749: Professional
- 750–849: Advanced
- 850–924: Expert
- 925–974: GSE-calibre target band
- 975–1000: Elite defensive platform

Scores must be evidence-backed. A feature flag or UI page cannot award points.

---

## 30. Detection Quality Score

Every production detection receives a score calculated from measurable data:
- coverage
- precision
- validation
- telemetry health
- execution performance
- documentation quality
- replay performance
- regression status

Suggested classification:
- 95–100: Elite
- 90–94: Expert
- 80–89: Production
- 70–79: Needs improvement
- below 70: Not production-ready

The self-improvement engine must use this score but cannot automatically weaken a control solely to improve the number.

---

## 31. Incident Handling Quality Score

Closed incidents should be measured using:
- MTTD
- MTTA
- investigation time
- containment time
- recovery time
- scope completeness
- evidence completeness
- root-cause confidence
- response verification
- ATT&CK mapping completeness
- lessons captured
- detection improvements created
- incident reopen rate

Use team/process metrics to improve operations, not as simplistic employee surveillance.

---

## 32. Frontend Visual Systems Architecture

The UI must look and behave like a premium mission-critical security product. Cursor is explicitly prohibited from shipping generic dashboard graphics, random gradients, unstructured glowing cards, inconsistent iconography, fake 3D decoration, decorative charts that do not encode useful information, or stock-dashboard layouts copied across pages.

### 32.1 Visual Engine Selection
Use the right rendering engine for the right information:

- **Apache ECharts:** operational charts, heatmaps, histograms, timelines, distributions, stacked trends, confidence bands, matrix views.
- **Cytoscape.js:** large interactive entity graphs, attack paths, lateral movement, user-device-IP relationships, threat-intelligence graphs.
- **React Flow:** editable SOAR playbooks, defensive architecture diagrams, rule pipelines, investigation DAGs.
- **PixiJS v8:** GPU-accelerated dense/live canvases such as high-volume network flows, animated telemetry streams, large spatial security maps, or visual scenes where DOM/SVG becomes a bottleneck.
- **Rive:** carefully authored premium stateful illustrations and motion assets; never use it to obscure operational data.
- **Motion for React:** navigation continuity, panel transitions, drill-down transitions, contextual micro-interactions, and state changes.
- **SVG/SVGR:** precise reusable diagrams, icons, badges, technique markers, topology primitives, and exportable visuals.

Do not use a heavyweight renderer when a simple semantic DOM/SVG component is sufficient.

### 32.2 Golden Reference Screens
Before broad UI implementation, create and freeze pixel-level golden references for at least:
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

Every other page must derive its visual language from these references.

### 32.3 Automated Visual Quality Pipeline
Every PR affecting the UI must run:
1. Storybook build
2. component interaction tests
3. Playwright browser tests
4. screenshot capture at approved desktop widths
5. visual diff against golden images
6. axe accessibility checks
7. Lighthouse performance checks for representative routes
8. console-error check
9. broken-image/missing-asset check
10. reduced-motion test

Material visual differences require explicit approval or golden-reference update.

### 32.4 Design Token Automation
Maintain source-of-truth tokens for:
- semantic colours
- threat severity
- confidence
- evidence level
- typography
- spacing
- radius
- elevation
- borders
- graph edge types
- chart semantics
- motion duration
- easing
- density modes

Generate Tailwind/CSS/TypeScript token artefacts automatically. Do not hard-code random values in components.

### 32.5 Data-Driven Graphics Rule
Security graphics must be generated from real typed data models. No fake numbers in production UI. Empty/demo states must be explicitly labelled as demo/sample data.

### 32.6 UI Quality Gate
A UI phase fails if:
- data is unreadable at realistic density
- visual hierarchy is ambiguous
- the same status is represented inconsistently
- charts lack units/labels/context
- critical evidence cannot be reached from an alert
- graph interactions break keyboard access
- animation reduces comprehension
- reduced-motion is ignored
- screenshots differ materially from approved references without review
- visual performance collapses under realistic datasets

---

## 33. Visual Performance Targets

Set explicit performance budgets for visual surfaces:
- avoid unnecessary rerenders
- virtualise large tables
- progressive-load very large graphs
- cluster/aggregate high-density nodes
- use WebGL/PixiJS only when justified by data volume
- cap animation work when the tab is hidden
- pause nonessential live visualisations when off-screen
- respect reduced-motion preferences
- maintain responsive analyst interaction under realistic synthetic datasets

Performance tests must include representative large datasets, not only empty-state screenshots.

---

## 34. Product Principle: Evidence Before Aesthetics, Aesthetics Without Compromise

The visual system has two simultaneous obligations:
1. never sacrifice evidentiary clarity for decoration;
2. never accept poor visual craft simply because the underlying engine works.

The target is **elite operational clarity + premium visual execution**.

---

## 35. Final Architecture Philosophy

Blue Team OS Center must operate according to this hierarchy:

**Code first. Rules first. Data first. AI last.**

The OS must still detect, investigate, score, correlate, alert, and execute safe deterministic automations if every external AI provider is unavailable.
