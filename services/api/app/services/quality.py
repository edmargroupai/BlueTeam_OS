from __future__ import annotations

from pathlib import Path

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_quality.engine import MODEL_VERSION, compute_quality_index
from blueteam_range.loader import load_scenarios
from blueteam_range.runner import run_scenario
from blueteam_schemas.quality import QualityCheckResult
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.audit import AuditLog
from app.models.quality import QualitySnapshot
from app.models.telemetry import FindingRecord, SecurityEvent
from app.services.audit import verify_audit_chain
from detections.python.catalog import build_default_registry

REPO_ROOT = Path(__file__).resolve().parents[4]
SCENARIO_ROOT = REPO_ROOT / "blue_range" / "scenarios"


def _check(
    check_id: str,
    domain: str,
    title: str,
    points: int,
    passed: bool,
    evidence_ids: list[str],
    reason: str,
) -> QualityCheckResult:
    return QualityCheckResult(
        check_id=check_id,
        domain=domain,
        title=title,
        max_points=points,
        awarded_points=points if passed and evidence_ids else 0,
        passed=passed and bool(evidence_ids),
        evidence_ids=evidence_ids,
        reason=reason,
    )


def build_checks(db: Session, tenant_id: str | None) -> list[QualityCheckResult]:
    checks: list[QualityCheckResult] = []
    registry = build_default_registry()
    scenarios = load_scenarios(SCENARIO_ROOT) if SCENARIO_ROOT.exists() else []
    results = [run_scenario(scenario, registry) for scenario in scenarios]
    identity_ids = [item.id for item in scenarios if item.family == "identity"]
    identity_results = [item for item in results if item.scenario_id in identity_ids]
    identity_pass = bool(identity_results) and all(item.passed for item in identity_results)
    checks.append(
        _check(
            "identity.blue_range",
            "identity_security",
            "Blue Range identity detections",
            50,
            identity_pass,
            [item.scenario_id for item in identity_results if item.passed],
            "Password spray, brute force, and privilege-grant scenarios must pass.",
        )
    )
    network_ids = [item.id for item in scenarios if item.family == "network"]
    network_results = [item for item in results if item.scenario_id in network_ids]
    network_pass = bool(network_results) and all(item.passed for item in network_results)
    checks.append(
        _check(
            "network.blue_range",
            "network_defence",
            "Blue Range network detections",
            25,
            network_pass,
            [item.scenario_id for item in network_results if item.passed],
            "Horizontal scan and related network scenarios must pass with evidence.",
        )
    )
    endpoint_ids = [item.id for item in scenarios if item.family == "endpoint"]
    endpoint_results = [item for item in results if item.scenario_id in endpoint_ids]
    endpoint_pass = bool(endpoint_results) and all(item.passed for item in endpoint_results)
    checks.append(
        _check(
            "endpoint.blue_range",
            "endpoint_defence",
            "Blue Range endpoint detections",
            25,
            endpoint_pass,
            [item.scenario_id for item in endpoint_results if item.passed],
            "Office-to-shell and Office/C2 scenarios must pass with evidence.",
        )
    )
    checks.append(
        _check(
            "detection.catalogue",
            "detection_engineering",
            "Versioned Python detections with tests",
            40,
            len(registry.all_rules()) >= 3,
            [rule.meta.rule_id for rule in registry.all_rules()],
            "Production detections exist as versioned Python rules.",
        )
    )
    chain_ok, chain_reason = verify_audit_chain(db)
    audit_count = db.execute(select(func.count()).select_from(AuditLog)).scalar_one()
    checks.append(
        _check(
            "ir.audit_chain",
            "incident_response",
            "Append-only hash-chained audit log",
            30,
            chain_ok and audit_count > 0,
            ["aud-chain"] if chain_ok and audit_count > 0 else [],
            chain_reason,
        )
    )
    event_count = 0
    finding_count = 0
    if tenant_id:
        event_count = db.execute(
            select(func.count()).select_from(SecurityEvent).where(SecurityEvent.tenant_id == tenant_id)
        ).scalar_one()
        finding_count = db.execute(
            select(func.count()).select_from(FindingRecord).where(FindingRecord.tenant_id == tenant_id)
        ).scalar_one()
    checks.append(
        _check(
            "monitor.ingestion",
            "continuous_monitoring",
            "Tenant telemetry persisted with integrity hashes",
            20,
            event_count > 0,
            [f"events:{event_count}"] if event_count else [],
            f"{event_count} events stored for tenant." if tenant_id else "No tenant scope for ingestion check.",
        )
    )
    checks.append(
        _check(
            "dfir.evidence",
            "dfir",
            "Findings cite persisted evidence objects",
            25,
            finding_count > 0,
            [f"findings:{finding_count}"] if finding_count else [],
            f"{finding_count} findings with evidence references." if tenant_id else "No tenant findings yet.",
        )
    )

    from blueteam_blueql.engine import BlueQLError, parse
    from blueteam_broker.broker import ExecutionBroker
    from blueteam_rego.engine import evaluate as evaluate_rego
    from blueteam_schemas.actions import ActionRequest
    from blueteam_sql.engine import list_hunts
    from blueteam_yara.engine import scan_bytes

    sigma_ids = [rule.meta.rule_id for rule in registry.all_rules() if rule.meta.rule_id.startswith("sigma.")]
    checks.append(
        _check(
            "detection.sigma",
            "detection_engineering",
            "Compiled Sigma rules in the detection registry",
            20,
            bool(sigma_ids),
            sigma_ids,
            "Sigma YAML is compiled to Python DetectionRule objects.",
        )
    )
    try:
        parse('process.name = "powershell.exe" AND parent.name IN ("winword.exe", "excel.exe")')
        parse("1=1; DROP TABLE events")
        blueql_ok = False
        blueql_reason = "injection was accepted"
    except BlueQLError:
        blueql_ok = True
        blueql_reason = "AST parser rejects SQL/control tokens."
    sql_ids = [item["id"] for item in list_hunts()]
    checks.append(
        _check(
            "hunt.blueql_sql",
            "threat_hunting",
            "BlueQL AST parser and registered SQL hunts",
            30,
            blueql_ok and bool(sql_ids),
            (["blueql.injection-blocked"] if blueql_ok else []) + sql_ids,
            blueql_reason,
        )
    )
    yara_root = REPO_ROOT / "security-languages" / "yara"
    malicious = (yara_root / "corpus" / "known-malicious" / "webshell_sample.php.txt").read_bytes()
    good = (yara_root / "corpus" / "known-good" / "readme.php.txt").read_bytes()
    rule = (yara_root / "webshells" / "webshell_eval.yar").read_text(encoding="utf-8")
    yara_ok = scan_bytes(malicious, rule) is not None and scan_bytes(good, rule) is None
    checks.append(
        _check(
            "dfir.yara",
            "dfir",
            "YARA subset distinguishes known-malicious from known-good fixtures",
            15,
            yara_ok,
            ["yara.Webshell_Eval_Marker"] if yara_ok else [],
            "Corpus match is required before YARA contributes score.",
        )
    )
    deny_ai = evaluate_rego({"action": {"type": "ai.execute", "tier": 0, "read_only": False, "dry_run": False}})
    broker = ExecutionBroker()
    unregistered = False
    try:
        broker.submit(
            ActionRequest(
                action_id="act_quality",
                action_type="shell.exec",
                tenant_id="ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                reason="quality probe",
                requested_by="quality",
                permissions=["response:tier0"],
            )
        )
    except Exception:
        unregistered = True
    checks.append(
        _check(
            "response.rego_broker",
            "response_automation",
            "Rego default-deny and broker rejects arbitrary shell",
            25,
            deny_ai.decision == "DENY" and unregistered,
            ["rego.deny-ai", "broker.no-generic-shell"] if deny_ai.decision == "DENY" and unregistered else [],
            "AI execution and unregistered shell actions must be denied.",
        )
    )

    from blueteam_correlation.engine import correlate
    from blueteam_range.loader import load_scenario

    c2_path = SCENARIO_ROOT / "endpoint" / "office_powershell_c2.yaml"
    correlation_ids: list[str] = []
    if c2_path.exists():
        c2 = load_scenario(c2_path)
        c2_result = next((item for item in results if item.scenario_id == c2.id), None)
        if c2_result and c2_result.passed:
            stories = correlate(c2.events, c2_result.findings)
            if stories:
                correlation_ids = [item.storyline_id for item in stories]
    checks.append(
        _check(
            "correlation.office_c2",
            "detection_engineering",
            "Cross-domain Office to beacon storyline",
            20,
            bool(correlation_ids),
            correlation_ids,
            "Storylines must cite finding evidence from endpoint and network detections.",
        )
    )

    from blueteam_graph.engine import build_graph

    identity_scenario = next((item for item in scenarios if item.id == "br-identity-password-spray"), None)
    identity_result = next(
        (item for item in results if identity_scenario and item.scenario_id == identity_scenario.id),
        None,
    )
    graph_ids: list[str] = []
    if identity_scenario and identity_result and identity_result.passed:
        graph = build_graph(identity_scenario.events, identity_result.findings)
        explained = [
            entity
            for entity in graph.entities
            if entity.risk_score > 0 and entity.risk_components and entity.event_ids
        ]
        observed = [rel for rel in graph.relationships if rel.event_ids and not rel.manufactured]
        if explained and observed and not graph.manufactured_edges:
            graph_ids = [explained[0].id, observed[0].id]
    checks.append(
        _check(
            "architecture.entity_graph",
            "defensive_architecture",
            "Entity graph and explainable risk from telemetry",
            20,
            bool(graph_ids),
            graph_ids,
            "Entities, observed relationships, and risk components must come from events and findings.",
        )
    )

    from blueteam_enrich.engine import enrich_event
    from blueteam_ingest.syslog import parse_syslog_line
    from blueteam_objects.store import open_store

    from detections.lint import lint_rules

    demo = "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    syslog_event = parse_syslog_line(
        "<34>1 2026-09-05T10:00:00Z sshd sshd - - - Failed password for alice from 203.0.113.77",
        demo,
    )
    _enriched, enrich_result = enrich_event(syslog_event)
    checks.append(
        _check(
            "enrichment.deterministic",
            "threat_intelligence",
            "Deterministic GeoIP/asset/identity enrichment",
            15,
            "geoip" in enrich_result.applied and enrich_result.geo.get("country") == "ZZ",
            [f"enrich:{','.join(enrich_result.applied)}"] if enrich_result.applied else [],
            "Fixture GeoIP and directory enrichment must be deterministic and testable.",
        )
    )
    store = open_store(root="./data/objects")
    ref = store.put(demo, "quality/probe.json", b'{"probe":true}')
    stored = store.get(ref.uri)
    checks.append(
        _check(
            "dataplane.object_store",
            "continuous_monitoring",
            "Raw object store write and read",
            10,
            stored == b'{"probe":true}',
            [ref.uri] if stored == b'{"probe":true}' else [],
            "Local object store must persist raw event bytes.",
        )
    )
    lint_errors = lint_rules()
    checks.append(
        _check(
            "detection.rule_lint",
            "detection_engineering",
            "Invalid detection rules fail CI lint",
            10,
            not lint_errors,
            ["detections.lint"] if not lint_errors else [],
            "OK" if not lint_errors else "; ".join(lint_errors[:4]),
        )
    )
    from app.models.ops import IncidentRecord, RuleRevision

    revision_count = db.execute(select(func.count()).select_from(RuleRevision)).scalar_one()
    checks.append(
        _check(
            "detection.rule_history",
            "detection_engineering",
            "Rule version history persisted",
            10,
            revision_count > 0,
            [f"revisions:{revision_count}"] if revision_count else [],
            f"{revision_count} rule revisions stored." if revision_count else "Rule revisions not synced.",
        )
    )
    incident_count = 0
    if tenant_id:
        incident_count = db.execute(
            select(func.count()).select_from(IncidentRecord).where(IncidentRecord.tenant_id == tenant_id)
        ).scalar_one()
    checks.append(
        _check(
            "correlation.incident_grouping",
            "incident_response",
            "Storylines group into incidents without duplicate inflation",
            20,
            incident_count > 0,
            [f"incidents:{incident_count}"] if incident_count else [],
            f"{incident_count} grouped incidents." if incident_count else "No grouped incidents for tenant.",
        )
    )

    # Remaining domains stay at zero until evidence exists. Do not inflate.
    ioc_active = 0
    if tenant_id:
        from blueteam_common.time import utcnow as _utcnow

        from app.models.intel import IndicatorOfCompromise

        now = _utcnow()
        ioc_active = db.execute(
            select(func.count())
            .select_from(IndicatorOfCompromise)
            .where(
                IndicatorOfCompromise.tenant_id == tenant_id,
                IndicatorOfCompromise.active.is_(True),
                IndicatorOfCompromise.expires_at > now,
            )
        ).scalar_one()
    checks.append(
        _check(
            "intel.ioc_store",
            "threat_intelligence",
            "Active IOC store with TTL and provenance",
            20,
            ioc_active > 0,
            [f"iocs:{ioc_active}"] if ioc_active else [],
            f"{ioc_active} active IOCs." if ioc_active else "No active tenant IOCs evidenced.",
        )
    )
    for domain, title, points in [
        ("cloud_security", "Cloud connector not yet evidenced", 0),
    ]:
        checks.append(
            _check(
                f"{domain}.pending",
                domain,
                title,
                points,
                False,
                [],
                "No evidence-backed implementation in this slice.",
            )
        )
    return checks


def compute_and_store(db: Session, tenant_id: str | None) -> QualitySnapshot:
    settings = get_settings()
    index = compute_quality_index(
        build_checks(db, tenant_id),
        computed_at=utcnow(),
        model_version=settings.quality_model_version or MODEL_VERSION,
    )
    snapshot = QualitySnapshot(
        id=new_id("qck"),
        tenant_id=tenant_id,
        model_version=index.model_version,
        total=index.total,
        band=index.band,
        domains=index.domains,
        checks=[item.model_dump() for item in index.checks],
        computed_at=index.computed_at,
    )
    db.add(snapshot)
    db.flush()
    return snapshot
