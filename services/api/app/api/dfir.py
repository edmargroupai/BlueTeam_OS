from __future__ import annotations

from blueteam_dfir import (
    browser_artefact_contract,
    file_artefacts,
    host_timeline,
    memory_artefact_contract,
    network_timeline,
)
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission, get_request_id
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.evidence import evidence_manifest_hash, list_evidence
from app.services.ingestion import load_window

router = APIRouter(prefix="/dfir", tags=["dfir"])


@router.get("/timeline/host")
def get_host_timeline(
    host: str | None = None,
    actor: TenantActor = Depends(Permission("evidence:read")),
    db: Session = Depends(get_db),
) -> dict:
    items = host_timeline(load_window(db, actor.tenant_id), host=host)
    return {"items": items, "count": len(items)}


@router.get("/timeline/network")
def get_network_timeline(
    actor: TenantActor = Depends(Permission("evidence:read")),
    db: Session = Depends(get_db),
) -> dict:
    items = network_timeline(load_window(db, actor.tenant_id))
    return {"items": items, "count": len(items)}


@router.get("/artefacts/files")
def get_file_artefacts(
    actor: TenantActor = Depends(Permission("evidence:read")),
    db: Session = Depends(get_db),
) -> dict:
    return {"items": file_artefacts(load_window(db, actor.tenant_id))}


@router.get("/artefacts/contracts")
def artefact_contracts(_: TenantActor = Depends(Permission("evidence:read"))) -> dict:
    return {"browser": browser_artefact_contract(), "memory": memory_artefact_contract()}


@router.post("/export")
def export_manifest(
    actor: TenantActor = Depends(Permission("evidence:export")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    rows = list_evidence(db, actor.tenant_id)
    manifest = {
        "tenant_id": actor.tenant_id,
        "count": len(rows),
        "items": [
            {
                "id": row.id,
                "integrity_hash": row.integrity_hash,
                "object_uri": row.object_uri,
                "sealed": row.sealed,
                "source": row.source,
            }
            for row in rows
        ],
        "manifest_hash": evidence_manifest_hash(db, actor.tenant_id),
    }
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="dfir.evidence.export",
        target_type="evidence_manifest",
        after_state={"count": len(rows), "manifest_hash": manifest["manifest_hash"]},
    )
    return manifest
