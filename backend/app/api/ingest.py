"""Event ingestion webhook (Wazuh manager / shipper -> platform)."""

from __future__ import annotations

import secrets
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..detection.correlation import correlate
from ..ingestion.normalize import normalize_wazuh_alert
from ..models import Alert
from ..schemas import AlertOut, IngestResponse
from ..security import client_ip

router = APIRouter(prefix="/api/ingest", tags=["ingest"])
settings = get_settings()
MAX_BATCH = 500


def verify_ingest_token(
    request: Request,
    x_ingest_token: Annotated[str | None, Header(alias="X-Ingest-Token")] = None,
) -> None:
    """Shared-secret authentication for the Wazuh webhook."""
    if not settings.ingest_token:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Ingestion disabled: INGEST_TOKEN is not configured",
        )
    provided = x_ingest_token or ""
    if not secrets.compare_digest(provided, settings.ingest_token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid ingest token")
    allowed = [ip.strip() for ip in settings.ingest_allowed_ips.split(",") if ip.strip()]
    if allowed and client_ip(request) not in allowed:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Source address not permitted")


def _payload_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict) and isinstance(payload.get("alerts"), list):
        items = payload["alerts"]
    elif isinstance(payload, dict):
        items = [payload]
    else:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Payload must be an alert object or array")
    if len(items) > MAX_BATCH:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"Batch limited to {MAX_BATCH} alerts")
    return items


@router.post("/wazuh", response_model=IngestResponse, dependencies=[Depends(verify_ingest_token)])
def ingest_wazuh(
    request: Request,
    payload: Annotated[Any, Body(...)],
    db: Session = Depends(get_db),
) -> IngestResponse:
    items = _payload_items(payload)
    accepted: list[Alert] = []
    duplicates = 0
    invalid = 0
    seen: set[str] = set()
    incident_ids: set[int] = set()

    for item in items:
        try:
            event = normalize_wazuh_alert(item if isinstance(item, dict) else {"full_log": str(item)})
        except ValueError:
            invalid += 1
            continue
        if event.alert_uid in seen:
            duplicates += 1
            continue
        seen.add(event.alert_uid)
        exists = db.execute(select(Alert.id).where(Alert.alert_uid == event.alert_uid)).first()
        if exists:
            duplicates += 1
            continue
        alert = Alert(**event.as_dict())
        db.add(alert)
        db.flush()
        incident, _created = correlate(db, alert)
        incident_ids.add(incident.id)
        accepted.append(alert)

    db.commit()
    for alert in accepted:
        db.refresh(alert)

    audit.record(
        db,
        action="ingest.wazuh",
        actor="wazuh-webhook",
        actor_role="integration",
        target=f"batch:{len(items)}",
        source_ip=client_ip(request),
        detail={
            "accepted": len(accepted),
            "duplicates": duplicates,
            "invalid": invalid,
            "incidents": sorted(incident_ids),
        },
        commit=True,
    )
    return IngestResponse(
        accepted=len(accepted),
        duplicates=duplicates,
        alerts=[AlertOut.model_validate(a) for a in accepted[:MAX_BATCH]],
        incidents=sorted(incident_ids),
    )
