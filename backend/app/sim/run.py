"""Simulate attacks end-to-end against a running instance.

Usage (from backend/):
    python -m app.sim.run --investigate

It uses the real authenticated webhook, so the demo exercises ingestion,
normalisation, correlation, both agents and the approval queue.
"""

from __future__ import annotations

import argparse
import sys

import httpx

from ..config import get_settings
from .scenarios import SCENARIOS


def _login(client: httpx.Client, email: str, password: str) -> str:
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    if response.status_code != 200:
        raise SystemExit(
            f"Login failed ({response.status_code}). Check --email/--password or seed settings: "
            f"{response.text[:200]}"
        )
    return response.json()["access_token"]


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Push simulated Wazuh alerts into the SOC platform")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Backend base URL")
    parser.add_argument("--token", default=settings.ingest_token, help="Ingest token (default: INGEST_TOKEN)")
    parser.add_argument("--email", default=settings.seed_analyst_email, help="Analyst login email")
    parser.add_argument("--password", default=settings.seed_analyst_password, help="Analyst password")
    parser.add_argument("--no-investigate", action="store_true", help="Only ingest, do not run agents")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), help="Run a single scenario")
    args = parser.parse_args(argv)

    if not args.token:
        print("No ingest token configured. Set INGEST_TOKEN or pass --token.", file=sys.stderr)
        return 2

    selected = {args.scenario: SCENARIOS[args.scenario]} if args.scenario else SCENARIOS
    with httpx.Client(base_url=args.url.rstrip("/"), timeout=120.0) as client:
        total = 0
        incidents: list[int] = []
        for name, builder in selected.items():
            events = builder()
            response = client.post(
                "/api/ingest/wazuh",
                json={"alerts": events},
                headers={"X-Ingest-Token": args.token},
            )
            if response.status_code != 200:
                print(f"[{name}] ingest failed: HTTP {response.status_code} {response.text[:300]}", file=sys.stderr)
                return 1
            body = response.json()
            total += body["accepted"]
            incidents.extend(body["incidents"])
            print(
                f"[{name}] accepted={body['accepted']} duplicates={body['duplicates']} "
                f"incidents={body['incidents']}"
            )

        print(f"\nIngested {total} alerts across {len(set(incidents))} incidents.")

        if args.no_investigate:
            return 0

        token = _login(client, args.email, args.password)
        headers = {"Authorization": f"Bearer {token}"}
        print("\nRunning investigator + critic for each incident...\n")
        for incident_id in sorted(set(incidents)):
            response = client.post(f"/api/incidents/{incident_id}/investigate", headers=headers)
            if response.status_code != 200:
                print(f"  incident {incident_id}: investigation failed HTTP {response.status_code}")
                continue
            incident = response.json()
            investigator = next((i for i in incident["investigations"] if i["agent"] == "investigator"), None)
            critic = next((i for i in incident["investigations"] if i["agent"] == "critic"), None)
            print(
                f"  #{incident_id:<3} {incident['severity']:<8} P{incident['priority']} "
                f"{incident['status']:<18} {incident['title'][:52]}"
            )
            if investigator:
                print(
                    f"       investigator: {investigator['provider']:<9} "
                    f"confidence={investigator['confidence']} findings={len(investigator['findings'])}"
                )
            if critic:
                print(f"       critic:       verdict={critic['verdict']} confidence={critic['confidence']}")
            print(f"       proposed actions: {len(incident['actions'])}")

        print("\nOpen the dashboard, review the incidents and approve/reject proposed actions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
