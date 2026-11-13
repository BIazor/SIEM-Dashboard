"""Demo account seeding.

Passwords are never hard-coded: they come from environment variables and the seeder is
disabled unless ``SEED_DEMO_USERS=true``.  Only existing accounts are reported, never
their credentials.
"""

from __future__ import annotations

import logging

from sqlalchemy import select

from .config import get_settings
from .db import SessionLocal, init_db
from .models import User
from .security import hash_password

logger = logging.getLogger(__name__)


def ensure_demo_users() -> list[str]:
    settings = get_settings()
    if not settings.seed_demo_users:
        return []
    if settings.environment == "production":
        logger.error("SEED_DEMO_USERS is set in production; refusing to seed")
        return []

    accounts = [
        (settings.seed_admin_email, settings.seed_admin_password, "admin", "SOC Platform Admin"),
        (settings.seed_approver_email, settings.seed_approver_password, "approver", "Incident Approver"),
        (settings.seed_analyst_email, settings.seed_analyst_password, "analyst", "SOC Analyst"),
        (settings.seed_viewer_email, settings.seed_viewer_password, "viewer", "Read-only Analyst"),
    ]
    created: list[str] = []
    with SessionLocal() as db:
        for email, password, role, full_name in accounts:
            email = (email or "").strip().lower()
            if not email:
                continue
            if not password or len(password) < settings.min_password_length:
                logger.warning("Skipping seed for %s: no strong password configured", email)
                continue
            existing = db.execute(select(User).where(User.email == email)).scalars().first()
            if existing:
                continue
            db.add(User(email=email, full_name=full_name, role=role, password_hash=hash_password(password)))
            created.append(email)
        db.commit()
    return created


def main() -> None:
    init_db()
    created = ensure_demo_users()
    if created:
        print("Created accounts:", ", ".join(created))
    else:
        print("No accounts created (seeding disabled or accounts already exist).")


if __name__ == "__main__":
    main()
