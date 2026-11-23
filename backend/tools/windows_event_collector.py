"""Ship real Windows Event Log records to the Aegis ingest webhook.

The collector reads events with PowerShell's Get-WinEvent (no extra Python
dependencies), maps the interesting Windows Security/System event IDs into the
platform's Wazuh-compatible alert shape, and posts them to
``POST /api/ingest/wazuh`` using the same token as a Wazuh manager would.

Security-channel events (sign-ins, account changes) require elevation; the
System and Application channels are readable by a normal user. Use
``tools/collect-security.cmd`` to start it with a UAC prompt.

Examples (run from ``backend/``)::

    .venv\\Scripts\\python tools\\windows_event_collector.py --once --dry-run --channel System --event-ids 7036
    .venv\\Scripts\\python tools\\windows_event_collector.py --once --channel System --event-ids 7036,7045
    .venv\\Scripts\\python tools\\windows_event_collector.py --channel Security --interval 20

State is kept per channel in ``data/windows_collector_state.json`` so repeated
runs resume where the last one stopped; alert IDs are derived from the channel
and Windows record ID, so replayed events are deduplicated by the API.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:  # allow ``from app...`` when run as a script
    sys.path.insert(0, str(BACKEND_ROOT))

DEFAULT_EVENT_IDS = "4625,4624,4672,4688,4720,4728,4732,4756,1102"
DEFAULT_STATE_FILE = BACKEND_ROOT / "data" / "windows_collector_state.json"
MAX_MESSAGE = 4000

# PowerShell emits one compressed JSON object per line (JSON Lines).
PS_SCRIPT = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

$channel = $env:AEGIS_CHANNEL
$max = [int]$env:AEGIS_MAX
$ids = @($env:AEGIS_IDS -split "," | Where-Object { $_ -ne "" } | ForEach-Object { [int]$_ })
# Get-WinEvent treats the StartTime value as local wall-clock time, so hand it
# LocalDateTime rather than the UTC instant (a UTC Kind shifts the window).
$since = [datetimeoffset]::Parse($env:AEGIS_SINCE, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).LocalDateTime

$filter = @{ LogName = $channel; StartTime = $since }
if ($ids.Count -gt 0) { $filter["Id"] = $ids }

try {
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $max -Oldest -ErrorAction Stop
} catch {
    $msg = $_.Exception.Message
    if ($msg -match "No events were found") { exit 0 }
    [Console]::Error.WriteLine($msg)
    if ($msg -match "unauthorized|access is denied|not authorized|privilege") { exit 3 }
    if ($msg -match "could not be found|does not exist|is not found") { exit 4 }
    exit 5
}

foreach ($e in $events) {
    $xml = [xml]$e.ToXml()
    $data = [ordered]@{}
    foreach ($node in $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
        $name = [string]$node.GetAttribute("Name")
        if ($name) { $data[$name] = [string]$node.InnerText }
    }

    $message = ""
    if ($e.Message) {
        $message = ($e.Message -replace "\s+", " ").Trim()
        if ($message.Length -gt 4000) { $message = $message.Substring(0, 4000) }
    }

    $record = [ordered]@{
        channel     = $channel
        recordId    = [int64]$e.RecordId
        id          = [int]$e.Id
        provider    = [string]$e.ProviderName
        timeCreated = $e.TimeCreated.ToUniversalTime().ToString("o")
        computer    = [string]$e.MachineName
        level       = [string]$e.LevelDisplayName
        message     = $message
        eventData   = $data
    }
    $record | ConvertTo-Json -Depth 4 -Compress
}
"""


def _clean(value: Any, limit: int = MAX_MESSAGE) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return text[:limit]


def _field(event_data: dict[str, Any], *names: str) -> str:
    """Case-insensitive lookup of an EventData field."""
    lowered = {str(key).lower(): value for key, value in (event_data or {}).items()}
    for name in names:
        value = lowered.get(name.lower())
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _valid_ip(value: str) -> str | None:
    text = value.strip()
    if not text or text in {"-", "::"}:
        return None
    try:
        return str(ip_address(text))
    except ValueError:
        return None


def _uid(event: dict[str, Any]) -> str:
    channel = _clean(event.get("channel"), 40) or "unknown"
    slug = re.sub(r"[^A-Za-z0-9]+", "-", channel).strip("-") or "unknown"
    host = _clean(event.get("computer"), 60) or "local"
    record_id = _clean(event.get("recordId"), 32) or "0"
    return f"win-{host}-{slug}-{record_id}"


def build_payload(event: dict[str, Any]) -> dict[str, Any]:
    """Map one raw Get-WinEvent record to an ingest-webhook alert document."""
    event_id = int(event.get("id") or 0)
    data = event.get("eventData") if isinstance(event.get("eventData"), dict) else {}
    channel = _clean(event.get("channel"), 60) or "Security"
    computer = _clean(event.get("computer"), 120) or "unknown"
    provider = _clean(event.get("provider"), 160)
    message = _clean(event.get("message"))
    timestamp = _clean(event.get("timeCreated"), 64)

    target = _field(data, "TargetUserName", "TargetUser", "MemberName")
    subject = _field(data, "SubjectUserName", "SubjectUser", "User")
    ip = _valid_ip(_field(data, "IpAddress", "SourceIp", "SourceAddress"))
    logon_type = _field(data, "LogonType")
    status = _field(data, "Status")
    substatus = _field(data, "SubStatus")
    workstation = _field(data, "WorkstationName", "Workstation")
    process = _field(data, "NewProcessName", "Image", "ProcessName")
    command_line = _field(data, "CommandLine", "ProcessCommandLine")
    group = _field(data, "TargetUserName", "GroupName") if event_id in {4728, 4732, 4756} else _field(data, "GroupName")
    member = _field(data, "MemberName", "MemberSid")

    level = 3
    groups = ["windows", re.sub(r"[^a-z0-9]+", "_", channel.lower()).strip("_") or "eventlog"]
    title = f"{provider} event {event_id}" if provider else f"Windows event {event_id}"
    user = target

    if event_id == 4625:
        user = target or subject
        level = 8
        title = f"Failed logon (4625) for account {user or 'unknown'}"
        if ip:
            title += f" from {ip}"
        groups += ["authentication_failures"]
    elif event_id == 4624:
        user = target or subject
        level = 3
        title = f"Successful logon (4624) for account {user or 'unknown'}"
        if ip:
            title += f" from {ip}"
    elif event_id == 4672:
        user = subject or target
        level = 5
        title = f"Special privileges assigned (4672) to {user or 'unknown'}"
    elif event_id == 4688:
        user = subject or target
        haystack = f"{process} {command_line}".lower()
        powershell = any(token in haystack for token in ("powershell", "pwsh", "-enc", "encodedcommand"))
        level = 10 if powershell else 5
        if powershell:
            title = f"PowerShell execution (4688): {process or command_line or 'process'}"
            groups += ["powershell"]
        else:
            title = f"Process created (4688): {process or 'unknown'}"
    elif event_id == 4720:
        user = target or subject
        level = 8
        title = f"New user account created (4720): {user or 'unknown'}"
    elif event_id in {4728, 4732, 4756}:
        user = member or target or subject
        level = 8
        title = f"User added to privileged group ({event_id}): {user or 'unknown'} -> {group or 'group'}"
    elif event_id == 1102:
        user = subject or target
        level = 12
        title = f"Audit log cleared (1102) by {user or 'unknown'}"
    elif event_id == 7045:
        service = _field(data, "ServiceName", "ImagePath")
        user = subject or target
        level = 7
        title = f"Service installed (7045): {service or 'unknown'}"

    details = [f"EventID {event_id}", f"Channel {channel}", f"Computer {computer}"]
    if provider:
        details.append(f"Provider {provider}")
    if user:
        details.append(f"Account {user}")
    if ip:
        details.append(f"Source {ip}")
    if logon_type:
        details.append(f"LogonType {logon_type}")
    if status or substatus:
        details.append(f"Status {status or '?'} SubStatus {substatus or '?'}")
    if workstation:
        details.append(f"Workstation {workstation}")
    if group:
        details.append(f"Group {group}")
    if command_line:
        details.append(f"CommandLine {command_line[:800]}")
    elif process:
        details.append(f"Process {process}")
    full_log = message or " | ".join(details)

    eventdata = {
        key: _clean(value, 2000)
        for key, value in {
            "targetUserName": user,
            "subjectUserName": subject,
            "ipAddress": ip or "",
            "logonType": logon_type,
            "workstationName": workstation,
            "status": status,
            "subStatus": substatus,
            "newProcessName": process,
            "commandLine": command_line,
            "groupName": group,
            "memberName": member,
            "serviceName": _field(data, "ServiceName"),
        }.items()
        if value
    }

    payload: dict[str, Any] = {
        "id": _uid(event),
        "timestamp": timestamp,
        "rule": {
            "id": f"win-{event_id}",
            "level": level,
            "description": title,
            "groups": groups,
        },
        "agent": {"id": "windows-local", "name": computer},
        "data": {
            "hostname": computer,
            "dstuser": user or None,
            "srcip": ip or None,
            "win": {
                "system": {
                    "computer": computer,
                    "eventID": str(event_id),
                    "channel": channel,
                    "providerName": provider,
                    "recordID": str(event.get("recordId") or ""),
                },
                "eventdata": eventdata,
            },
        },
        "full_log": full_log,
        "windows": event,
    }
    return payload


PROBE_SCRIPT = r"""
$ErrorActionPreference = "Stop"
try {
    $null = Get-WinEvent -LogName $env:AEGIS_CHANNEL -MaxEvents 1 -ErrorAction Stop
    exit 0
} catch {
    $msg = $_.Exception.Message
    if ($msg -match "No events were found") { exit 0 }
    [Console]::Error.WriteLine($msg)
    if ($msg -match "unauthorized|access is denied|not authorized|privilege") { exit 3 }
    exit 4
}
"""


def ensure_channel_access(channel: str) -> None:
    """Fail fast when the channel exists but the account may not read it.

    Filtered Get-WinEvent calls on a protected channel report "no events found"
    instead of an access error, which would otherwise look like an idle machine.
    """
    env = os.environ.copy()
    env["AEGIS_CHANNEL"] = channel
    process = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", PROBE_SCRIPT],
        capture_output=True,
        env=env,
        timeout=60,
    )
    stderr = process.stderr.decode("utf-8", errors="replace").strip()
    if process.returncode == 3:
        raise PermissionError(stderr or "Access denied reading the event log")
    if process.returncode == 4:
        raise FileNotFoundError(f"Event log channel '{channel}' is not available on this machine")
    if process.returncode != 0:
        raise RuntimeError(stderr or f"PowerShell exited with {process.returncode}")


def read_events(
    *, channel: str, event_ids: list[int], since: datetime, max_events: int
) -> list[dict[str, Any]]:
    """Invoke PowerShell once and return parsed Get-WinEvent records."""
    if os.name != "nt":
        raise RuntimeError("Windows Event Log collection only runs on Windows")

    env = os.environ.copy()
    env.update(
        {
            "AEGIS_CHANNEL": channel,
            "AEGIS_IDS": ",".join(str(i) for i in event_ids),
            "AEGIS_SINCE": since.astimezone(UTC).isoformat(),
            "AEGIS_MAX": str(max_events),
        }
    )
    process = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            PS_SCRIPT,
        ],
        capture_output=True,
        env=env,
        timeout=180,
    )
    stderr = process.stderr.decode("utf-8", errors="replace").strip()
    if process.returncode == 3:
        raise PermissionError(stderr or "Access denied reading the event log")
    if process.returncode == 4:
        raise FileNotFoundError(f"Event log channel '{channel}' is not available on this machine")
    if process.returncode != 0:
        raise RuntimeError(stderr or f"PowerShell exited with {process.returncode}")

    records: list[dict[str, Any]] = []
    for line in process.stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def collect(
    *, channel: str, event_ids: list[int], since: datetime, max_events: int = 200, pages: int = 10
) -> tuple[list[dict[str, Any]], datetime, bool]:
    """Read up to ``pages`` batches, returning (events, newest time, truncated)."""
    events: list[dict[str, Any]] = []
    cursor = since
    truncated = True
    for _ in range(pages):
        page = read_events(channel=channel, event_ids=event_ids, since=cursor, max_events=max_events)
        if not page:
            truncated = False
            break
        events.extend(page)
        newest = _newest(page, fallback=cursor)
        cursor = newest + timedelta(milliseconds=1)
        if len(page) < max_events:
            truncated = False
            break
    return events, _newest(events, fallback=since), truncated


def _newest(events: list[dict[str, Any]], *, fallback: datetime) -> datetime:
    times = [_parse_time(event.get("timeCreated")) for event in events]
    valid = [moment for moment in times if moment is not None]
    return max(valid) if valid else fallback


def _parse_time(value: Any) -> datetime | None:
    text = _clean(value, 64)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _load_token(explicit: str | None) -> str:
    if explicit:
        return explicit
    if os.environ.get("INGEST_TOKEN"):
        return os.environ["INGEST_TOKEN"]
    for candidate in (BACKEND_ROOT / ".env", Path.cwd() / ".env"):
        if not candidate.is_file():
            continue
        for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "INGEST_TOKEN" and value.strip():
                return value.strip().strip('"').strip("'")
    return ""


def post_alerts(*, api: str, token: str, alerts: list[dict[str, Any]]) -> dict[str, Any]:
    request = urllib.request.Request(
        api.rstrip("/") + "/api/ingest/wazuh",
        data=json.dumps({"alerts": alerts}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Ingest-Token": token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"API rejected the batch: HTTP {exc.code} {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach the API at {api}: {exc.reason}") from exc


def _load_state(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _initial_since(state: dict[str, Any], channel: str, since_minutes: float) -> datetime:
    stored = _parse_time((state.get(channel) or {}).get("since"))
    if stored:
        return stored
    return datetime.now(UTC) - timedelta(minutes=since_minutes)


def _classify_preview(payload: dict[str, Any]) -> str:
    try:
        from app.ingestion.normalize import normalize_wazuh_alert

        event = normalize_wazuh_alert(payload)
        return f"{event.category}/{event.severity}/{event.technique}"
    except Exception as exc:  # preview only - never block collection on it
        return f"classification preview unavailable ({exc})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ship real Windows Event Log records to the Aegis ingest webhook."
    )
    parser.add_argument("--channel", default="Security", help="Event log channel (default: Security)")
    parser.add_argument(
        "--event-ids",
        default=DEFAULT_EVENT_IDS,
        help=f"Comma-separated event IDs (default: {DEFAULT_EVENT_IDS}); empty = all events",
    )
    parser.add_argument("--api", default="http://127.0.0.1:8000", help="Aegis API base URL")
    parser.add_argument("--token", default=None, help="Ingest token (default: env/.env INGEST_TOKEN)")
    parser.add_argument("--state-file", default=str(DEFAULT_STATE_FILE), help="Checkpoint file")
    parser.add_argument(
        "--since-minutes",
        type=float,
        default=60,
        help="First-run backfill window when no checkpoint exists (default: 60)",
    )
    parser.add_argument("--max-events", type=int, default=200, help="Events per PowerShell call (max 200)")
    parser.add_argument("--interval", type=float, default=30, help="Seconds between polls")
    parser.add_argument("--once", action="store_true", help="Collect one batch and exit")
    parser.add_argument("--dry-run", action="store_true", help="Print mapped alerts; do not post or save state")
    args = parser.parse_args(argv)

    if os.name != "nt":
        print("This collector reads Windows Event Logs and only runs on Windows.", file=sys.stderr)
        return 2

    event_ids = [int(part) for part in args.event_ids.split(",") if part.strip()]
    token = _load_token(args.token)
    if not token and not args.dry_run:
        print(
            "No INGEST_TOKEN found. Set it in backend/.env, the environment, or --token.",
            file=sys.stderr,
        )
        return 2

    try:
        ensure_channel_access(args.channel)
    except PermissionError:
        print(
            f"Access denied reading the '{args.channel}' log.\n"
            "Security-channel events require elevation. Run tools\\collect-security.cmd "
            "(approve the UAC prompt), or add this account to the 'Event Log Readers' group.",
            file=sys.stderr,
        )
        return 3
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 4
    except Exception as exc:
        print(f"Could not open event log '{args.channel}': {exc}", file=sys.stderr)
        return 1

    state_path = Path(args.state_file)
    state = _load_state(state_path)
    since = _initial_since(state, args.channel, args.since_minutes)
    print(
        f"Collector: channel={args.channel} ids={event_ids or 'all'} api={args.api} "
        f"since={since.isoformat()} dry_run={args.dry_run}",
        flush=True,
    )

    while True:
        poll_started = datetime.now(UTC)
        try:
            events, newest, truncated = collect(
                channel=args.channel,
                event_ids=event_ids,
                since=since,
                max_events=max(1, min(args.max_events, 200)),
            )
        except PermissionError:
            print(
                f"Access denied reading the '{args.channel}' log.\n"
                "Security-channel events require elevation. Run tools\\collect-security.cmd "
                "(approve the UAC prompt), or add this account to the 'Event Log Readers' group.",
                file=sys.stderr,
            )
            return 3
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 4
        except Exception as exc:
            print(f"Event log read failed: {exc}", file=sys.stderr)
            return 1

        if events:
            alerts = [build_payload(event) for event in events]
            print(f"{poll_started.isoformat()} read {len(alerts)} new event(s)", flush=True)
            if args.dry_run:
                for alert in alerts[:10]:
                    print(
                        f"  {alert['timestamp']} [{alert['rule']['id']}] "
                        f"{alert['rule']['description']} -> {_classify_preview(alert)}",
                        flush=True,
                    )
                if len(alerts) > 10:
                    print(f"  ... {len(alerts) - 10} more", flush=True)
            else:
                accepted = duplicates = 0
                incidents: set[int] = set()
                for start in range(0, len(alerts), 500):
                    result = post_alerts(api=args.api, token=token, alerts=alerts[start : start + 500])
                    accepted += int(result.get("accepted", 0))
                    duplicates += int(result.get("duplicates", 0))
                    incidents.update(result.get("incidents", []))
                print(
                    f"  accepted={accepted} duplicates={duplicates} incidents={sorted(incidents)}",
                    flush=True,
                )
            since = newest + timedelta(milliseconds=1)
            if truncated:
                print(
                    "  warning: more events are waiting than the page limit allows; "
                    "run again or raise --max-events",
                    file=sys.stderr,
                )
            if not args.dry_run:
                state[args.channel] = {"since": since.isoformat(), "updated": poll_started.isoformat()}
                _save_state(state_path, state)
        else:
            # Nothing new: move the cursor forward so the query window stays small.
            since = poll_started - timedelta(minutes=2)
            if not args.dry_run:
                state[args.channel] = {"since": since.isoformat(), "updated": poll_started.isoformat()}
                _save_state(state_path, state)

        if args.once:
            return 0
        time.sleep(max(1.0, args.interval))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Collector stopped.", file=sys.stderr)
        raise SystemExit(0) from None
