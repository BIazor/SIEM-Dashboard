# Testing

## 1. Running the suites

```bash
# Backend (63 tests)
cd backend
.venv/Scripts/python -m pytest -q            # macOS/Linux: .venv/bin/python

# Frontend typecheck + production build
cd frontend
npm run build

# Optional: one package's tests with output
cd backend && .venv/Scripts/python -m pytest tests/test_agents.py -v
```

Tests run against a temporary SQLite file, with `ENVIRONMENT=test`, `LLM_PROVIDER=none` (no network) and
the login limiter reset between tests. No test touches the development database.

## 2. What is covered

| File | Tests | Focus |
| --- | --- | --- |
| `tests/test_auth.py` | 9 | Login, wrong password, unknown user, invalid email, rate limiting (429), `/me`, scrypt format/salting |
| `tests/test_ingest.py` | 10 | Token auth, brute-force correlation, dedupe, PowerShell/network/privilege/file classification, sanitisation, batch cap, payload shapes |
| `tests/test_agents.py` | 13 | Read-only tool catalogue, unknown-tool denial, strict args, scope enforcement, injection redaction, output validation, fabricated alert IDs, critic verification |
| `tests/test_api_security.py` | 10 | Auth requirements, viewer read-only, approver cannot investigate, analyst cannot approve, admin-only audit, security headers, CORS allow/deny, LIKE escaping, type validation |
| `tests/test_approvals.py` | 7 | Proposals after investigation, queue visibility, approval → contained + audit, rejection, 409 on double decision, manual status change |
| `tests/test_hardening.py` | 10 | Evidence and critic prompts redacted/wrapped, proxy-header trust gate, JWT subject handling, limiter key bound, seeder password policy, production config guards, approver-gated containment |
| `tests/test_windows_collector.py` | 4 | Windows Event Log mapping: 4625 → brute force with source IP, 4624 low-noise, 4688 PowerShell escalation, 4720/1102 severity and stable unique alert IDs |

Frontend verification is browser-based (Playwright, or Chrome DevTools Protocol when MCP is
unavailable) rather than unit-based: login, KPI render, alert/incident tables, incident detail agent
reports, approval decision, console and network checks.

The Windows collector is tested two ways: mapping unit tests above, and a live smoke run
`tools/windows_event_collector.py --once --channel System --event-ids 7040 --dry-run`. Real Security
events need an elevated shell; the collector exits 3 with instructions rather than silently reporting
an empty log.

## 3. Verified results

Recorded on the build host (Windows, Python 3.13.15, Node 24.14.0):

- `pytest -q` → **63 passed**
- `pytest --cov=app` → **80% statement coverage** (security 93%, ingest 89%, guardrails 90%, auth 97%)
- `npm run build` → **typecheck clean, 438 modules, built in ~2.2s**
- Independent live probe against the running API → **29/29 checks passed** (see `docs/security-audit.md`)
- Independent acceptance harness on an isolated database → **195/195 checks passed** (see
  `docs/acceptance-test-report.md`)
- Browser acceptance via Chrome DevTools Protocol → **33/33 checks passed**, 0 unexpected console
  errors, 0 failed requests (screenshots in `docs/acceptance-screenshots/`)
- Windows Event Log collector → **42/42 real System-channel records accepted**, 0 duplicates, one
  correlated incident; Security-channel reads correctly refused without elevation (NOT TESTED
  elevated; `tools/collect-security.cmd` provides the elevation prompt)

Checks performed in the browser run:

| Check | Result |
| --- | --- |
| Login form renders, credentials accepted | PASS |
| Dashboard KPIs and incident queue render | PASS |
| Console has no errors | PASS |
| No 4xx/5xx API requests | PASS |
| Incident list shows correlated incidents | PASS |
| Incident detail shows investigator + critic reports | PASS |
| Containment actions visible with risk/status | PASS |
| Critic verdict visible | PASS |
| Approval queue renders | PASS |
| Approve button applies a decision (pending count decreases) | PASS |
| Alert queue renders ingested data | PASS |

## 4. Simulated attack scenarios

`python -m app.sim.run` posts through the real webhook. Expected results (verified):

| Scenario | Events | Expected category | Expected severity | Detected behaviour |
| --- | --- | --- | --- | --- |
| `failed_logins` | 8 Windows 4625 failures from `203.0.113.45` | `brute_force` | high (levels 5 + 10) | One incident, 8 alerts, single-source password guessing, spray hypothesis, block + disable proposals |
| `suspicious_powershell` | 2 Sysmon 4104/4688 events with `-EncodedCommand` + `DownloadString` | `powershell` | critical (level 12) | Confirmed four high-risk indicators, isolate + forensics proposals |
| `beaconing_network` | 4 outbound connections to `198.51.100.77:4444`, 60s apart | `network` | high | Confirmed beacon regularity (~60s, jitter 0.0s), block-IP proposal |
| `privilege_change` | `usermod -aG sudo` + new account on a DB host | `privilege_change` | high | Confirmed privileged change, notes change-ticket gap, disable + forensics |
| `file_integrity` | Startup-folder autorun + modified system DLL | `file_integrity` | critical (level 12) | Confirmed protected-path change, isolate proposal |

Each investigation produces one investigator record and one critic record; verdicts are `supported`
when every confirmed finding is backed by incident alerts.

## 5. Manual verification workflow

1. Start the API (`uvicorn app.main:app --port 8000 --no-proxy-headers`) and the SPA (`npm run dev`).
2. Sign in as admin or analyst.
3. Run `python -m app.sim.run` and confirm "accepted / duplicates / incidents" per scenario.
4. Open each incident, run (or re-run) the investigation, and check:
   - confirmed findings cite alert IDs that exist in the table below,
   - hypotheses are in a separate block,
   - the critic verdict and missing-information list are populated,
   - "Model note" explains deterministic mode when no provider is configured.
5. Sign in as approver, open **Approvals**, approve one action and verify the incident becomes
   `contained`.
6. Sign in as admin and check **Audit log** for `investigation.completed` and `action.approved`.
7. Sign in as viewer and confirm write controls are absent and API calls to write endpoints return 403.

## 6. Negative tests worth repeating

| Attempt | Expected |
| --- | --- |
| `POST /api/ingest/wazuh` without token | 401 |
| `GET /api/alerts` without JWT | 401 |
| Viewer calls `/api/incidents/1/investigate` | 403 |
| Analyst calls `/api/approvals/1/decision` | 403 |
| Second decision on the same action | 409 |
| `q=%` search | 200 with 0 results (wildcard escaped, no error) |
| 501-alert batch | 413 |
| Alert with `srcip: "999.999.999.999"` | stored with `src_ip: null` |
| Failed logins with rotating `X-Forwarded-For` | 429 once the limit is reached (header ignored) |
| Signed JWT with `sub: "not-an-int"` | 401, never 500 |
| `X-Forwarded-For: 10.9.9.9` against a different `INGEST_ALLOWED_IPS` | 403 |

## 7. Gaps

- No coverage for the live LLM HTTP calls themselves (only the client contract and downstream
  validation, using a stub). Verified against a real provider: **no** — none was available.
- Docker Compose was not executed on the build host (Docker is not installed), so the images are
  unbuilt/unrun.
- No load/performance testing; investigations are synchronous.
- No automated accessibility audit (keyboard use is possible, labels exist on inputs).
