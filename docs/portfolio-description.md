# Aegis SOC — portfolio copy

Copy is structured for a projects grid: the **bubble** line is what sits on the card, then the
**card summary** and **expanded detail** fill the panel that opens when someone clicks it.

---

## Bubble (on the card)

**Aegis SOC** — a security operations console that turns real Windows event logs into
investigated incidents and human-approved response.

_Tags:_ FastAPI · React · TypeScript · SQLite · Security Engineering

---

## Card summary (~50 words)

A SIEM-style analyst console built around a real problem: a security tool is only useful if an
analyst can trust it. Aegis ingests live Windows Event Log telemetry, correlates it into incidents,
and runs an investigator agent plus an independent critic — but a person still approves every
response action.

---

## Expanded detail (~180 words, for the opened panel)

Most "AI security" demos are a chatbot in front of fake data. Aegis is the opposite: it reads this
machine's actual Windows Security and System channels, normalises and deduplicates the events,
scores them for severity, maps them to MITRE ATT&CK, and groups related activity into incidents.

Each incident can be examined by two agents with separate jobs — an investigator that builds a case
citing specific event IDs, and a critic that tries to break it. Their output is only a recommendation.
Containment actions sit in an approval queue until a human with the right role decides, and every
decision lands in an append-only audit trail.

The UI is a working tier-1 workflow, not a mockup: alert triage with search and filters, incident
detail with the evidence both agents used, an approval queue, and the audit log. When no language
model is reachable the app says so and falls back to deterministic analysis rather than inventing a
narrative.

Honest scope: response actions are recorded as simulated (dry run), and the app runs on SQLite with a
synchronous investigation call — deliberate lab-scale choices.

---

## What I learned (first person, for the opened panel)

- **Reading real telemetry is mostly an access problem.** The Security channel needs elevation and
  failure auditing has to be enabled before failed logons even exist. I built a UAC-launched collector
  and a dry-run mode instead of instructing users to bypass Windows security.
- **Streaming logs means solving duplicates and restarts.** Alert IDs are derived from the channel and
  Windows record ID, with a checkpoint file, so replaying events after a restart does not double-count.
- **Giving an agent tools is a permissions exercise, not a prompting one.** Tools are read-only with
  strict schemas; nothing the model emits can write to the database, execute a command, or approve its
  own recommendation.
- **Untrusted text is untrusted even when it is "just a log line".** Event fields are sanitised and
  instruction-like phrases redacted, because an attacker can put text in a username.
- **Authorisation belongs on the server.** I found and fixed a role check that the UI hid but did not
  enforce; the fix plus a regression test taught me to verify every control by calling the API directly.
- **Trust is a feature.** The most valuable lesson was building the "no model available" path: a tool
  that admits its limits is more convincing than one that always has an answer.

---

## Tech stack

FastAPI · Python 3.13 · SQLAlchemy 2 · SQLite · JWT + scrypt · React 19 · TypeScript · Vite ·
Recharts · pytest (63 tests, 80% coverage)

---

## Demo

`docs/demo/aegis-soc-demo.mp4` — 20-second silent walkthrough of the live dashboard
(Overview → Alerts → incident investigation → approvals → audit trail).
