# Sample investigations

These are excerpts of real API responses produced by `python -m app.sim.run` on the build host. Every
finding comes from the rule-based investigator, and each record carries `provider: heuristic` and
`model: rules-v1`. Confirmed facts and their alert IDs always trace back to stored alerts.

---

## INC-0001 — Repeated authentication failures on WKS-FIN-02

**Severity** high · **Priority** P2 · **Alerts** 8 · **Technique** T1110 · **Confidence** 0.62

**Investigator summary**

> Repeated authentication failures on WKS-FIN-02: 8 correlated alerts between 22:52:51 and 22:59:51.
> Confirmed observations: 8 authentication failures were recorded against a.chen, admin, j.smith from
> 203.0.113.45. The failures come from one source address (203.0.113.45), consistent with a
> password-guessing campaign from a single source. Open hypotheses: 3 distinct accounts were targeted,
> suggesting password spraying rather than a targeted guess.

| Nature | Finding | Evidence |
| --- | --- | --- |
| confirmed | 8 authentication failures recorded against a.chen, admin, j.smith from 203.0.113.45 | alerts 1–8 |
| confirmed | Failures come from one source address, consistent with password guessing | alerts 1–8 |
| hypothesis | 3 distinct accounts targeted — suggests password spraying | — |
| hypothesis | Volume and severity warrant escalation to tier 2 | — |

**Recommendations** (pending approval): `block_ip 203.0.113.45` (medium risk),
`disable_account a.chen` (high risk).

**Critic** — verdict `supported`, confidence 0.62. Missing information:

- No authentication outcome is present: we cannot tell whether any attempt succeeded.
- No endpoint telemetry (Sysmon 4624/4625 correlation) to confirm which host was targeted.

**Analyst takeaway:** block at the perimeter, confirm with the account owner whether any logon
succeeded, and check the workstation for interactive logons from 203.0.113.45.

---

## INC-0002 — Suspicious PowerShell execution on WKS-ENG-04

**Severity** critical · **Priority** P1 · **Alerts** 2 · **Technique** T1059.001 · **Confidence** 0.57

**Investigator summary**

> Suspicious PowerShell execution on WKS-ENG-04: 2 correlated alerts. Confirmed observations:
> PowerShell execution shows high-risk indicators: download string, encoded command, execution policy
> bypass, obfuscation. Open hypotheses: The encoded/obfuscated command may decode to a download cradle
> or in-memory payload; decoding the script block is required to confirm.

| Nature | Finding | Evidence |
| --- | --- | --- |
| confirmed | PowerShell shows download string, encoded command, policy bypass, obfuscation | alerts 9, 10 |
| hypothesis | Encoded command may decode to a download cradle / in-memory payload | — |
| hypothesis | No parent-process telemetry, launch chain cannot be confirmed | — |

**Recommendations:** `isolate_host WKS-ENG-04` (high), `collect_forensics WKS-ENG-04` (low).

**Critic** — verdict `supported`, confidence 0.57. Missing information: no parent process or user
context, encoded command not decoded, no file hashes or reputation data.

**Analyst takeaway:** isolate, capture the 4104 script block, decode the base64 payload, then decide
whether the endpoint needs reimaging.

---

## INC-0003 — Anomalous network activity on SRV-DC-01

**Severity** high · **Priority** P2 · **Alerts** 4 · **Technique** T1071 · **Confidence** 0.62

**Investigator summary**

> Outbound connections were observed to 198.51.100.77 from SRV-DC-01. Connection timing is highly
> regular (~60s apart, jitter 0.0s), which is characteristic of beaconing.

| Nature | Finding | Evidence |
| --- | --- | --- |
| confirmed | Outbound connections to 198.51.100.77 from SRV-DC-01 | alerts 11–14 |
| confirmed | Timing is highly regular (~60s, jitter 0.0s) — characteristic of beaconing | alerts 11–14 |
| hypothesis | Regular callbacks suggest C2 check-in rather than user-driven traffic | — |

**Recommendation:** `block_ip 198.51.100.77` (medium).

**Critic** — verdict `supported`. Missing: no DNS/proxy logs to attribute the domain, no NetFlow or
packet capture to confirm payload or protocol abuse.

**Analyst takeaway:** block the destination, then pull DNS and proxy logs for the same period, and check
whether any process on the DC resolves that address.

---

## INC-0004 — Account privilege change on LINUX-DB-03

**Severity** high · **Priority** P2 · **Alerts** 2 · **Technique** T1098 · **Confidence** 0.57

**Investigator summary**

> 1 privilege-related change was recorded involving svc-backup. Open hypotheses: A change to a
> privileged group can be legitimate administrative work; a change ticket or operator confirmation is
> needed before treating it as malicious.

**Recommendations:** `disable_account svc-backup` (high), `collect_forensics LINUX-DB-03` (low).

**Critic** — verdict `supported`. Missing: no change ticket or operator identity, no directory-service
audit trail for who performed the change.

**Analyst takeaway:** confirm with the platform owner whether `usermod -aG sudo svc-backup` was
scheduled. Disabling the service account can break backups, so this is a good example of why the critic
flags "legitimate admin work" as a live hypothesis instead of asserting malice.

---

## INC-0005 — Suspicious file or configuration change on WKS-ENG-04

**Severity** critical · **Priority** P1 · **Alerts** 2 · **Technique** T1565.001 · **Confidence** 0.57

**Investigator summary**

> 2 file or configuration changes were detected on WKS-ENG-04, including paths in protected system
> locations. Open hypotheses: The change may be the result of a dropper or persistence mechanism; file
> hashes and the creating process are not present in this evidence.

**Recommendation:** `isolate_host WKS-ENG-04` (high). In this run the action was **approved** by an
approver, which moved the incident to `contained` and wrote `action.approved` to the audit log with
`execution: "dry-run"`.

**Critic** — verdict `supported`. Missing: no file hashes or known-good baseline, no process telemetry
showing which binary wrote the files.

**Analyst takeaway:** the Startup-folder shortcut plus a modified system DLL is a classic persistence
pair. Contain first, then verify hashes against a known-good image.

---

## What these samples demonstrate

1. **Evidence discipline** — every confirmed claim lists the alert IDs it came from; hypotheses are
   explicitly separate.
2. **Independent review** — the critic re-derives counts and always lists what is *not* known.
3. **No false certainty** — with no model, confidence stays below 0.7 and the reason is recorded
4. **Human control** — actions are proposals with risk levels; approval is required and audited.
