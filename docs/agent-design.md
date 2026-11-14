# Agent design

Two agents, deliberately adversarial:

- **Investigator** builds the case: what happened, what is confirmed, what is hypothesis, how urgent,
  what should be done.
- **Critic** attacks the case: which conclusions are unsupported, what counts do not add up, what
  evidence is missing.

They never talk to each other directly. They communicate through the evidence bundle and the persisted
investigation records, which the orchestrator controls.

```mermaid
flowchart LR
    E[Evidence bundle<br/>tool output only] --> I[Investigator]
    E --> C[Critic]
    I -->|report| P[(Investigation record)]
    P --> C
    C -->|verdict, gaps| P
    P --> O[Orchestrator]
    O --> A[Pending actions]
```

## 1. Capability model

Agents receive **no** database handle, HTTP client or shell. Their entire universe is this registry
(`app/agents/tooling.py`):

| Tool | Arguments (strict) | Scope enforcement |
| --- | --- | --- |
| `get_incident_summary` | `incident_id` | must equal the assigned incident |
| `list_incident_alerts` | `incident_id`, `limit` 1–50 | must equal the assigned incident |
| `search_alerts` | `category?`, `severity?`, `since_minutes` 1–1440, `limit` 1–50 | only alerts sharing the incident entity |
| `get_host_activity` | `value`, `limit` 1–50 | host must appear in the incident |
| `get_ip_activity` | `value`, `limit` 1–50 | IP must appear in the incident |
| `get_user_activity` | `value`, `limit` 1–50 | user must appear in the incident |

Properties:

- Every argument model is pydantic with `extra="forbid"` and bounded integers/strings; `limit` above 50
  is rejected, so an agent cannot ask for "all alerts".
- Requests outside the incident scope raise `ToolPermissionError` and are recorded in the evidence
  bundle (`failures`), which the critic then reports.
- Results are trimmed (IDs, timestamps, key fields) rather than returning raw documents.
- The catalog is exposed read-only at `GET /api/agents/tools` (admin) with JSON Schema.

Denied by construction: shell execution, arbitrary network requests, database writes, credential
access, action approval.

## 2. Investigator

### Deterministic layer (always runs)

Per category it derives confirmed facts from the evidence:

| Category | Confirmed findings | Hypotheses it may raise |
| --- | --- | --- |
| `brute_force` | Failure count, targeted accounts, source address(es) | Password spraying vs targeted guessing, low volume benign |
| `powershell` | Which high-risk indicators appear (`EncodedCommand`, `DownloadString`, `-nop`, obfuscation) | Download cradle / in-memory payload, launch chain unknown |
| `network` | Destinations, beacon regularity (mean interval + jitter) | C2 check-in vs application polling |
| `privilege_change` | Privileged-group changes and affected accounts | Legitimate admin work pending change ticket |
| `file_integrity` | Changes, protected system paths involved | Dropper/persistence, hashes and writer unknown |

Priority comes from severity (`critical`→P1 … `info`→P5) and is never lowered by the model. Confidence
is a function of how many confirmed findings exist (capped at 0.85 when no model is involved).

### Model layer (optional)

The prompt contains a fixed security preamble plus the evidence bundle, with every untrusted block
wrapped as:

```xml
<untrusted source="evidence_bundle" redactions="1">
...sanitised alert titles, hosts, users, commands...
</untrusted>
```

The critic receives the investigator's report inside a second block
(`<untrusted source="investigator_report">`) so model-written prose is also data, not instruction.

The model must return JSON matching `InvestigatorOutput`: `summary`, `findings[]`
(`statement`, `evidence_alert_ids`, `confidence`, `nature`), `hypotheses[]`, `recommendations[]`,
`priority`, `confidence`, `attack_techniques[]`.

Grounding checks applied before anything is stored:

1. Reply must parse as a JSON object (code fences tolerated) and validate against the schema.
2. Every cited `evidence_alert_ids` entry must exist in the incident; otherwise the claim is dropped
   and recorded in `unsupported_claims`.
3. A `confirmed` claim without evidence is rejected.
4. Free text is re-sanitised (a model can echo injected instructions back).
5. Priority can only be raised relative to the incident's severity-derived priority.
6. Action types are restricted to `block_ip`, `isolate_host`, `disable_account`, `collect_forensics`.

If any of this fails, the investigation still completes with `provider="heuristic"` and a recorded
reason.

## 3. Critic

Independent verification runs deterministically first:

- Every `confirmed` finding must cite alerts that belong to the incident (else `unsupported`).
- Numeric claims are re-counted from evidence (e.g. "8 authentication failures").
- Category consistency is checked (a brute-force incident with no brute-force alerts is flagged).
- Missing information is enumerated per category — e.g. for PowerShell: no parent process, command not
  decoded, no hashes; for network: no DNS/proxy logs, no packet capture; for privilege changes: no
  change ticket.

Verdict logic:

| Condition | Verdict |
| --- | --- |
| No unsupported claims | `supported` |
| Some unsupported claims | `partially_supported` |
| Unsupported claims ≥ findings | `unsupported` |

The critic's confidence is the investigator's confidence discounted by 0.8 when issues exist (0.95
otherwise, capped at 0.9).

When a model is available, its review can add unsupported claims and missing information, but it
**cannot upgrade** a verdict that failed a deterministic check. Model `unsupported` verdicts are
always honoured.

## 4. Evidence grounding

Two rules keep the report honest:

| Rule | Enforcement |
| --- | --- |
| A "confirmed" finding must cite alert IDs that belong to the incident | The investigator only emits findings for alerts in the evidence bundle; the critic re-checks every ID and re-counts the numbers it asserts |
| An inference must stay an inference | The investigator records inference as a hypothesis; nothing promotes a hypothesis to confirmed without evidence |

Ingested text is still stripped of control characters and length-clamped at the ingestion boundary
(`ingestion/normalize.py`), because the analyst reads that text too.


## 5. Analysis engine

There is no model client, no provider probing and no API key. `investigate()` and `review()` are pure
functions over the evidence bundle, so the same incident always produces the same report
(`provider: heuristic`, `model: rules-v1`). That is deliberate: it runs offline and every sentence can
be traced back to a rule. The trade-off is that it only recognises the five behaviour families the
rules cover.


## 6. Recommendations and approvals

Recommendations become `ProposedAction` rows with `status=pending`, deduplicated per incident by
`(action_type, target)`. The incident moves to `awaiting_approval`.

An approver (or admin) approves or rejects with an optional note. Approval sets
`status=approved`, timestamps the decision, marks the incident `contained`, and writes
`action.approved` to the audit log with `execution: "dry-run"`. Nothing is actually blocked, isolated or
disabled — implementing that would require a real EDR/firewall adapter and is intentionally out of
scope.

## 7. Extension points

- **More tools** (e.g. threat-intel lookup) — must be read-only, schema-validated, and scoped; add to
  `TOOLS` and the test that asserts no write/shell tools exist.
- **More detectors** — add a pattern to `detection/rules.py` and a finding block in the investigator;
  add a scenario to `app/sim` and a test.
- **Queue-based investigations** — wrap `run_investigation` in a task; the persisted records already
  carry everything the UI needs.
