<!-- Nischay | 2026 -->
<!-- README.md -->

# Azure Sentinel Alert Pipeline

A Python pipeline that runs custom KQL detection rules against an Azure Sentinel workspace, scores every match for severity, and emits structured incident tickets. I built this because writing detection rules in the Sentinel UI is slow and impossible to version-control, and because most SOC teams eventually want a programmatic way to run the same queries on a schedule, feed the results into a ticketing system, and keep the rules in git like any other piece of code.

The pipeline works in two modes: **dry-run** against canned sample data (no credentials, no Azure cost) and **live** mode against a real Log Analytics workspace via the official `azure-monitor-query` SDK. The same code path handles both, which means you can demo the whole thing on a laptop and then flip one config flag to point it at production.

## What It Does

1. Loads every detection rule from `rules/*.yaml`. Each rule has metadata (MITRE tactics, base severity, entity fields, real-world references) plus a real KQL query written against the same tables Sentinel exposes — `SigninLogs`, `AuditLogs`, `AzureActivity`.
2. Executes each rule's query. In dry-run mode it reads a matching sample file from `samples/`; in live mode it hits the real Log Analytics workspace configured in `config.yaml`.
3. Scores every result row. Severity starts at the rule's `base_severity` and can be bumped one level for high-volume matches (e.g. 200 failed logins instead of 10) and another level if the entity looks like a privileged account (matches substrings like `admin`, `svc`, `sysadmin`, `global`, `privileged`, etc.). Bumps can stack and are capped at Critical.
4. Builds a structured incident ticket for every match. The shape matches what a real SOC tool expects: rule id, severity (base and bumped), MITRE tactics and techniques, extracted entities, the raw evidence row, and recommended analyst actions.
5. Writes each incident to `incidents/<run_timestamp>/<incident_id>.json` and prints a terminal summary grouped by severity, the same way a SOC shift report reads.

## How to Run

```bash
pip install -r requirements.txt
python3 pipeline.py
```

Dry-run is the default. You should see five rules fire against the sample data and get output like:

```
========================================================================
  AZURE SENTINEL ALERT PIPELINE
========================================================================
  Mode:          DRY-RUN (sample data)
  Rules loaded:  5
  Incidents:     10
  Output dir:    incidents/20260415T233209Z
========================================================================

  INCIDENTS
------------------------------------------------------------------------
  [CRIT] AS-001  Brute Force Sign-in Attempts
         account: john.admin@contoso.onmicrosoft.com
         source_ip: 45.227.253.109
         location: RU / MOW / Moscow
         severity: Medium -> Critical (bumped)

  [CRIT] AS-003  MFA Fatigue / Push Bombing
         account: contractor01@contoso.onmicrosoft.com
         source_ips: 193.32.163.11
         severity: High -> Critical (bumped)

  [CRIT] AS-004  Privileged Role Assignment
         actor: sysadmin@contoso.onmicrosoft.com
         target: temp.consultant@contoso.onmicrosoft.com
         role_added: "Global Administrator"
         severity: High -> Critical (bumped)

  [CRIT] AS-005  Mass Resource Deletion Burst
         caller: automation-svc@contoso.onmicrosoft.com
         source_ip: 52.168.33.14
         resource_group: rg-prod-web

  [HIGH] AS-002  Impossible Travel Between Sign-ins
         account: ceo@contoso.onmicrosoft.com
         locations: US / WA / Redmond, SG / 01 / Singapore
         ip_addresses: 20.124.88.17, 103.214.68.231

  [MED ] AS-001  Brute Force Sign-in Attempts
         account: marketing@contoso.onmicrosoft.com
         source_ip: 89.248.171.23
         location: NL / NH / Amsterdam

  SUMMARY BY SEVERITY
------------------------------------------------------------------------
    Critical: 5
    High: 4
    Medium: 1
```

Every line in the report maps back to a JSON file under `incidents/<timestamp>/` that contains the full evidence, MITRE mapping, and recommended actions.

### Running Against Real Azure Sentinel

When you're ready to point it at your actual workspace:

1. Open `config.yaml`, flip `dry_run: false`, paste in your Log Analytics `workspace_id` and `tenant_id`.
2. Sign in with the Azure CLI: `az login`. The `DefaultAzureCredential` in the pipeline picks that session up automatically — no client secrets in the code, no secrets in the repo.
3. Make sure the account you logged in as has the `Log Analytics Reader` role on the workspace.
4. Run `python3 pipeline.py` again.

The same pipeline code runs both paths. The only difference is where the rows come from.

## Detection Rules

Each rule is a single YAML file in `rules/`. Dropping another `.yaml` in that folder is enough to wire in a new detection — the pipeline auto-discovers them.

| Rule ID | Name | Table | Base Severity | Real-World Reference |
|---------|------|-------|---------------|----------------------|
| AS-001 | Brute Force Sign-in Attempts | SigninLogs | Medium | Lapsus$ credential attacks on Microsoft / Okta / Nvidia (2022) |
| AS-002 | Impossible Travel Between Sign-ins | SigninLogs | High | Classic ATP indicator, flagged by every major identity provider |
| AS-003 | MFA Fatigue / Push Bombing | SigninLogs | High | Uber breach (September 2022) |
| AS-004 | Privileged Role Assignment | AuditLogs | High | Midnight Blizzard / APT29 attack on Microsoft (January 2024) |
| AS-005 | Mass Resource Deletion Burst | AzureActivity | Critical | Code Spaces destruction event (2014), modern ransomware playbook |

## Severity Scoring

Base severity is fixed per rule. Two modifiers can bump it up, each by one level, capped at Critical:

- **Volume bump** — If the rule declares a `volume_field` and the row's value exceeds `volume_bump_threshold`, the severity moves up one level. The brute-force rule firing on 11 failed logins is Medium; the same rule firing on 200 failed logins is High. This encodes the reality that the alert is the same but the blast radius isn't.
- **Privileged entity bump** — If any entity extracted from the row matches a privileged-account pattern (`admin`, `svc`, `sysadmin`, `root`, `global`, `privileged`, etc.), severity moves up one level. A brute-force alert against an intern stays Medium. The same alert against `john.admin@contoso.onmicrosoft.com` goes High. The incident ticket records the original and the bumped severity so the analyst knows why.

Both modifiers stack. A high-volume brute-force attempt against `svc-backups` starts at Medium and lands at Critical, which is exactly what you want for a service account getting hammered.

## Project Structure

```
azure-sentinel-alert-pipeline/
├── README.md            <- you are here
├── pipeline.py          <- main entry: orchestrates everything
├── detections.py        <- rule loading + severity scoring
├── config.yaml          <- dry_run flag + workspace ids
├── requirements.txt
├── rules/               <- YAML detection rules (auto-discovered)
│   ├── brute_force_signin.yaml
│   ├── impossible_travel.yaml
│   ├── mfa_fatigue.yaml
│   ├── privileged_role_assignment.yaml
│   └── mass_resource_deletion.yaml
├── samples/             <- canned KQL results for dry-run mode
│   ├── brute_force_signin.json
│   ├── impossible_travel.json
│   ├── mfa_fatigue.json
│   ├── privileged_role_assignment.json
│   └── mass_resource_deletion.json
└── incidents/           <- generated output, one subdir per run (gitignored)
```

## Anatomy of a Detection Rule

Here's `mfa_fatigue.yaml` end-to-end — this is representative of every rule:

```yaml
id: AS-003
name: MFA Fatigue / Push Bombing
description: >
  Detects 5 or more MFA challenges denied or timed out for the
  same account in a 10 minute window...
base_severity: High
tactics: [InitialAccess, CredentialAccess]
techniques: [T1621]
real_world_reference: >
  In September 2022 Uber was breached by a Lapsus$ affiliate...
entity_fields:
  account: UserPrincipalName
  source_ips: SourceIPs
volume_field: MfaPromptCount
volume_bump_threshold: 15
query: |
  SigninLogs
  | where TimeGenerated > ago(1h)
  | where ResultType in (50074, 50158, 500121)
  | summarize MfaPromptCount = count(),
              FirstPrompt = min(TimeGenerated),
              LastPrompt = max(TimeGenerated),
              SourceIPs = make_set(IPAddress)
              by UserPrincipalName, bin(TimeGenerated, 10m)
  | where MfaPromptCount >= 5
recommended_actions:
  - Immediately revoke active sessions for the affected user
  - Reset the password and treat it as fully exposed
  - Enable number-matching MFA to defeat blind push approval
```

The rule is 100% declarative data. Adding a new detection means dropping another YAML in `rules/`. The Python code that executes it doesn't change.

## Why I Built It This Way

A few choices worth explaining in an interview:

- **YAML rules, not hardcoded Python detections.** Azure Sentinel itself ships analytic rule templates as YAML. Mirroring that convention means the rules can be code-reviewed, version-controlled, and potentially exported into real Sentinel Analytics Rules later. Every detection engineer I respect version-controls their detection logic.
- **Dry-run mode as a first-class citizen.** I didn't want a project that only works if you're already paying for a Sentinel workspace. Dry-run makes the pipeline runnable on day one with zero setup, and since the code path is identical to live mode, the production code path isn't paying any tax for it.
- **`DefaultAzureCredential`, never hardcoded secrets.** Hardcoded secrets are how people end up on breach blogs. The default credential chain works in dev (az CLI), CI (environment variables or workload identity), and production (managed identity), and it requires zero code changes between environments.
- **Severity bumping is data-driven, not per-rule code.** The same scorer runs against every rule. If the scoring logic ever needs to change — add a new modifier, change the ladder, whatever — it changes in exactly one place.
- **Every incident references a real breach.** The rules aren't abstract. Each one maps to something that actually happened: Lapsus$, Uber, Midnight Blizzard, Code Spaces. A detection rule you can't defend in an interview is a detection rule you don't really understand.

## Extending It

Every design choice in the pipeline points toward making new rules cheap to add. To write your own:

1. Copy one of the existing rule files as a template.
2. Change the `id`, `name`, `description`, `base_severity`, `tactics`, and `techniques`.
3. Write the KQL query. Test it directly in the Sentinel Logs blade first — if it returns rows there, it'll return rows here.
4. List the columns your query outputs that you want treated as entities in `entity_fields`.
5. If your rule has a natural "how much is happening" count, set `volume_field` and `volume_bump_threshold` so big matches auto-escalate.
6. Save the file in `rules/`, create a matching sample JSON in `samples/`, and run `python3 pipeline.py`.

No registration step. The loader picks it up on the next run.
