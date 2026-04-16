"""
Nischay | 2026
pipeline.py

Azure Sentinel Alert Pipeline — main entry point. Loads detection
rules, executes their KQL against a Log Analytics workspace (or
against canned sample data in dry-run mode), scores each match for
severity, and writes out structured incident tickets.

Usage: python3 pipeline.py
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

import detections


SEVERITY_BANNER = {
    "Critical": "[CRIT]",
    "High": "[HIGH]",
    "Medium": "[MED ]",
    "Low": "[LOW ]",
    "Informational": "[INFO]",
}


def load_config(path="config.yaml"):
    """
    Load the pipeline configuration. The config controls whether
    the pipeline runs in dry-run mode against sample data or
    whether it hits a real Azure Sentinel workspace via the
    LogsQueryClient.
    """
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def query_logs_dry_run(rule):
    """
    Read a canned query result from samples/ that matches the
    rule filename. This lets the whole pipeline run end-to-end
    without any Azure credentials, which is how demos and local
    testing happen. The shape of the returned list matches what
    the live code path produces, so nothing downstream cares
    which mode ran.
    """
    sample_path = Path("samples") / f"{rule.filename}.json"
    if not sample_path.exists():
        print(f"  Warning: no sample file for {rule.id} at {sample_path}")
        return []
    with open(sample_path, "r") as f:
        return json.load(f)


def query_logs_live(rule, config):
    """
    Run a KQL query against a real Log Analytics workspace via
    the Azure Monitor Query SDK. Credentials come from the
    default credential chain, which honors environment variables,
    a managed identity, or az CLI login in that order. No client
    secrets live in this codebase on purpose.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.monitor.query import LogsQueryClient, LogsQueryStatus
    except ImportError:
        print("  Error: azure-monitor-query and azure-identity are required for live mode")
        print("         pip install -r requirements.txt")
        return []

    credential = DefaultAzureCredential()
    client = LogsQueryClient(credential)

    lookback = timedelta(hours=config.get("lookback_hours", 1))
    response = client.query_workspace(
        workspace_id=config["workspace_id"],
        query=rule.query,
        timespan=lookback,
    )

    if response.status != LogsQueryStatus.SUCCESS:
        print(f"  Warning: query for {rule.id} returned status {response.status}")
        return []
    if not response.tables:
        return []

    table = response.tables[0]
    columns = [col.name for col in table.columns]
    return [dict(zip(columns, row)) for row in table.rows]


def build_incident(rule, row, severity):
    """
    Build a structured incident ticket for a single detection
    match. The shape mirrors what a real SOC ticketing system
    would expect: identifiers, severity (base and bumped), MITRE
    ATT&CK tactics and techniques, extracted entities, raw
    evidence, and recommended analyst actions.
    """
    entities = {
        label: row.get(field, "unknown")
        for label, field in rule.entity_fields.items()
    }
    now_utc = datetime.now(timezone.utc)
    incident_id = f"{rule.id}-{now_utc.strftime('%Y%m%d%H%M%S%f')}"
    return {
        "incident_id": incident_id,
        "rule_id": rule.id,
        "rule_name": rule.name,
        "severity": severity,
        "base_severity": rule.base_severity,
        "tactics": rule.tactics,
        "techniques": rule.techniques,
        "description": rule.description,
        "real_world_reference": rule.real_world_reference,
        "entities": entities,
        "evidence": row,
        "created_at": now_utc.isoformat().replace("+00:00", "Z"),
        "recommended_actions": rule.recommended_actions,
    }


def execute_rule(rule, config):
    """
    Run one rule end-to-end: query logs (dry-run or live), score
    each row for severity, and return a list of incident dicts
    ready to be written to disk.
    """
    if config.get("dry_run", True):
        rows = query_logs_dry_run(rule)
    else:
        rows = query_logs_live(rule, config)

    incidents = []
    for row in rows:
        severity = detections.score_severity(rule, row)
        incidents.append(build_incident(rule, row, severity))
    return incidents


def write_incidents(incidents, output_dir):
    """
    Write every incident to disk as a JSON file under a new
    timestamped run directory. One directory per run makes it
    trivial to diff between runs, archive historical alerts, or
    pipe the output into a SOAR playbook.
    """
    now_utc = datetime.now(timezone.utc)
    run_dir = Path(output_dir) / now_utc.strftime("%Y%m%dT%H%M%SZ")
    run_dir.mkdir(parents=True, exist_ok=True)
    for incident in incidents:
        path = run_dir / f"{incident['incident_id']}.json"
        with open(path, "w") as f:
            json.dump(incident, f, indent=2, default=str)
    return run_dir


def format_entity_value(value):
    """
    Turn an entity value into a single line of display text.
    Lists get joined with commas so aggregated fields like
    make_set results render cleanly in the terminal.
    """
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def print_summary(incidents, rules, mode, run_dir):
    """
    Print a SOC-style shift report to the terminal. Header block
    with mode and counts, each incident summarized on a few
    lines with severity and key entities, then a count grouped
    by severity at the bottom.
    """
    print("=" * 72)
    print("  AZURE SENTINEL ALERT PIPELINE")
    print("=" * 72)
    print(f"  Mode:          {mode}")
    print(f"  Rules loaded:  {len(rules)}")
    print(f"  Incidents:     {len(incidents)}")
    if run_dir:
        print(f"  Output dir:    {run_dir}")
    print(f"  Run time:      {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}")
    print("=" * 72)

    if not incidents:
        print("\n  No detections fired. All clear.\n")
        return

    print("\n  INCIDENTS")
    print("-" * 72)
    ordered = sorted(
        incidents,
        key=lambda i: detections.SEVERITY_LADDER.index(i["severity"]),
        reverse=True,
    )
    for inc in ordered:
        tag = SEVERITY_BANNER.get(inc["severity"], "[????]")
        print(f"  {tag} {inc['rule_id']}  {inc['rule_name']}")
        for label, value in inc["entities"].items():
            print(f"         {label}: {format_entity_value(value)}")
        if inc["base_severity"] != inc["severity"]:
            print(f"         severity: {inc['base_severity']} -> {inc['severity']} (bumped)")
        print()

    counts = {}
    for inc in incidents:
        counts[inc["severity"]] = counts.get(inc["severity"], 0) + 1

    print("  SUMMARY BY SEVERITY")
    print("-" * 72)
    for level in reversed(detections.SEVERITY_LADDER):
        if counts.get(level):
            print(f"    {level}: {counts[level]}")
    print()


def main():
    """
    Entry point. Read config, load rules, execute each one,
    write incidents to disk, and print a summary report.
    """
    try:
        config = load_config()
    except FileNotFoundError:
        print("Error: config.yaml not found. Run from the project directory.")
        sys.exit(1)

    mode = "DRY-RUN (sample data)" if config.get("dry_run", True) else "LIVE (Azure Sentinel)"

    rules = detections.load_rules("rules")
    if not rules:
        print("No detection rules found in rules/")
        sys.exit(1)

    all_incidents = []
    for rule in rules:
        incidents = execute_rule(rule, config)
        all_incidents.extend(incidents)

    run_dir = None
    if all_incidents:
        run_dir = write_incidents(all_incidents, "incidents")

    print_summary(all_incidents, rules, mode, run_dir)


if __name__ == "__main__":
    main()
