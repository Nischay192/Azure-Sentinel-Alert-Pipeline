"""
Nischay | 2026
detections.py

Detection rule loading and severity scoring for the Azure Sentinel
Alert Pipeline. Rules live in rules/*.yaml. Each rule describes a
KQL query plus metadata: MITRE tactics, base severity, entity
fields to extract, and optional volume-based severity modifiers.
"""

from pathlib import Path

import yaml


SEVERITY_LADDER = ["Informational", "Low", "Medium", "High", "Critical"]

PRIVILEGED_ACCOUNT_INDICATORS = [
    "admin",
    "svc",
    "root",
    "sysadmin",
    "sso",
    "_adm",
    "global",
    "privileged",
]


class Rule:
    """
    A detection rule loaded from a YAML file. Exposes parsed
    fields as attributes so the rest of the pipeline can reference
    them by name instead of dict-lookup everywhere.
    """

    def __init__(self, filename, data):
        """
        Build a Rule from its filename stem and the parsed YAML
        contents. Filename is kept so the pipeline can locate the
        matching sample file in dry-run mode.
        """
        self.filename = filename
        self.id = data["id"]
        self.name = data["name"]
        self.description = data.get("description", "").strip()
        self.base_severity = data.get("base_severity", "Medium")
        self.tactics = data.get("tactics", [])
        self.techniques = data.get("techniques", [])
        self.real_world_reference = data.get("real_world_reference", "").strip()
        self.entity_fields = data.get("entity_fields", {})
        self.volume_field = data.get("volume_field")
        self.volume_bump_threshold = data.get("volume_bump_threshold")
        self.query = data["query"]
        self.recommended_actions = data.get("recommended_actions", [])

    def __repr__(self):
        """Short debug representation used in pipeline log output."""
        return f"<Rule {self.id} {self.name}>"


def load_rules(rules_dir):
    """
    Read every .yaml file in rules_dir and return a list of Rule
    objects sorted by rule id. Sorting keeps detection ordering
    deterministic across runs so diffs are easy to read and the
    output lines up with the README.
    """
    rules = []
    path = Path(rules_dir)
    if not path.exists():
        return rules

    for yaml_path in sorted(path.glob("*.yaml")):
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)
        rule = Rule(yaml_path.stem, data)
        rules.append(rule)

    rules.sort(key=lambda r: r.id)
    return rules


def _bump_severity(current, levels=1):
    """
    Move a severity value up the ladder by the given number of
    levels. Caps at the top of the ladder so repeated bumps can
    never overflow past Critical.
    """
    if current not in SEVERITY_LADDER:
        return current
    idx = SEVERITY_LADDER.index(current)
    new_idx = min(idx + levels, len(SEVERITY_LADDER) - 1)
    return SEVERITY_LADDER[new_idx]


def _is_privileged_entity(value):
    """
    Decide whether a given entity value looks like a privileged
    account. Check is intentionally simple: lowercase substring
    match against a small list of indicators. False positives
    here only cause a severity bump, they never create an alert
    on their own, so being liberal is safe.
    """
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return any(indicator in lowered for indicator in PRIVILEGED_ACCOUNT_INDICATORS)


def score_severity(rule, row):
    """
    Start at the rule's base severity and apply modifiers based
    on the row contents, capped at Critical. Modifiers:

        1. Volume bump. If the rule declares a volume_field and
           the row value meets volume_bump_threshold, bump one
           level. This is how the same rule can fire Medium on
           11 failed logins and High on 200.

        2. Privileged entity bump. If any entity value in the
           row looks like a privileged account, bump one level.
           This models the truth that the same brute-force alert
           against an intern is Medium but against a Global
           Admin is High. Both bumps can stack.
    """
    severity = rule.base_severity
    bumps = 0

    if rule.volume_field and rule.volume_bump_threshold is not None:
        value = row.get(rule.volume_field)
        try:
            if value is not None and int(value) >= int(rule.volume_bump_threshold):
                bumps += 1
        except (TypeError, ValueError):
            pass

    for field in rule.entity_fields.values():
        entity_value = row.get(field)
        if _is_privileged_entity(entity_value):
            bumps += 1
            break

    if bumps:
        severity = _bump_severity(severity, bumps)
    return severity
