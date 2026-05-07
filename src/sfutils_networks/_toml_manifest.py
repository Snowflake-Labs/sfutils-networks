"""TOML manifest helpers for sfutils-networks multi-rule support.

Reads .sfutils/manifest.toml using stdlib tomllib (Python 3.12, read-only).
Writes using a hand-rolled serializer scoped to the manifest schema — no
external dependencies required.

Schema:

    schema_version = "1"
    project_name   = "my-project"
    created_at     = "2026-05-02T10:00:00Z"

    [snowflake]
    connection   = "local-oauth"   # default connection for all rules
    account      = "ABC12345"      # cached from snow connection test
    user         = "KAMESHS"
    account_url  = "https://abc12345.snowflakecomputing.com"
    sf_utils_db  = "KAMESHS_SF_UTILS"
    admin_role   = "ACCOUNTADMIN"

    [prereqs]
    tools_verified = "2026-05-02"
    infra_ready    = true

    [rule.kameshs-app-ingress]      # label is the TOML key, not a field
    status         = "COMPLETE"
    rule_name      = "KAMESHS_APP_INGRESS_RULE"
    rule_mode      = "INGRESS"
    rule_type      = "IPV4"
    value_list     = ["203.0.113.1/32", "198.51.100.0/24"]
    policy_name    = "KAMESHS_APP_INGRESS_POLICY"
    allow_github   = false
    allow_google   = false

    [rule.kameshs-app-ingress.resources]
    network_rule   = "KAMESHS_SF_UTILS.NETWORKS.KAMESHS_APP_INGRESS_RULE"
    network_policy = "KAMESHS_APP_INGRESS_POLICY"

    [rule.kameshs-app-ingress.cleanup]
    rule_name   = "KAMESHS_APP_INGRESS_RULE"
    policy_name = "KAMESHS_APP_INGRESS_POLICY"
    db          = "KAMESHS_SF_UTILS"
"""

from __future__ import annotations

import contextlib
import datetime
import os
import tomllib
from pathlib import Path

from sfutils_networks._presets import (
    NetworkRuleMode,
    NetworkRuleType,
    get_valid_types_for_mode,
    validate_mode_type,
)

MANIFEST_PATH = ".sfutils/manifest.toml"
SCHEMA_VERSION = "1"

# Ordered field lists drive the serializer — order is preserved in output.
# Note: no "label" — the label is the TOML key, not a field inside the table.
_RULE_SCALAR_KEYS = [
    "status",
    "created_at",
    "updated_at",
    "removed_at",
    "rule_name",
    "rule_mode",
    "rule_type",
    "value_list",
    "policy_name",
    "allow_github",
    "allow_google",
    "sf_utils_db",
    "admin_role",
    "eai",
    "policy",
]

_EAI_SCALAR_KEYS = [
    "name",
    "status",
    "operation",
    "created_at",
    "updated_at",
    "admin_role",
]

_POLICY_SCALAR_KEYS = [
    "name",
    "status",
    "operation",
    "created_at",
    "updated_at",
    "admin_role",
]

_SNOWFLAKE_KEYS = [
    "connection",
    "account",
    "user",
    "account_url",
    "sf_utils_db",
    "admin_role",
]

_PREREQS_KEYS = [
    "tools_verified",
    "infra_ready",
]

_ROOT_KEYS = [
    "schema_version",
    "project_name",
    "created_at",
]

# Sections that this serializer writes explicitly — everything else is passed through.
_OWNED_SECTIONS = {"snowflake", "prereqs", "rule", "eai", "policy"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today_iso() -> str:
    return datetime.date.today().isoformat()


def _escape_str(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _toml_value(v: object) -> str:
    """Serialize a Python value to a TOML literal string."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        items = ", ".join(f'"{_escape_str(str(i))}"' for i in v)
        return f"[{items}]"
    if isinstance(v, str):
        return f'"{_escape_str(v)}"'
    # Fallback — should not happen with our fixed schema
    return f'"{_escape_str(str(v))}"'


def _section_comment(title: str, width: int = 78) -> str:
    """Return a TOML comment line: '# ── {title} ──...──'."""
    fill = "─" * max(2, width - len(title) - 5)
    return f"# ── {title} {fill}"


def _write_table(section: dict, ordered_keys: list[str]) -> list[str]:
    """Serialize a flat dict in key-declaration order, then remaining keys."""
    lines: list[str] = []
    emitted: set[str] = set()
    for key in ordered_keys:
        if key in section:
            lines.append(f"{key:<20} = {_toml_value(section[key])}")
            emitted.add(key)
    for key, val in section.items():
        if key not in emitted:
            lines.append(f"{key:<20} = {_toml_value(val)}")
    return lines


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def ensure_manifest_defaults(data: dict, manifest_path: Path | str = MANIFEST_PATH) -> None:
    """Ensure *data* has all required top-level sections with sensible defaults.

    Called before writing a rule entry so the manifest is always well-formed,
    even when the prereqs init block was skipped.  Mutates *data* in place.

    Connection is NOT auto-filled here — that is the skill's responsibility
    (interactive picker at Step 1).  If SNOWFLAKE_DEFAULT_CONNECTION_NAME is
    already set in the environment, it is used as a silent fallback so CI/CD
    environments that export it don't need interactive prompting.
    """
    if "schema_version" not in data:
        data["schema_version"] = SCHEMA_VERSION
    if "project_name" not in data:
        # Derive from the project directory (parent of the .sfutils/ dir).
        data["project_name"] = Path(manifest_path).resolve().parent.parent.name
    if "created_at" not in data:
        data["created_at"] = _now_iso()

    if "snowflake" not in data:
        data["snowflake"] = {}
    sf = data["snowflake"]
    if not sf.get("connection"):
        sf["connection"] = os.environ.get("SNOWFLAKE_DEFAULT_CONNECTION_NAME", "")
    if not sf.get("sf_utils_db"):
        sf["sf_utils_db"] = (
            os.environ.get("SF_UTILS_DB")
            or os.environ.get("SFUTILS_DB")
            or os.environ.get("SNOW_UTILS_DB")
            or ""
        )
    sf.setdefault("admin_role", "ACCOUNTADMIN")

    if "prereqs" not in data:
        data["prereqs"] = {"tools_verified": _today_iso(), "infra_ready": False}
    data.setdefault("rule", {})
    data.setdefault("eai", {})
    data.setdefault("policy", {})
    # Silently promote any legacy integration_name/policy_name from cleanup/resources
    # to top-level [eai.*]/[policy.*] sections (additive, no version bump needed).
    promote_legacy_eai_policy_refs(data)


def load_manifest(path: Path | str = MANIFEST_PATH) -> dict:
    """Read manifest.toml.  Returns empty dict if the file is missing or
    cannot be parsed (tolerant — caller should not crash on missing manifest).
    """
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with p.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError:
        return {}


def save_manifest(path: Path | str, data: dict) -> None:
    """Write *data* to *path* as TOML.

    Creates the parent directory with mode 700 if needed.
    Sets the file mode to 600 after writing.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(p.parent, 0o700)

    lines: list[str] = ["# Machine-managed by Cortex Code. Do not hand-edit."]

    # Root-level scalars
    for key in _ROOT_KEYS:
        if key in data:
            lines.append(f"{key:<14} = {_toml_value(data[key])}")
    # Any extra root scalars not in the ordered list
    for key, val in data.items():
        if key not in _ROOT_KEYS and not isinstance(val, (dict, list)):
            lines.append(f"{key:<14} = {_toml_value(val)}")

    # [snowflake]
    if "snowflake" in data:
        _sc = _section_comment("Shared Snowflake connection (captured once, reused by all rules)")
        lines += ["", _sc, "[snowflake]"]
        lines += _write_table(data["snowflake"], _SNOWFLAKE_KEYS)

    # [prereqs]
    if "prereqs" in data:
        lines += ["", _section_comment("Tool / infra pre-flight cache")]
        lines += ["[prereqs]"]
        lines += _write_table(data["prereqs"], _PREREQS_KEYS)

    # [rule.<label>] named tables — label is the TOML key, not a field
    for label, rule in data.get("rule", {}).items():
        lines += ["", _section_comment(f"Rule: {label}")]
        lines += [f"[rule.{label}]"]
        # Scalar fields in declared order
        emitted: set[str] = set()
        for key in _RULE_SCALAR_KEYS:
            if key in rule:
                lines.append(f"{key:<20} = {_toml_value(rule[key])}")
                emitted.add(key)
        for key, val in rule.items():
            if key not in emitted and not isinstance(val, dict):
                lines.append(f"{key:<20} = {_toml_value(val)}")

        # [rule.<label>.resources] subtable
        if "resources" in rule:
            lines += ["", f"[rule.{label}.resources]"]
            for k, v in rule["resources"].items():
                lines.append(f"{k:<20} = {_toml_value(v)}")

        # [rule.<label>.cleanup] subtable
        if "cleanup" in rule:
            lines += ["", f"[rule.{label}.cleanup]"]
            for k, v in rule["cleanup"].items():
                lines.append(f"{k:<20} = {_toml_value(v)}")

    # [eai.<label>] named tables
    for label, eai in data.get("eai", {}).items():
        lines += ["", _section_comment(f"EAI: {label}")]
        lines += [f"[eai.{label}]"]
        emitted: set[str] = set()
        for key in _EAI_SCALAR_KEYS:
            if key in eai:
                lines.append(f"{key:<20} = {_toml_value(eai[key])}")
                emitted.add(key)
        for key, val in eai.items():
            if key not in emitted and not isinstance(val, dict):
                lines.append(f"{key:<20} = {_toml_value(val)}")
        # [eai.<label>.rules] subtable
        if "rules" in eai:
            lines += ["", f"[eai.{label}.rules]"]
            for k, v in eai["rules"].items():
                lines.append(f"{k:<30} = {_toml_value(v)}")

    # [policy.<label>] named tables
    for label, pol in data.get("policy", {}).items():
        lines += ["", _section_comment(f"Policy: {label}")]
        lines += [f"[policy.{label}]"]
        emitted = set()
        for key in _POLICY_SCALAR_KEYS:
            if key in pol:
                lines.append(f"{key:<20} = {_toml_value(pol[key])}")
                emitted.add(key)
        for key, val in pol.items():
            if key not in emitted and not isinstance(val, dict):
                lines.append(f"{key:<20} = {_toml_value(val)}")
        # [policy.<label>.rules] subtable
        if "rules" in pol:
            lines += ["", f"[policy.{label}.rules]"]
            for k, v in pol["rules"].items():
                lines.append(f"{k:<30} = {_toml_value(v)}")

    # Preserve sections not owned by sfutils-networks (e.g. [pat.*], [volume.*], [openflow])
    for key, val in data.items():
        if not isinstance(val, dict):
            continue
        if key in _OWNED_SECTIONS:
            continue
        # Dotted keys like "rule.label" are sub-tables already written above
        if "." in key:
            continue
        lines += ["", _section_comment(f"{key} (preserved by sfutils-networks)"), f"[{key}]"]
        for k, v in val.items():
            if isinstance(v, dict):
                lines += ["", f"[{key}.{k}]"]
                for sk, sv in v.items():
                    lines.append(f"{sk:<20} = {_toml_value(sv)}")
            else:
                lines.append(f"{k:<20} = {_toml_value(v)}")

    content = "\n".join(lines) + "\n"
    p.write_text(content, encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(p, 0o600)


def get_rule_entry(
    data: dict,
    *,
    rule_name: str | None = None,
    label: str | None = None,
) -> dict | None:
    """Return the rule entry for *label* (O(1)) or the first entry matching
    *rule_name* (linear scan).  Returns None if not found.
    """
    rules = data.get("rule", {})
    if label:
        return rules.get(label)
    if rule_name:
        for entry in rules.values():
            if entry.get("rule_name", "").upper() == rule_name.upper():
                return entry
    return None


def upsert_resource(data: dict, label: str, rule_config: dict) -> None:
    """Add or replace the rule entry for *label*.

    The label is the TOML key — it must not appear as a field inside
    *rule_config*.  Mutates *data* in place; caller must call save_manifest().
    """
    data.setdefault("rule", {})[label] = rule_config


def update_resource_status(data: dict, rule_name: str, status: str) -> None:
    """Set *status* on the rule entry matching *rule_name*.

    Sets *removed_at* when status is REMOVED.
    Mutates *data* in place — caller must call save_manifest() afterwards.
    """
    now = _now_iso()
    for entry in data.get("rule", {}).values():
        if entry.get("rule_name", "").upper() == rule_name.upper():
            entry["status"] = status
            entry["updated_at"] = now
            if status == "REMOVED":
                entry["removed_at"] = now
            return


def upsert_eai(data: dict, label: str, eai_config: dict) -> None:
    """Add or replace an EAI entry. Mutates data in place; caller calls save_manifest()."""
    data.setdefault("eai", {})[label] = eai_config


def upsert_policy_entry(data: dict, label: str, policy_config: dict) -> None:
    """Add or replace a Policy entry. Mutates data in place; caller calls save_manifest()."""
    data.setdefault("policy", {})[label] = policy_config


def get_eai_entry(
    data: dict,
    *,
    name: str | None = None,
    label: str | None = None,
) -> dict | None:
    """Return EAI entry by label (O(1)) or by name (linear scan)."""
    eais = data.get("eai", {})
    if label:
        return eais.get(label)
    if name:
        for entry in eais.values():
            if entry.get("name", "").upper() == name.upper():
                return entry
    return None


def get_eai_label_for_name(data: dict, name: str) -> str | None:
    """Return the TOML label for an EAI with the given name, or None."""
    for label, entry in data.get("eai", {}).items():
        if entry.get("name", "").upper() == name.upper():
            return label
    return None


def get_policy_label_for_name(data: dict, name: str) -> str | None:
    """Return the TOML label for a policy with the given name, or None."""
    for label, entry in data.get("policy", {}).items():
        if entry.get("name", "").upper() == name.upper():
            return label
    return None


def update_eai_status(data: dict, eai_name: str, status: str) -> None:
    """Set status on the EAI entry matching eai_name. Mutates data in place."""
    now = _now_iso()
    for entry in data.get("eai", {}).values():
        if entry.get("name", "").upper() == eai_name.upper():
            entry["status"] = status
            entry["updated_at"] = now
            if status == "REMOVED":
                entry["removed_at"] = now
            return


def update_policy_status(data: dict, policy_name: str, status: str) -> None:
    """Set status on the policy entry matching policy_name. Mutates data in place."""
    now = _now_iso()
    for entry in data.get("policy", {}).values():
        if entry.get("name", "").upper() == policy_name.upper():
            entry["status"] = status
            entry["updated_at"] = now
            if status == "REMOVED":
                entry["removed_at"] = now
            return


def validate_manifest(data: dict) -> list[str]:
    """Validate *data* against the expected manifest schema.

    Returns a list of human-readable error/warning strings.
    An empty list means the manifest is valid.
    """
    issues: list[str] = []

    # Root-level required fields
    for field in ("schema_version", "project_name", "created_at"):
        if not data.get(field):
            issues.append(f"missing root field: {field}")

    # [snowflake] section
    if "snowflake" not in data:
        issues.append("missing section: [snowflake]")
    else:
        sf = data["snowflake"]
        if not sf.get("connection"):
            issues.append("[snowflake].connection is empty — run 'nw setup-connection'")
        if not sf.get("sf_utils_db"):
            issues.append("[snowflake].sf_utils_db is empty — run 'nw check-setup'")

    # [prereqs] section
    if "prereqs" not in data:
        issues.append("missing section: [prereqs]")
    else:
        prereqs = data["prereqs"]
        if not prereqs.get("tools_verified"):
            issues.append("[prereqs].tools_verified is empty")
        if not prereqs.get("infra_ready", True):
            # infra_ready = false means the database has never been Snowflake-verified.
            # Set by migrate when sf_utils_db name was found but db existence unconfirmed.
            # Must run check-setup before creating network rule resources.
            sf_db = data.get("snowflake", {}).get("sf_utils_db", "")
            if sf_db:
                issues.append(
                    f"[prereqs].infra_ready = false — database '{sf_db}' not yet "
                    "verified in Snowflake; run 'nw check-setup' first"
                )
            else:
                issues.append(
                    "[prereqs].infra_ready = false — run 'nw check-setup' "
                    "to set up the infra database before creating network resources"
                )

    # [rule.*] entries
    valid_statuses = {"CREATE_IN_PROGRESS", "COMPLETE", "DELETE_IN_PROGRESS", "REMOVED"}
    for label, rule in data.get("rule", {}).items():
        prefix = f"[rule.{label}]"
        for field in ("status", "rule_name", "rule_mode", "rule_type"):
            if not rule.get(field):
                issues.append(f"{prefix} missing required field: {field}")
        if rule.get("status") and rule["status"] not in valid_statuses:
            issues.append(
                f"{prefix} invalid status '{rule['status']}' "
                f"(expected: {', '.join(sorted(valid_statuses))})"
            )

        rule_mode = rule.get("rule_mode", "")
        rule_type = rule.get("rule_type", "")
        if rule_mode and rule_type:
            try:
                m = NetworkRuleMode(rule_mode)
                t = NetworkRuleType(rule_type)
                if not validate_mode_type(m, t):
                    valid = get_valid_types_for_mode(m)
                    issues.append(
                        f"{prefix} invalid rule_type '{rule_type}' for mode "
                        f"'{rule_mode}'; valid: {valid}"
                    )
            except ValueError:
                pass  # enum validation catches invalid values elsewhere

        cleanup = rule.get("cleanup", {})
        if not cleanup.get("rule_name"):
            issues.append(f"{prefix} [cleanup].rule_name is empty")
        if not cleanup.get("db"):
            issues.append(f"{prefix} [cleanup].db is empty")

    valid_operations = {"CREATED", "ALTERED"}

    # [eai.*] entries
    for label, eai in data.get("eai", {}).items():
        prefix = f"[eai.{label}]"
        for field in ("name", "status", "operation"):
            if not eai.get(field):
                issues.append(f"{prefix} missing required field: {field}")
        if eai.get("operation") and eai["operation"] not in valid_operations:
            issues.append(
                f"{prefix} invalid operation '{eai['operation']}' "
                f"(expected: {', '.join(sorted(valid_operations))})"
            )
        if eai.get("status") and eai["status"] not in valid_statuses:
            issues.append(
                f"{prefix} invalid status '{eai['status']}' "
                f"(expected: {', '.join(sorted(valid_statuses))})"
            )

    # [policy.*] entries
    for label, pol in data.get("policy", {}).items():
        prefix = f"[policy.{label}]"
        for field in ("name", "status", "operation"):
            if not pol.get(field):
                issues.append(f"{prefix} missing required field: {field}")
        if pol.get("operation") and pol["operation"] not in valid_operations:
            issues.append(
                f"{prefix} invalid operation '{pol['operation']}' "
                f"(expected: {', '.join(sorted(valid_operations))})"
            )
        if pol.get("status") and pol["status"] not in valid_statuses:
            issues.append(
                f"{prefix} invalid status '{pol['status']}' "
                f"(expected: {', '.join(sorted(valid_statuses))})"
            )

    return issues


def promote_legacy_eai_policy_refs(data: dict) -> bool:
    """Promote legacy EAI/policy refs from rule cleanup/resources to top-level sections.

    Old manifests stored integration_name and policy_name inside
    [rule.<label>.resources] and [rule.<label>.cleanup]. This helper promotes
    them to top-level [eai.*] and [policy.*] sections so the new hierarchical
    layout is consistent.

    Called automatically by ensure_manifest_defaults() — no explicit migration step needed.
    The schema_version stays "1" since the change is purely additive.

    Returns True if any promotion was performed, False if nothing to promote.
    """
    if data.get("eai") or data.get("policy"):
        # Already has top-level EAI/policy sections — nothing to promote
        return False

    now = _now_iso()
    eai_seen: dict[str, str] = {}   # eai_name.upper() → label
    policy_seen: dict[str, str] = {}  # policy_name.upper() → label

    for rule_label, rule in data.get("rule", {}).items():
        cleanup = rule.get("cleanup", {})
        resources = rule.get("resources", {})

        # Promote integration to [eai.*]
        eai_name = (
            resources.get("integration_name")
            or cleanup.get("integration_name")
        )
        if eai_name and eai_name.upper() not in eai_seen:
            eai_label = eai_name.lower().replace("_", "-")
            eai_seen[eai_name.upper()] = eai_label
            data.setdefault("eai", {})[eai_label] = {
                "name":       eai_name.upper(),
                "status":     rule.get("status", "COMPLETE"),
                "operation":  "CREATED",
                "created_at": rule.get("created_at", now),
                "updated_at": rule.get("updated_at", now),
                "admin_role": rule.get("admin_role", "ACCOUNTADMIN"),
                "rules":      {rule_label: resources.get("network_rule", "")},
            }
        elif eai_name and eai_name.upper() in eai_seen:
            # Add this rule to the existing EAI entry
            eai_label = eai_seen[eai_name.upper()]
            data["eai"][eai_label].setdefault("rules", {})[rule_label] = (
                resources.get("network_rule", "")
            )

        # Promote policy to [policy.*]
        policy_name = (
            rule.get("policy_name")
            or cleanup.get("policy_name")
        )
        if policy_name and policy_name.upper() not in policy_seen:
            policy_label = policy_name.lower().replace("_", "-")
            policy_seen[policy_name.upper()] = policy_label
            data.setdefault("policy", {})[policy_label] = {
                "name":       policy_name.upper(),
                "status":     rule.get("status", "COMPLETE"),
                "operation":  "CREATED",
                "created_at": rule.get("created_at", now),
                "updated_at": rule.get("updated_at", now),
                "admin_role": rule.get("admin_role", "ACCOUNTADMIN"),
                "rules":      {rule_label: resources.get("network_rule", "")},
            }
        elif policy_name and policy_name.upper() in policy_seen:
            policy_label = policy_seen[policy_name.upper()]
            data["policy"][policy_label].setdefault("rules", {})[rule_label] = (
                resources.get("network_rule", "")
            )

        # Add back-references to the rule
        if eai_name and eai_name.upper() in eai_seen:
            rule["eai"] = eai_seen[eai_name.upper()]
        if policy_name and policy_name.upper() in policy_seen:
            rule["policy"] = policy_seen[policy_name.upper()]

        # Simplify cleanup — remove integration_name and policy_name (now in parent sections)
        for key in ("integration_name", "policy_name"):
            cleanup.pop(key, None)

    return bool(eai_seen or policy_seen)


# ---------------------------------------------------------------------------
# Resolution helpers (3-level fallback: rule entry → root [snowflake] → env var)
# ---------------------------------------------------------------------------


def resolve_rule_connection(rule_entry: dict, manifest: dict) -> str | None:
    """Effective connection name: rule override → root snowflake → env var."""
    return (
        rule_entry.get("connection")
        or manifest.get("snowflake", {}).get("connection")
        or os.environ.get("SNOWFLAKE_DEFAULT_CONNECTION_NAME")
        or None
    )


def resolve_rule_sf_utils_db(rule_entry: dict, manifest: dict) -> str | None:
    """Effective sf_utils_db: rule override → root snowflake → env var."""
    return (
        rule_entry.get("sf_utils_db")
        or manifest.get("snowflake", {}).get("sf_utils_db")
        or os.environ.get("SF_UTILS_DB")
        or os.environ.get("SFUTILS_DB")
        or os.environ.get("SNOW_UTILS_DB")
        or None
    )


def resolve_rule_admin_role(rule_entry: dict, manifest: dict) -> str:
    """Effective admin role: rule override → root snowflake → env var → ACCOUNTADMIN."""
    return (
        rule_entry.get("admin_role")
        or manifest.get("snowflake", {}).get("admin_role")
        or os.environ.get("SA_ADMIN_ROLE")
        or "ACCOUNTADMIN"
    )
