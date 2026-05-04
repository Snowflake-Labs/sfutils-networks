#!/usr/bin/env python3
# Copyright 2026 Snowflake Inc.
# Generated with Cortex Code
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Snowflake Network Manager - Core module and CLI.

Provides:
- Core functions for creating/managing network rules and policies
- CLI commands for network operations
- IPv4 preset support (GitHub Actions, Google, local IP)
"""

import contextlib
import datetime
import json
import re
import subprocess
from pathlib import Path

import click
from dotenv import dotenv_values

from sfutils_networks._presets import (
    PRESET_NAMES,
    PRESET_REGISTRY,
    SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN,
    NetworkRuleMode,
    NetworkRuleType,
    collect_ipv4_cidrs,
    collect_preset_values,
    get_valid_types_for_mode,
    validate_mode_type,
)
from sfutils_networks._snow import (
    run_snow_sql,
    run_snow_sql_stdin,
    set_connection,
    set_snow_cli_options,
)
from sfutils_networks._toml_manifest import (
    ensure_manifest_defaults,
    get_eai_label_for_name,
    load_manifest,
    migrate_v1_to_v2,
    resolve_rule_admin_role,
    resolve_rule_connection,
    save_manifest,
    update_resource_status,
    upsert_eai,
    upsert_policy_entry,
    upsert_resource,
    validate_manifest,
)


def _sql_str(value: str) -> str:
    """Escape a value for safe use inside a SQL single-quoted literal."""
    return value.replace("'", "''")


_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def _assert_safe_identifier(value: str, label: str = "identifier") -> None:
    """Raise ClickException if value is not a safe unquoted SQL identifier."""
    if not _IDENT_RE.match(value):
        raise click.ClickException(
            f"Invalid {label} '{value}': must match ^[A-Za-z_][A-Za-z0-9_$]*$"
        )


def normalize_identifier(name: str, style: str = "snowflake") -> str:
    """Normalize name for SQL or DNS compliance.

    Args:
        name: Raw input (e.g., "My Cool Project!")
        style: "snowflake" (UPPER_SNAKE) or "aws" (lower-kebab)

    Returns:
        Normalized identifier safe for SQL or AWS DNS
    """
    clean = re.sub(r"[^a-zA-Z0-9\s\-_]", "", name)
    clean = re.sub(r"\s+", "_" if style == "snowflake" else "-", clean)
    clean = re.sub(r"[-_]+", "_" if style == "snowflake" else "-", clean)
    clean = clean.strip("-_")

    if style == "snowflake":
        return clean.upper()
    else:
        return clean.lower()


def get_network_rule_sql(
    name: str,
    db: str,
    schema: str,
    values: list[str],
    mode: NetworkRuleMode = NetworkRuleMode.INGRESS,
    rule_type: NetworkRuleType = NetworkRuleType.IPV4,
    comment: str = "",
    force: bool = False,
) -> str:
    """
    Generate SQL for creating a network rule.

    Args:
        name: Network rule name
        db: Database name
        schema: Schema name
        values: List of values (CIDRs, hosts, VPC IDs depending on type)
        mode: Rule mode (INGRESS, EGRESS, etc.)
        rule_type: Value type (IPV4, HOST_PORT, etc.)
        comment: Optional comment

    Returns:
        CREATE OR REPLACE NETWORK RULE SQL statement (idempotent)
    """
    _assert_safe_identifier(name, "name")
    _assert_safe_identifier(db, "db")
    _assert_safe_identifier(schema, "schema")
    value_list = ", ".join(f"'{_sql_str(v)}'" for v in values)
    comment_text = comment or "Created by sfutils"
    return f"""CREATE OR REPLACE NETWORK RULE {db}.{schema}.{name}
    MODE = {mode.value}
    TYPE = {rule_type.value}
    VALUE_LIST = ({value_list})
    COMMENT = '{_sql_str(comment_text)}';"""


def get_network_policy_sql(
    policy_name: str,
    rule_refs: list[str],
    comment: str = "",
    force: bool = False,
) -> str:
    """
    Generate SQL for creating a network policy from rules.

    Args:
        policy_name: Network policy name
        rule_refs: List of fully qualified network rule names
        comment: Optional comment

    Returns:
        CREATE NETWORK POLICY IF NOT EXISTS SQL statement (idempotent)
    """
    _assert_safe_identifier(policy_name, "policy_name")
    rule_list = ", ".join(rule_refs)
    comment_text = comment or "Created by sfutils"
    return f"""CREATE NETWORK POLICY IF NOT EXISTS {policy_name}
    ALLOWED_NETWORK_RULE_LIST = ({rule_list})
    COMMENT = '{_sql_str(comment_text)}';"""


def get_alter_network_policy_sql(
    policy_name: str,
    rule_refs: list[str],
) -> str:
    """
    Generate SQL for adding rules to an existing network policy.

    Args:
        policy_name: Network policy name
        rule_refs: List of fully qualified network rule names to add

    Returns:
        ALTER NETWORK POLICY SQL statement
    """
    _assert_safe_identifier(policy_name, "policy_name")
    rule_list = ", ".join(rule_refs)
    return f"""ALTER NETWORK POLICY {policy_name}
    ADD ALLOWED_NETWORK_RULE_LIST = ({rule_list});"""


def create_network_rule(
    name: str,
    db: str,
    schema: str,
    values: list[str],
    mode: NetworkRuleMode = NetworkRuleMode.INGRESS,
    rule_type: NetworkRuleType = NetworkRuleType.IPV4,
    comment: str = "",
    dry_run: bool = False,
    force: bool = False,
    admin_role: str = "accountadmin",
) -> str:
    """
    Create a network rule in Snowflake.

    Args:
        name: Network rule name
        db: Database name
        schema: Schema name
        values: List of values (CIDRs, hosts, VPC IDs)
        mode: Rule mode
        rule_type: Value type
        comment: Optional comment
        dry_run: If True, only print SQL without executing
        admin_role: Role for creating resources (default: accountadmin)

    Returns:
        Fully qualified network rule name (db.schema.name)

    Raises:
        click.ClickException: If mode/type combination is invalid
    """
    _assert_safe_identifier(admin_role, "admin_role")
    if not validate_mode_type(mode, rule_type):
        valid = get_valid_types_for_mode(mode)
        raise click.ClickException(
            f"Invalid type '{rule_type.value}' for mode '{mode.value}'. Valid types: {valid}"
        )

    rule_fqn = f"{db}.{schema}.{name}"
    sql = get_network_rule_sql(name, db, schema, values, mode, rule_type, comment, force)

    if dry_run:
        click.echo(sql)
    else:
        expected_policy = name.replace("_NETWORK_RULE", "_NETWORK_POLICY")
        attached_policies = get_policies_for_rule(rule_fqn, expected_policy, admin_role=admin_role)

        if attached_policies:
            click.echo(f"  Detaching rule from {len(attached_policies)} policy(ies)...")
            for policy in attached_policies:
                detach_rule_from_policy(policy, admin_role=admin_role)

        setup_sql = (
            f"USE ROLE {admin_role};\n"
            f"CREATE DATABASE IF NOT EXISTS {db};\n"
            f"CREATE SCHEMA IF NOT EXISTS {db}.{schema};\n"
        )
        run_snow_sql_stdin(setup_sql + sql)

        if attached_policies:
            click.echo(f"  Re-attaching rule to {len(attached_policies)} policy(ies)...")
            for policy in attached_policies:
                reattach_rule_to_policy(policy, rule_fqn, admin_role=admin_role)

    return rule_fqn


def create_network_policy(
    policy_name: str,
    rule_refs: list[str],
    comment: str = "",
    dry_run: bool = False,
    force: bool = False,
    admin_role: str = "accountadmin",
) -> None:
    """
    Create a network policy referencing given rules.

    Args:
        policy_name: Network policy name
        rule_refs: List of fully qualified network rule names
        comment: Optional comment
        dry_run: If True, only print SQL without executing
        admin_role: Role for creating resources (default: accountadmin)
    """
    _assert_safe_identifier(admin_role, "admin_role")
    sql = get_network_policy_sql(policy_name, rule_refs, comment, force)

    if dry_run:
        click.echo(sql)
    else:
        run_snow_sql_stdin(f"USE ROLE {admin_role};\n{sql}")


def alter_network_policy(
    policy_name: str,
    rule_refs: list[str],
    dry_run: bool = False,
    admin_role: str = "accountadmin",
) -> None:
    """
    Add rules to an existing network policy.

    Args:
        policy_name: Network policy name
        rule_refs: List of fully qualified network rule names to add
        dry_run: If True, only print SQL without executing
        admin_role: Role for modifying resources (default: accountadmin)
    """
    _assert_safe_identifier(admin_role, "admin_role")
    sql = get_alter_network_policy_sql(policy_name, rule_refs)

    if dry_run:
        click.echo(sql)
    else:
        run_snow_sql_stdin(f"USE ROLE {admin_role};\n{sql}")


def get_update_network_rule_sql(
    name: str,
    db: str,
    schema: str,
    values: list[str],
) -> str:
    """
    Generate SQL for updating (replacing) values in an existing network rule.

    Uses CREATE OR REPLACE to atomically update the rule with new values.

    Args:
        name: Network rule name
        db: Database name
        schema: Schema name
        values: New list of values (CIDRs, hosts, VPC IDs)

    Returns:
        ALTER NETWORK RULE SQL statement
    """
    _assert_safe_identifier(name, "name")
    _assert_safe_identifier(db, "db")
    _assert_safe_identifier(schema, "schema")
    value_list = ", ".join(f"'{_sql_str(v)}'" for v in values)
    return f"ALTER NETWORK RULE {db}.{schema}.{name} SET VALUE_LIST = ({value_list});"


def update_network_rule(
    name: str,
    db: str,
    schema: str,
    values: list[str],
    dry_run: bool = False,
    admin_role: str = "accountadmin",
) -> str:
    """
    Update an existing network rule with new values.

    Args:
        name: Network rule name
        db: Database name
        schema: Schema name
        values: New list of values
        dry_run: If True, only print SQL without executing
        admin_role: Role for modifying resources (default: accountadmin)

    Returns:
        Fully qualified network rule name (db.schema.name)
    """
    _assert_safe_identifier(admin_role, "admin_role")
    sql = get_update_network_rule_sql(name, db, schema, values)

    if dry_run:
        click.echo(sql)
    else:
        run_snow_sql_stdin(f"USE ROLE {admin_role};\n{sql}")

    return f"{db}.{schema}.{name}"


def update_network_for_user(
    user: str,
    db: str,
    cidrs: list[str],
    schema: str = "NETWORKS",
    dry_run: bool = False,
    admin_role: str = "accountadmin",
) -> str:
    """
    Update the network rule CIDRs for an existing user.

    This is a convenience function for updating a user's network access
    (e.g., when IP changes or adding new IPs).

    Args:
        user: Username (used to derive rule name: {user}_NETWORK_RULE)
        db: Database containing the network rule
        cidrs: New list of IPv4 CIDRs
        schema: Schema containing the rule (default: NETWORKS)
        dry_run: If True, only print SQL
        admin_role: Role for modifying resources (default: accountadmin)

    Returns:
        Fully qualified network rule name
    """
    rule_name = f"{user}_NETWORK_RULE".upper()
    return update_network_rule(
        name=rule_name,
        db=db.upper(),
        schema=schema.upper(),
        values=cidrs,
        dry_run=dry_run,
        admin_role=admin_role,
    )


def delete_network_rule(name: str, db: str, schema: str, admin_role: str = "accountadmin") -> None:
    """Delete a network rule (idempotent)."""
    _assert_safe_identifier(name, "name")
    _assert_safe_identifier(db, "db")
    _assert_safe_identifier(schema, "schema")
    _assert_safe_identifier(admin_role, "admin_role")
    run_snow_sql_stdin(f"USE ROLE {admin_role};\nDROP NETWORK RULE IF EXISTS {db}.{schema}.{name}")


def delete_network_policy(policy_name: str, admin_role: str = "accountadmin") -> None:
    """Delete a network policy (idempotent)."""
    _assert_safe_identifier(policy_name, "policy_name")
    _assert_safe_identifier(admin_role, "admin_role")
    run_snow_sql_stdin(f"USE ROLE {admin_role};\nDROP NETWORK POLICY IF EXISTS {policy_name}")


# ---------------------------------------------------------------------------
# External Access Integration helpers
# ---------------------------------------------------------------------------


def get_external_access_integration_sql(
    name: str,
    network_rule_fqns: list[str],
    secrets: list[str] | None = None,
    comment: str = "",
    force: bool = False,
) -> str:
    """Generate CREATE [OR REPLACE] EXTERNAL ACCESS INTEGRATION SQL."""
    _assert_safe_identifier(name, "name")
    kw = "CREATE OR REPLACE" if force else "CREATE EXTERNAL ACCESS INTEGRATION IF NOT EXISTS"
    rule_list = ", ".join(f"'{_sql_str(r)}'" for r in network_rule_fqns)
    secret_clause = ""
    if secrets:
        secret_list = ", ".join(f"'{_sql_str(s)}'" for s in secrets)
        secret_clause = f"\n  ALLOWED_AUTHENTICATION_TOKENS_SECRETS = ({secret_list})"
    comment_text = comment or "Created by sfutils-networks"
    return (
        f"{kw} {name}\n"
        f"  ALLOWED_NETWORK_RULES = ({rule_list})"
        f"{secret_clause}\n"
        f"  ENABLED = TRUE\n"
        f"  COMMENT = '{_sql_str(comment_text)}';"
    )


def get_eai_current_rules(name: str, admin_role: str = "accountadmin") -> list[str]:
    """DESC EXTERNAL ACCESS INTEGRATION and return ALLOWED_NETWORK_RULES list."""
    _assert_safe_identifier(name, "name")
    rows = run_snow_sql(f"DESC EXTERNAL ACCESS INTEGRATION {name}", role=admin_role) or []
    for row in rows:
        if row.get("property") == "ALLOWED_NETWORK_RULES":
            val = row.get("property_value", "")
            return [r.strip().strip("'\"") for r in val.split(",") if r.strip()]
    return []


def get_alter_external_access_integration_sql(name: str, full_rule_fqns: list[str]) -> str:
    """ALTER EXTERNAL ACCESS INTEGRATION SET ALLOWED_NETWORK_RULES = (full list)."""
    _assert_safe_identifier(name, "name")
    rule_list = ", ".join(f"'{_sql_str(r)}'" for r in full_rule_fqns)
    return f"ALTER EXTERNAL ACCESS INTEGRATION {name} SET ALLOWED_NETWORK_RULES = ({rule_list});"


def create_external_access_integration(
    name: str, network_rule_fqns: list[str], secrets: list[str] | None = None,
    comment: str = "", dry_run: bool = False, force: bool = False, admin_role: str = "accountadmin",
) -> None:
    """Create an External Access Integration referencing EGRESS network rule(s)."""
    _assert_safe_identifier(name, "name")
    _assert_safe_identifier(admin_role, "admin_role")
    sql = get_external_access_integration_sql(name, network_rule_fqns, secrets, comment, force)
    if dry_run:
        click.echo(sql)
    else:
        run_snow_sql_stdin(f"USE ROLE {admin_role};\n{sql}")


def alter_external_access_integration(
    name: str,
    add_rule_fqns: list[str],
    dry_run: bool = False,
    admin_role: str = "accountadmin",
) -> None:
    """Add network rule(s) to an existing EAI (GET current + union + SET).

    In dry-run mode skips the DESC query and shows SET with only the new rules
    (full union requires the EAI to exist in Snowflake).
    """
    _assert_safe_identifier(name, "name")
    _assert_safe_identifier(admin_role, "admin_role")
    if dry_run:
        # Skip DESC in dry-run — show SET with the new rules only
        sql = get_alter_external_access_integration_sql(name, add_rule_fqns)
        click.echo(sql)
        return
    existing = get_eai_current_rules(name, admin_role=admin_role)
    full_list = list(dict.fromkeys(existing + add_rule_fqns))
    sql = get_alter_external_access_integration_sql(name, full_list)
    run_snow_sql_stdin(f"USE ROLE {admin_role};\n{sql}")


def list_external_access_integrations(admin_role: str = "accountadmin") -> list[dict]:
    """List External Access Integrations via SHOW EXTERNAL ACCESS INTEGRATIONS."""
    result = run_snow_sql("SHOW EXTERNAL ACCESS INTEGRATIONS", role=admin_role)
    return result if isinstance(result, list) else []


def delete_external_access_integration(name: str, admin_role: str = "accountadmin") -> None:
    """Drop an External Access Integration (idempotent)."""
    _assert_safe_identifier(name, "name")
    _assert_safe_identifier(admin_role, "admin_role")
    run_snow_sql_stdin(
        f"USE ROLE {admin_role};\nDROP EXTERNAL ACCESS INTEGRATION IF EXISTS {name}"
    )


def list_network_rules(db: str, schema: str, admin_role: str = "accountadmin") -> list[dict]:
    """List network rules in a schema."""
    _assert_safe_identifier(db, "db")
    _assert_safe_identifier(schema, "schema")
    result = run_snow_sql(f"SHOW NETWORK RULES IN SCHEMA {db}.{schema}", role=admin_role)
    return result if isinstance(result, list) else []


def list_network_policies(admin_role: str = "accountadmin") -> list[dict]:
    """List all network policies."""
    result = run_snow_sql("SHOW NETWORK POLICIES", role=admin_role)
    return result if isinstance(result, list) else []


def network_policy_exists(policy_name: str, admin_role: str = "accountadmin") -> bool:
    """Check if a network policy exists by trying to describe it directly.

    Uses exact name lookup instead of listing all policies to avoid
    privilege errors on policies we don't own.
    """
    _assert_safe_identifier(policy_name, "policy_name")
    try:
        result = run_snow_sql(f"DESC NETWORK POLICY {policy_name}", role=admin_role)
        return result is not None and len(result) > 0
    except Exception:
        return False


def get_policies_for_rule(
    rule_fqn: str, expected_policy_name: str, admin_role: str = "accountadmin"
) -> list[str]:
    """Check if the expected policy contains this network rule.

    Args:
        rule_fqn: Fully qualified rule name (db.schema.rule)
        expected_policy_name: The specific policy name to check
        admin_role: Role for queries

    Returns:
        List containing expected_policy_name if it references the rule, empty otherwise.
    """
    _assert_safe_identifier(expected_policy_name, "expected_policy_name")
    result = []
    try:
        desc = run_snow_sql(f"DESC NETWORK POLICY {expected_policy_name}", role=admin_role) or []
        for row in desc:
            if row.get("name") == "ALLOWED_NETWORK_RULE_LIST":
                rules_str = row.get("value", "")
                if rule_fqn.upper() in rules_str.upper():
                    result.append(expected_policy_name)
                    break
    except Exception:
        pass
    return result


def detach_rule_from_policy(policy_name: str, admin_role: str = "accountadmin") -> None:
    """Temporarily detach all rules from a policy (SET to empty list)."""
    _assert_safe_identifier(policy_name, "policy_name")
    _assert_safe_identifier(admin_role, "admin_role")
    sql = (
        f"USE ROLE {admin_role};\n"
        f"ALTER NETWORK POLICY IF EXISTS {policy_name} SET ALLOWED_NETWORK_RULE_LIST = ();"
    )
    run_snow_sql_stdin(sql)


def reattach_rule_to_policy(
    policy_name: str, rule_fqn: str, admin_role: str = "accountadmin"
) -> None:
    """Re-attach a rule to a policy."""
    _assert_safe_identifier(policy_name, "policy_name")
    _assert_safe_identifier(admin_role, "admin_role")
    sql = (
        f"USE ROLE {admin_role};\n"
        f"ALTER NETWORK POLICY IF EXISTS {policy_name} "
        f"SET ALLOWED_NETWORK_RULE_LIST = ('{_sql_str(rule_fqn)}');"
    )
    run_snow_sql_stdin(sql)


def get_setup_network_for_user_sql(
    user: str,
    db: str,
    cidrs: list[str],
    schema: str = "NETWORKS",
    force: bool = False,
    comment_prefix: str | None = None,
    admin_role: str = "accountadmin",
) -> str:
    """
    Generate SQL for creating network rule and policy for a user.

    This returns the complete SQL without executing it, useful for dry-run display.

    Args:
        user: Username (used for naming rule/policy)
        db: Database for network rule
        cidrs: List of IPv4 CIDRs
        schema: Schema for network rule (default: NETWORKS)
        force: If True, use CREATE OR REPLACE
        comment_prefix: Comment prefix for SQL resources (inferred from user if not provided)
        admin_role: Role for creating resources (default: accountadmin)

    Returns:
        Complete SQL string for rule and policy creation
    """
    _assert_safe_identifier(admin_role, "admin_role")
    rule_name = f"{user}_NETWORK_RULE".upper()
    policy_name = f"{user}_NETWORK_POLICY".upper()
    rule_fqn = f"{db.upper()}.{schema.upper()}.{rule_name}"
    user_part = normalize_identifier(comment_prefix or user, "snowflake")
    project_part = normalize_identifier(db, "snowflake")

    rule_sql = get_network_rule_sql(
        name=rule_name,
        db=db.upper(),
        schema=schema.upper(),
        values=cidrs,
        mode=NetworkRuleMode.INGRESS,
        rule_type=NetworkRuleType.IPV4,
        comment=f"Used by {user_part} - {project_part} app - managed by sfutils-networks",
        force=force,
    )

    policy_sql = get_network_policy_sql(
        policy_name=policy_name,
        rule_refs=[rule_fqn],
        comment=f"Used by {user_part} - {project_part} app - managed by sfutils-networks",
        force=force,
    )

    return f"USE ROLE {admin_role};\n{rule_sql}\n\n{policy_sql}"


def setup_network_for_user(
    user: str,
    db: str,
    cidrs: list[str],
    schema: str = "NETWORKS",
    dry_run: bool = False,
    force: bool = False,
    comment_prefix: str | None = None,
    admin_role: str = "accountadmin",
) -> tuple[str, str]:
    """
    Create network rule and policy for a user (idempotent).

    This is a convenience function for PAT and other user setup workflows.
    Uses CREATE OR REPLACE for idempotency.

    Args:
        user: Username (used for naming rule/policy)
        db: Database for network rule
        cidrs: List of IPv4 CIDRs
        schema: Schema for network rule (default: NETWORKS)
        dry_run: If True, only print SQL
        comment_prefix: Comment prefix for SQL resources (inferred from user if not provided)
        admin_role: Role for creating resources (default: accountadmin)

    Returns:
        Tuple of (rule_fqn, policy_name)
    """
    rule_name = f"{user}_NETWORK_RULE".upper()
    policy_name = f"{user}_NETWORK_POLICY".upper()
    ctx = comment_prefix or user.upper()

    rule_fqn = create_network_rule(
        name=rule_name,
        db=db,
        schema=schema,
        values=cidrs,
        mode=NetworkRuleMode.INGRESS,
        rule_type=NetworkRuleType.IPV4,
        comment=f"{ctx} network rule - managed by sfutils-networks",
        dry_run=dry_run,
        force=force,
        admin_role=admin_role,
    )

    create_network_policy(
        policy_name=policy_name,
        rule_refs=[rule_fqn],
        comment=f"{ctx} network policy - managed by sfutils-networks",
        dry_run=dry_run,
        force=force,
        admin_role=admin_role,
    )

    return rule_fqn, policy_name


def cleanup_network_for_user(
    user: str,
    db: str,
    schema: str = "NETWORKS",
    unset_from_user: bool = True,
    admin_role: str = "accountadmin",
) -> None:
    """
    Remove network rule and policy for a user (idempotent).

    Args:
        user: Username
        db: Database containing network rule
        schema: Schema containing network rule
        unset_from_user: If True, also unset network policy from user
        admin_role: Role for dropping resources (default: accountadmin)
    """
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(admin_role, "admin_role")
    rule_name = f"{user}_NETWORK_RULE".upper()
    policy_name = f"{user}_NETWORK_POLICY".upper()

    if unset_from_user:
        run_snow_sql_stdin(
            f"USE ROLE {admin_role};\nALTER USER IF EXISTS {user} UNSET NETWORK_POLICY;",
            check=False,
        )

    delete_network_policy(policy_name, admin_role=admin_role)
    delete_network_rule(rule_name, db.upper(), schema.upper(), admin_role=admin_role)


def assign_network_policy_to_user(
    user: str, policy_name: str, admin_role: str = "accountadmin"
) -> None:
    """Assign a network policy to a user."""
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(policy_name, "policy_name")
    _assert_safe_identifier(admin_role, "admin_role")
    run_snow_sql_stdin(
        f"USE ROLE {admin_role};\nALTER USER {user} SET NETWORK_POLICY = '{_sql_str(policy_name)}';"
    )


def unassign_network_policy_from_user(user: str, admin_role: str = "accountadmin") -> None:
    """Remove network policy from a user (idempotent)."""
    _assert_safe_identifier(user, "user")
    _assert_safe_identifier(admin_role, "admin_role")
    run_snow_sql_stdin(
        f"USE ROLE {admin_role};\nALTER USER IF EXISTS {user} UNSET NETWORK_POLICY;", check=False
    )


MODE_CHOICES = ["ingress", "internal_stage", "egress", "postgres_ingress", "postgres_egress"]
TYPE_CHOICES = ["ipv4", "host_port", "private_host_port", "awsvpceid"]


def _begin_rule_create(
    manifest_path: Path,
    label: str,
    rule_name: str,
    db: str,
    admin_role: str,
) -> None:
    """Write status=CREATE_IN_PROGRESS to manifest BEFORE first SQL runs.

    This ensures the manifest always reflects current intent even if creation
    fails mid-way.  _persist_rule_state() will overwrite with COMPLETE on success.
    Idempotent: skips the write if the entry already has status=COMPLETE
    (so a dry-run + confirm re-run doesn't regress a healthy entry).
    """
    data = load_manifest(manifest_path)
    ensure_manifest_defaults(data, manifest_path)
    existing = data.get("rule", {}).get(label)
    if existing and existing.get("status") == "COMPLETE":
        return
    _now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    upsert_resource(data, label, {
        "status":     "CREATE_IN_PROGRESS",
        "created_at": _now,
        "updated_at": _now,
        "rule_name":  rule_name.upper(),
        "sf_utils_db": db.upper(),
        "admin_role":  admin_role,
    })
    save_manifest(manifest_path, data)
    click.echo(f"[manifest] '{label}' → CREATE_IN_PROGRESS", err=True)


def _persist_rule_state(
    manifest_path: Path,
    label: str,
    rule_config: dict,
) -> None:
    """Write rule entry to manifest.toml with status=COMPLETE on success."""
    data = load_manifest(manifest_path)
    ensure_manifest_defaults(data, manifest_path)
    upsert_resource(data, label, rule_config)
    save_manifest(manifest_path, data)
    click.echo(f"✓ Updated {manifest_path} with rule entry '{label}'")


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--debug", "-d", is_flag=True, help="Enable debug output")
@click.option(
    "--manifest-path",
    "-m",
    type=click.Path(path_type=Path),
    default=Path(".sfutils/manifest.toml"),
    show_default=True,
    help="Path to TOML manifest (default: .sfutils/manifest.toml)",
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool, debug: bool, manifest_path: Path) -> None:
    """
    Snowflake Network Rule Manager.

    Create and manage network rules with IPv4 presets for GitHub Actions,
    Google services, and local IP detection.

    \b
    Commands:
      rule              - Manage network rules (create, list, delete)
      policy            - Manage network policies (create, list, delete)
      integration       - Manage External Access Integrations (EGRESS rules)
      list              - List all rules from manifest.toml
      setup-connection  - Cache Snowflake connection in manifest.toml
      validate-manifest - Validate (and optionally repair) manifest.toml
      migrate           - Migrate legacy .env + manifest.md to manifest.toml
    """
    set_snow_cli_options(verbose=verbose, debug=debug)
    ctx.ensure_object(dict)
    ctx.obj["manifest_path"] = manifest_path

    # Set connection from manifest so all snow SQL calls use -c <connection>.
    _manifest = load_manifest(manifest_path)
    _conn = resolve_rule_connection({}, _manifest)
    if _conn:
        set_connection(_conn)

    # ── Manifest auto-gate ────────────────────────────────────────────────────
    # Runs before EVERY subcommand. If manifest exists and is broken:
    #   1. Auto-repair structural gaps (missing schema_version, [snowflake],
    #      [prereqs] sections) via ensure_manifest_defaults — silent success.
    #   2. Warn loudly about non-structural issues that need manual action
    #      (empty connection, infra_ready=false, missing rule fields, etc.).
    # New projects with no manifest yet are skipped — setup-connection / create
    # will initialise it correctly.
    if manifest_path.exists() and ctx.invoked_subcommand not in (
        "validate-manifest",
        "setup-connection",
    ):
        _gdata = load_manifest(manifest_path)
        _issues_before = validate_manifest(_gdata)
        if _issues_before:
            ensure_manifest_defaults(_gdata, manifest_path)
            save_manifest(manifest_path, _gdata)
            _issues_after = validate_manifest(_gdata)
            if _issues_after:
                click.echo(
                    f"\n⚠️  manifest.toml has {len(_issues_after)} issue(s) "
                    "that need attention before this operation:",
                    err=True,
                )
                for _issue in _issues_after:
                    click.echo(f"   ✗ {_issue}", err=True)
                click.echo(
                    "   Run 'nw validate-manifest' for details\n",
                    err=True,
                )
            else:
                click.echo(
                    f"[manifest] auto-repaired {len(_issues_before)} structural gap(s)",
                    err=True,
                )

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.group()
def rule() -> None:
    """Manage network rules."""
    pass


@cli.group()
def policy() -> None:
    """Manage network policies."""
    pass


@rule.command(name="create")
@click.option("--name", "-n", required=True, envvar="NW_RULE_NAME", help="Network rule name")
@click.option("--db", required=True, envvar="NW_RULE_DB", help="Database for rule")
@click.option(
    "--schema",
    "-s",
    default="NETWORKS",
    envvar="NW_RULE_SCHEMA",
    help="Schema (default: NETWORKS)",
)
@click.option(
    "--mode",
    "-m",
    type=click.Choice(MODE_CHOICES, case_sensitive=False),
    default="ingress",
    help="Rule mode (default: ingress)",
)
@click.option(
    "--type",
    "-t",
    "rule_type",
    type=click.Choice(TYPE_CHOICES, case_sensitive=False),
    default="ipv4",
    help="Value type (default: ipv4)",
)
@click.option("--values", help="Comma-separated values (CIDRs, hosts, VPC IDs)")
@click.option(
    "--allow-local/--no-local",
    default=True,
    help="Include local IP (IPV4 only, default: ON)",
)
@click.option("--allow-gh", "-G", is_flag=True, help="Include GitHub Actions IPs (IPV4 only)")
@click.option("--allow-google", "-g", is_flag=True, help="Include Google IPs (IPV4 only)")
@click.option(
    "--preset",
    multiple=True,
    type=click.Choice(PRESET_NAMES, case_sensitive=False),
    help="Intent vocabulary preset — auto-derives mode/type and resolves to values (repeatable)",
)
@click.option("--dry-run", is_flag=True, help="Preview SQL without executing")
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Overwrite existing rule/policy (CREATE OR REPLACE)",
)
@click.option(
    "--policy",
    "-p",
    "policy_name",
    help="Also create/update network policy with this name",
)
@click.option(
    "--policy-mode",
    type=click.Choice(["create", "alter"], case_sensitive=False),
    default="create",
    help="Policy mode: 'create' (replace) or 'alter' (add to existing)",
)
@click.option(
    "--integration",
    "-i",
    "integration_name",
    default=None,
    help="Also create/update External Access Integration with this name (EGRESS HOST_PORT only)",
)
@click.option(
    "--integration-mode",
    type=click.Choice(["create", "alter"], case_sensitive=False),
    default="create",
    help="Integration mode: 'create' (new EAI) or 'alter' (add rule to existing EAI)",
)
@click.option(
    "-o", "--output", type=click.Choice(["text", "json"]), default="text", help="Output format"
)
@click.option(
    "--yes", "-y", is_flag=True, default=False,
    help="Skip interactive confirmation (use after reviewing dry-run output)",
)
@click.pass_context
def rule_create(
    ctx: click.Context,
    name: str,
    db: str,
    schema: str,
    mode: str,
    rule_type: str,
    values: str | None,
    allow_local: bool,
    allow_gh: bool,
    allow_google: bool,
    preset: tuple[str, ...],
    dry_run: bool,
    force: bool,
    policy_name: str | None,
    policy_mode: str,
    integration_name: str | None,
    integration_mode: str,
    output: str,
    yes: bool,
) -> None:
    """
    Create a network rule with presets and/or custom values.

    \b
    Examples:
        # Local IP only (default)
        network.py rule create --name dev_rule --db my_db

        # GitHub Actions + local IP
        network.py rule create --name ci_rule --db my_db --allow-gh

        # GitHub Actions + local IP + create policy
        network.py rule create --name ci_rule --db my_db --allow-gh --policy ci_policy

        # Google IPs
        network.py rule create --name google_rule --db my_db --allow-google

        # Add rule to existing policy
        network.py rule create --name extra_rule --db my_db --policy my_policy --policy-mode alter

        # Egress rule for external APIs
        network.py rule create --name api_egress --db my_db \\
            --mode egress --type host_port \\
            --values "api.openai.com:443,api.anthropic.com:443"

        # Postgres wire protocol for BI tools
        network.py rule create --name bi_access --db my_db --mode postgres_ingress
    """
    mode_enum = NetworkRuleMode(mode.upper())
    type_enum = NetworkRuleType(rule_type.upper())

    # When --preset is used, derive mode/type from the registry metadata.
    # This is schema-driven: EGRESS presets → EGRESS/HOST_PORT automatically.
    # Future INGRESS presets would resolve to INGRESS/IPV4 the same way.
    # --integration is orthogonal and does not affect this derivation.
    if preset:
        _specs = [PRESET_REGISTRY[p] for p in preset]
        _preset_modes = {s.mode for s in _specs}
        _preset_types = {s.rule_type for s in _specs}
        if len(_preset_modes) > 1 or len(_preset_types) > 1:
            raise click.ClickException(
                "Cannot mix presets with different modes/types in one rule. "
                f"Modes found: {_preset_modes}. Types found: {_preset_types}."
            )
        mode_enum = NetworkRuleMode(_specs[0].mode)
        type_enum = NetworkRuleType(_specs[0].rule_type)

    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))
    _mdata = load_manifest(manifest_path)
    label = name.upper().lower().replace("_", "-")
    resolved_role = resolve_rule_admin_role({}, _mdata)

    # Auto-disable allow_local for non-IPV4 rules (defaults to True but is IPV4-only).
    # This prevents the default silently colliding when --type host_port or --preset is used.
    if type_enum != NetworkRuleType.IPV4:
        allow_local = False

    has_presets = allow_local or allow_gh or allow_google
    if has_presets and type_enum != NetworkRuleType.IPV4:
        raise click.ClickException(
            f"IPv4 presets (--allow-gh, --allow-google) "
            f"only valid for --type ipv4, not {rule_type}"
        )

    # --integration is EGRESS HOST_PORT only; IPV4 ingress flags are incompatible.
    # This guard runs after allow_local has been coerced off, so only allow_gh
    # and allow_google can trigger it here.
    if integration_name:
        ingress_flags_set = [
            f for f, v in [("--allow-gh", allow_gh), ("--allow-google", allow_google)] if v
        ]
        if ingress_flags_set:
            raise click.ClickException(
                f"IPv4 ingress flags ({', '.join(ingress_flags_set)}) cannot be used with "
                "--integration. EAI rules use EGRESS HOST_PORT, not IPv4."
            )

    if type_enum == NetworkRuleType.IPV4:
        extra = [v.strip() for v in values.split(",")] if values else None
        # --allow-gh uses the Snowflake-managed SaaS rule, not snapshot CIDRs
        all_values = collect_ipv4_cidrs(allow_local, False, allow_google, extra)
    elif preset:
        custom_hosts = [v.strip() for v in values.split(",")] if values else []
        all_values = collect_preset_values(list(preset), custom_hosts)
    elif values:
        all_values = [v.strip() for v in values.split(",")]
    else:
        all_values = []

    # GitHub-only case: allow_gh with no custom IPs — policy-only, no custom rule
    github_only = allow_gh and not all_values

    if not all_values and not allow_gh:
        raise click.ClickException("No values specified.")

    # GitHub managed rule requires a policy to be meaningful
    if allow_gh and not policy_name:
        raise click.ClickException(
            "--allow-gh requires --policy <name>: the managed GitHub rule "
            f"({SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN}) must be added to a "
            "network policy to take effect."
        )

    if github_only:
        click.echo(
            "No custom IPs specified — policy will reference only "
            f"{SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN}"
        )
    else:
        click.echo(
            f"Creating {mode_enum.value} network rule ({type_enum.value}) "
            f"with {len(all_values)} value(s)..."
        )
        if allow_gh:
            click.echo(
                f"  + hybrid policy: {SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN}"
            )
        if preset and type_enum != NetworkRuleType.IPV4:
            click.echo(f"  Presets: {', '.join(preset)}")

    if dry_run:
        click.echo("SQL that would be executed:")
        click.echo("─" * 60)
    elif output == "text" and not yes:
        if not click.confirm("\nProceed with network rule creation?", default=True):
            click.echo("Aborted.")
            return

    fqn: str | None = None
    if not github_only:
        if not dry_run:
            _begin_rule_create(manifest_path, label, name, db, resolved_role)

        fqn = create_network_rule(
            name.upper(),
            db.upper(),
            schema.upper(),
            all_values,
            mode_enum,
            type_enum,
            dry_run=dry_run,
            force=force,
            admin_role=resolved_role,
        )

        if not dry_run:
            click.echo(f"✓ Created rule: {fqn}")

    if policy_name:
        policy_upper = policy_name.upper()
        # Build policy refs: custom rule (if any) + optional managed GitHub rule
        policy_refs: list[str] = []
        if fqn:
            policy_refs.append(fqn)
        if allow_gh:
            policy_refs.append(SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN)

        if policy_mode.lower() == "alter":
            click.echo(f"Adding rule(s) to policy: {policy_upper}")
            alter_network_policy(
                policy_upper, policy_refs, dry_run=dry_run, admin_role=resolved_role
            )
            if not dry_run:
                click.echo(f"✓ Updated policy: {policy_upper}")
        else:
            click.echo(f"Creating policy: {policy_upper}")
            create_network_policy(
                policy_upper, policy_refs, dry_run=dry_run, force=force, admin_role=resolved_role
            )
            if not dry_run:
                click.echo(f"✓ Created policy: {policy_upper}")

    # EAI: only for EGRESS HOST_PORT
    if integration_name and fqn:
        integration_upper = integration_name.upper()
        if integration_mode.lower() == "alter":
            click.echo(f"Adding rule to EAI: {integration_upper}")
            alter_external_access_integration(
                integration_upper, [fqn], dry_run=dry_run, admin_role=resolved_role
            )
            if not dry_run:
                click.echo(f"✓ Updated EAI: {integration_upper}")
        else:
            click.echo(f"Creating EAI: {integration_upper}")
            create_external_access_integration(
                integration_upper, [fqn], dry_run=dry_run, force=force, admin_role=resolved_role
            )
            if not dry_run:
                click.echo(f"✓ Created EAI: {integration_upper}")
                click.echo(
                    f"\n  Reference: EXTERNAL_ACCESS_INTEGRATIONS = ('{integration_upper}')"
                )

    if not dry_run:
        _now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        _eai = integration_name.upper() if integration_name else ""
        _rule_config: dict = {
            "status":      "COMPLETE",
            "created_at":  _now,
            "updated_at":  _now,
            "rule_name":   name.upper() if not github_only else "",
            "rule_mode":   mode.upper(),
            "rule_type":   rule_type.upper(),
            "value_list":  all_values,
            "policy_name": policy_name.upper() if policy_name else "",
            "allow_github": allow_gh,
            "allow_google": allow_google,
            "sf_utils_db": db.upper(),
            "admin_role":  resolved_role,
            "eai":    integration_name.lower().replace("_", "-") if integration_name else "",
            "policy": policy_name.lower().replace("_", "-") if policy_name else "",
            "resources": {
                "network_rule":    fqn or "",
                "network_policy":  policy_name.upper() if policy_name else "",
                "integration_name": _eai,
            },
            "cleanup": {
                "rule_name": name.upper() if not github_only else "",
                "db":        db.upper(),
            },
        }
        if not github_only:
            _persist_rule_state(manifest_path, label, _rule_config)

        # Write [policy.<label>] to manifest if policy was created/altered
        if policy_name:
            _pol_upper = policy_name.upper()
            _pol_label = _pol_upper.lower().replace("_", "-")
            _pol_operation = "ALTERED" if policy_mode.lower() == "alter" else "CREATED"
            _pol_data = load_manifest(manifest_path)
            _existing_pol = _pol_data.get("policy", {}).get(_pol_label, {})
            _pol_config = {
                "name":       _pol_upper,
                "status":     "COMPLETE",
                "operation":  _existing_pol.get("operation", _pol_operation),
                "created_at": _existing_pol.get("created_at", _now),
                "updated_at": _now,
                "admin_role": resolved_role,
            }
            _pol_rules = dict(_existing_pol.get("rules", {}))
            if fqn:
                _pol_rules[label] = fqn
            _pol_config["rules"] = _pol_rules
            upsert_policy_entry(_pol_data, _pol_label, _pol_config)
            save_manifest(manifest_path, _pol_data)


@rule.command(name="update")
@click.option("--name", "-n", required=True, envvar="NW_RULE_NAME", help="Network rule name")
@click.option("--db", required=True, envvar="NW_RULE_DB", help="Database name")
@click.option("--schema", "-s", default="NETWORKS", envvar="NW_RULE_SCHEMA", help="Schema name")
@click.option("--values", help="Comma-separated values (CIDRs, hosts) to replace existing")
@click.option(
    "--allow-local/--no-local",
    default=True,
    help="Include local IP (IPV4 only, default: ON)",
)
@click.option(
    "--allow-gh", "-G", is_flag=True,
    help="NOTE: --allow-gh on update only affects VALUE_LIST (no snapshot). "
         "To add GITHUBACTIONS_GLOBAL to a policy, use 'nw policy alter'.",
)
@click.option("--allow-google", "-g", is_flag=True, help="Include Google IPs (IPV4 only)")
@click.option("--dry-run", is_flag=True, help="Preview SQL without executing")
def rule_update_cmd(
    name: str,
    db: str,
    schema: str,
    values: str | None,
    allow_local: bool,
    allow_gh: bool,
    allow_google: bool,
    dry_run: bool,
) -> None:
    """
    Update (replace) values in an existing network rule.

    This replaces ALL values in the rule. To add values, first list
    existing values with DESCRIBE NETWORK RULE, then include them.

    \b
    Examples:
        # Update with new local IP (e.g., after IP change)
        network.py rule update --name my_rule --db my_db

        # Replace with specific CIDRs
        network.py rule update --name my_rule --db my_db \
            --values "10.0.0.0/8,192.168.1.0/24" --no-local
    """
    extra = [v.strip() for v in values.split(",")] if values else None
    # --allow-gh is ignored for VALUE_LIST update (use 'nw policy alter' for managed rule)
    all_values = collect_ipv4_cidrs(allow_local, False, allow_google, extra)

    if not all_values:
        raise click.ClickException(
            "No values specified. Use --allow-local, --allow-google, or --values"
        )

    fqn = f"{db}.{schema}.{name}".upper()
    click.echo(f"Updating network rule {fqn} with {len(all_values)} value(s)...")

    update_network_rule(
        name.upper(),
        db.upper(),
        schema.upper(),
        all_values,
        dry_run=dry_run,
    )

    if not dry_run:
        click.echo(f"✓ Updated rule: {fqn}")


@rule.command(name="delete")
@click.option("--name", "-n", required=True, envvar="NW_RULE_NAME", help="Network rule name")
@click.option("--db", required=True, envvar="NW_RULE_DB", help="Database name")
@click.option("--schema", "-s", default="NETWORKS", envvar="NW_RULE_SCHEMA", help="Schema name")
@click.option(
    "--admin-role", "-a", default=None,
    help="Admin role for dropping resources (default: from manifest or ACCOUNTADMIN)",
)
@click.option(
    "--yes", "-y", is_flag=True, default=False,
    help="Skip interactive confirmation",
)
@click.pass_context
def rule_delete_cmd(
    ctx: click.Context, name: str, db: str, schema: str, admin_role: str | None, yes: bool
) -> None:
    """Delete a network rule and its associated policy (manifest-driven)."""
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))
    _mdata = load_manifest(manifest_path)
    resolved_role = admin_role or resolve_rule_admin_role({}, _mdata)

    fqn = f"{db}.{schema}.{name}".upper()
    click.echo(f"Deleting network rule: {fqn}")

    if not yes and not click.confirm("Delete this network rule?", default=False):
        click.echo("Aborted.")
        return

    # Write DELETE_IN_PROGRESS before any DROP runs.
    _del_data = load_manifest(manifest_path)
    update_resource_status(_del_data, name, "DELETE_IN_PROGRESS")
    save_manifest(manifest_path, _del_data)
    click.echo(f"[manifest] '{name.upper()}' → DELETE_IN_PROGRESS", err=True)

    # Look up associated policy/EAI from manifest for cleanup.
    _rule_entry = None
    for _entry in _del_data.get("rule", {}).values():
        if _entry.get("rule_name", "").upper() == name.upper():
            _rule_entry = _entry
            break

    # v2: look up parent EAI/policy from back-references on the rule
    _rule_entry_v2 = _rule_entry

    # EAI cleanup: check parent [eai.*] section
    _eai_label = (_rule_entry_v2 or {}).get("eai", "")
    _eai_entry = _del_data.get("eai", {}).get(_eai_label, {}) if _eai_label else {}
    _eai_name = _eai_entry.get("name", "")
    _eai_operation = _eai_entry.get("operation", "CREATED")

    # Policy cleanup: check parent [policy.*] section
    _pol_label = (_rule_entry_v2 or {}).get("policy", "")
    _pol_entry = _del_data.get("policy", {}).get(_pol_label, {}) if _pol_label else {}
    _pol_name = _pol_entry.get("name", "")
    _pol_operation = _pol_entry.get("operation", "CREATED")

    # Also check v1 cleanup for backwards compat
    _cleanup_v1 = (_rule_entry_v2 or {}).get("cleanup", {})
    if not _eai_name:
        _eai_name = _cleanup_v1.get("integration_name", "")
    if not _pol_name:
        _pol_name = _cleanup_v1.get("policy_name", "")

    # Drop policy first (dependency order), then EAI, then rule
    if _pol_name:
        if _pol_operation == "CREATED":
            click.echo(f"Deleting associated policy: {_pol_name}")
            delete_network_policy(_pol_name, admin_role=resolved_role)
        else:  # ALTERED — just remove our rule from the policy
            click.echo(f"Removing rule from policy: {_pol_name} (policy was ALTERED, not dropped)")
            # ALTER NETWORK POLICY REMOVE ALLOWED_NETWORK_RULE_LIST = (fqn)
            _rm_fqn = f"{db.upper()}.{schema.upper()}.{name.upper()}"
            run_snow_sql_stdin(
                f"USE ROLE {resolved_role};\n"
                f"ALTER NETWORK POLICY IF EXISTS {_pol_name} "
                f"REMOVE ALLOWED_NETWORK_RULE_LIST = ('{_rm_fqn}');"
            )

    if _eai_name:
        if _eai_operation == "CREATED":
            click.echo(f"Deleting associated EAI: {_eai_name}")
            delete_external_access_integration(_eai_name, admin_role=resolved_role)
        else:  # ALTERED — just remove our rule from the EAI
            click.echo(f"Removing rule from EAI: {_eai_name} (EAI was ALTERED, not dropped)")
            _rm_fqn = f"{db.upper()}.{schema.upper()}.{name.upper()}"
            _cur_rules = get_eai_current_rules(_eai_name, admin_role=resolved_role)
            _new_rules = [r for r in _cur_rules if r.upper() != _rm_fqn.upper()]
            if _new_rules:
                run_snow_sql_stdin(
                    f"USE ROLE {resolved_role};\n"
                    + get_alter_external_access_integration_sql(_eai_name, _new_rules)
                )
            else:
                click.echo(f"  (EAI {_eai_name} now has no rules — consider deleting it)")

    delete_network_rule(name.upper(), db.upper(), schema.upper(), admin_role=resolved_role)

    # Write REMOVED after all drops succeed.
    _fin_data = load_manifest(manifest_path)
    update_resource_status(_fin_data, name, "REMOVED")
    save_manifest(manifest_path, _fin_data)
    click.echo(f"✓ Deleted: {fqn}")


@rule.command(name="list")
@click.option("--db", required=True, envvar="NW_RULE_DB", help="Database name")
@click.option("--schema", "-s", default="NETWORKS", envvar="NW_RULE_SCHEMA", help="Schema name")
@click.option(
    "--admin-role",
    "-a",
    default="accountadmin",
    help="Admin role for listing resources",
)
def rule_list_cmd(db: str, schema: str, admin_role: str) -> None:
    """List network rules in schema."""
    click.echo(f"Network rules in {db}.{schema}:".upper())
    rules = list_network_rules(db.upper(), schema.upper(), admin_role=admin_role)

    if not rules:
        click.echo("  (none)")
        return

    for r in rules:
        rule_name = r.get("name", "N/A")
        rule_type = r.get("type", "N/A")
        mode = r.get("mode", "N/A")
        click.echo(f"  {rule_name} ({mode}, {rule_type})")


@policy.command(name="create")
@click.option("--name", "-n", required=True, help="Network policy name")
@click.option(
    "--rules",
    "-r",
    required=True,
    help="Comma-separated fully qualified rule names (db.schema.rule)",
)
@click.option("--dry-run", is_flag=True, help="Preview SQL without executing")
@click.option("--force", "-f", is_flag=True, help="Overwrite existing policy (CREATE OR REPLACE)")
@click.option(
    "-o", "--output", type=click.Choice(["text", "json"]), default="text", help="Output format"
)
@click.option(
    "--yes", "-y", is_flag=True, default=False,
    help="Skip interactive confirmation (use after reviewing dry-run output)",
)
def policy_create_cmd(
    name: str, rules: str, dry_run: bool, force: bool, output: str, yes: bool
) -> None:
    """
    Create a network policy with specified rules.

    \b
    Examples:
        # Create new policy with rules
        network.py policy create --name my_policy --rules "db.networks.rule1,db.networks.rule2"
    """
    rule_refs = [r.strip().upper() for r in rules.split(",")]
    policy_name = name.upper()

    click.echo(f"Creating policy {policy_name} with {len(rule_refs)} rule(s)...")

    if dry_run:
        click.echo("SQL that would be executed:")
        click.echo("─" * 60)
    elif output == "text" and not yes:
        if not click.confirm("\nProceed with network policy creation?", default=True):
            click.echo("Aborted.")
            return

    create_network_policy(policy_name, rule_refs, dry_run=dry_run, force=force)
    if not dry_run:
        click.echo(f"✓ Created: {policy_name}")


@policy.command(name="alter")
@click.option("--name", "-n", required=True, help="Network policy name")
@click.option(
    "--rules",
    "-r",
    required=True,
    help="Comma-separated fully qualified rule names (db.schema.rule)",
)
@click.option("--dry-run", is_flag=True, help="Preview SQL without executing")
@click.option(
    "-o", "--output", type=click.Choice(["text", "json"]), default="text", help="Output format"
)
@click.option(
    "--yes", "-y", is_flag=True, default=False,
    help="Skip interactive confirmation (use after reviewing dry-run output)",
)
def policy_alter_cmd(name: str, rules: str, dry_run: bool, output: str, yes: bool) -> None:
    """
    Add rules to an existing network policy.

    \b
    Examples:
        # Add rules to existing policy
        network.py policy alter --name my_policy --rules "db.networks.rule3"
    """
    rule_refs = [r.strip().upper() for r in rules.split(",")]
    policy_name = name.upper()

    click.echo(f"Adding {len(rule_refs)} rule(s) to policy: {policy_name}")

    if dry_run:
        click.echo("SQL that would be executed:")
        click.echo("─" * 60)
    elif output == "text" and not yes:
        if not click.confirm("\nProceed with policy modification?", default=True):
            click.echo("Aborted.")
            return

    alter_network_policy(policy_name, rule_refs, dry_run=dry_run)
    if not dry_run:
        click.echo(f"✓ Updated: {policy_name}")


@policy.command(name="delete")
@click.option("--name", "-n", required=True, help="Network policy name")
@click.option("--user", "-u", help="Also unset from this user first")
@click.option(
    "--admin-role",
    "-a",
    default="accountadmin",
    help="Admin role for modifying resources",
)
@click.confirmation_option(prompt="Delete this network policy?")
def policy_delete_cmd(name: str, user: str | None, admin_role: str) -> None:
    """Delete a network policy."""
    policy_name = name.upper()
    if user:
        click.echo(f"Unsetting policy from user: {user}")
        unassign_network_policy_from_user(user, admin_role=admin_role)
    click.echo(f"Deleting network policy: {policy_name}")
    delete_network_policy(policy_name, admin_role=admin_role)
    click.echo(f"✓ Deleted: {policy_name}")


@policy.command(name="list")
@click.option(
    "--admin-role",
    "-a",
    default="accountadmin",
    help="Admin role for listing resources",
)
@click.option(
    "-o", "--output", type=click.Choice(["text", "json"]), default="text", help="Output format"
)
def policy_list_cmd(admin_role: str, output: str) -> None:
    """List all network policies."""
    policies = list_network_policies(admin_role=admin_role)

    if output == "json":
        click.echo(json.dumps([p.get("name", "") for p in policies]))
        return

    click.echo("Network policies:")
    if not policies:
        click.echo("  (none)")
        return

    for p in policies:
        name = p.get("name", "N/A")
        click.echo(f"  {name}")


@policy.command(name="assign")
@click.option("--name", "-n", required=True, help="Network policy name")
@click.option("--user", "-u", required=True, help="User to assign policy to")
@click.option(
    "--admin-role",
    "-a",
    default="accountadmin",
    help="Admin role for assignment",
)
def policy_assign_cmd(name: str, user: str, admin_role: str) -> None:
    """Assign a network policy to a user."""
    policy_upper = name.upper()
    user_upper = user.upper()
    click.echo(f"Assigning policy {policy_upper} to user {user_upper}...")
    assign_network_policy_to_user(user_upper, policy_upper, admin_role=admin_role)
    click.echo(f"✓ Assigned {policy_upper} to {user_upper}")


# ---------------------------------------------------------------------------
# nw integration — External Access Integration commands
# ---------------------------------------------------------------------------


@cli.group()
def integration() -> None:
    """Manage External Access Integrations (for EGRESS HOST_PORT rules)."""
    pass


@integration.command(name="create")
@click.option("--name", "-n", required=True, help="Integration name")
@click.option("--rules", "-r", required=True,
              help="Comma-separated fully qualified EGRESS rule FQNs")
@click.option("--secrets", help="Comma-separated secret FQNs (optional)")
@click.option("--dry-run", is_flag=True, help="Preview SQL without executing")
@click.option("--force", "-f", is_flag=True, help="CREATE OR REPLACE")
@click.option("--admin-role", "-a", default=None, help="Admin role (default: from manifest)")
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation")
@click.pass_context
def integration_create_cmd(
    ctx: click.Context, name: str, rules: str, secrets: str | None,
    dry_run: bool, force: bool, admin_role: str | None, yes: bool,
) -> None:
    """Create an External Access Integration for EGRESS HOST_PORT rule(s).

    \b
    After creation, reference in your function/procedure/SPCS service:
        EXTERNAL_ACCESS_INTEGRATIONS = ('<NAME>')
    """
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))
    _mdata = load_manifest(manifest_path)
    resolved_role = admin_role or resolve_rule_admin_role({}, _mdata)
    rule_fqns = [r.strip().upper() for r in rules.split(",")]
    secret_list = [s.strip() for s in secrets.split(",")] if secrets else None
    integration_upper = name.upper()
    click.echo(f"Creating External Access Integration: {integration_upper}")
    click.echo(f"  Allowed rules: {', '.join(rule_fqns)}")
    if dry_run:
        click.echo("SQL that would be executed:")
        click.echo("─" * 60)
    elif not yes and not click.confirm("\nProceed?", default=True):
        click.echo("Aborted.")
        return
    create_external_access_integration(
        integration_upper, rule_fqns, secret_list,
        dry_run=dry_run, force=force, admin_role=resolved_role,
    )
    if not dry_run:
        click.echo(f"✓ Created: {integration_upper}")
        click.echo(f"\n  Reference: EXTERNAL_ACCESS_INTEGRATIONS = ('{integration_upper}')")
        # Write [eai.<label>] to manifest
        _eai_label = integration_upper.lower().replace("_", "-")
        _eai_now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        _eai_data = load_manifest(manifest_path)
        _eai_config = {
            "name":       integration_upper,
            "status":     "COMPLETE",
            "operation":  "CREATED",
            "created_at": _eai_now,
            "updated_at": _eai_now,
            "admin_role": resolved_role,
            "rules":      {r.lower().replace("_", "-").replace(".", "-"): r for r in rule_fqns},
        }
        upsert_eai(_eai_data, _eai_label, _eai_config)
        save_manifest(manifest_path, _eai_data)
        click.echo(f"[manifest] EAI '{_eai_label}' → COMPLETE (CREATED)", err=True)


@integration.command(name="alter")
@click.option("--name", "-n", required=True, help="Integration name")
@click.option("--add-rules", required=True, help="Comma-separated FQN rule names to add")
@click.option("--dry-run", is_flag=True)
@click.option("--admin-role", "-a", default=None)
@click.option("--yes", "-y", is_flag=True, default=False)
@click.pass_context
def integration_alter_cmd(
    ctx: click.Context, name: str, add_rules: str, dry_run: bool, admin_role: str | None, yes: bool,
) -> None:
    """Add network rule(s) to an existing External Access Integration."""
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))
    _mdata = load_manifest(manifest_path)
    resolved_role = admin_role or resolve_rule_admin_role({}, _mdata)
    rule_fqns = [r.strip().upper() for r in add_rules.split(",")]
    integration_upper = name.upper()
    click.echo(f"Adding rule(s) to {integration_upper}: {', '.join(rule_fqns)}")
    if dry_run:
        click.echo("SQL that would be executed:")
        click.echo("─" * 60)
    elif not yes and not click.confirm("\nProceed?", default=True):
        click.echo("Aborted.")
        return
    alter_external_access_integration(
        integration_upper, rule_fqns, dry_run=dry_run, admin_role=resolved_role
    )
    if not dry_run:
        click.echo(f"✓ Updated: {integration_upper}")
        # Write/update [eai.<label>] to manifest with operation=ALTERED
        _eai_label = get_eai_label_for_name(load_manifest(manifest_path), integration_upper)
        if _eai_label is None:
            _eai_label = integration_upper.lower().replace("_", "-")
        _eai_now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        _eai_data = load_manifest(manifest_path)
        _existing_eai = _eai_data.get("eai", {}).get(_eai_label, {})
        _eai_config = {
            "name":       integration_upper,
            "status":     "COMPLETE",
            "operation":  _existing_eai.get("operation", "ALTERED"),  # preserve CREATED
            "created_at": _existing_eai.get("created_at", _eai_now),
            "updated_at": _eai_now,
            "admin_role": resolved_role,
        }
        # Merge new rules into existing rules dict
        _eai_rules = dict(_existing_eai.get("rules", {}))
        for r in rule_fqns:
            _eai_rules[r.lower().replace("_", "-").replace(".", "-")] = r
        _eai_config["rules"] = _eai_rules
        upsert_eai(_eai_data, _eai_label, _eai_config)
        save_manifest(manifest_path, _eai_data)
        click.echo(f"[manifest] EAI '{_eai_label}' updated", err=True)


@integration.command(name="list")
@click.option(
    "-o", "--output", type=click.Choice(["text", "json"]), default="text", help="Output format"
)
@click.option("--admin-role", "-a", default="accountadmin")
def integration_list_cmd(output: str, admin_role: str) -> None:
    """List External Access Integrations."""
    integrations = list_external_access_integrations(admin_role=admin_role)
    if output == "json":
        click.echo(json.dumps([i.get("name", "") for i in integrations]))
        return
    if not integrations:
        click.echo("  (none)")
        return
    for i in integrations:
        click.echo(f"  {i.get('name', 'N/A')}")


@integration.command(name="delete")
@click.option("--name", "-n", required=True)
@click.option("--admin-role", "-a", default=None)
@click.option("--yes", "-y", is_flag=True, default=False)
@click.pass_context
def integration_delete_cmd(
    ctx: click.Context, name: str, admin_role: str | None, yes: bool
) -> None:
    """Delete an External Access Integration."""
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))
    _mdata = load_manifest(manifest_path)
    resolved_role = admin_role or resolve_rule_admin_role({}, _mdata)
    if not yes and not click.confirm(f"Delete integration {name.upper()}?", default=False):
        click.echo("Aborted.")
        return
    delete_external_access_integration(name.upper(), admin_role=resolved_role)
    click.echo(f"✓ Deleted: {name.upper()}")


# ---------------------------------------------------------------------------
# Top-level manifest commands
# ---------------------------------------------------------------------------


@cli.command(name="list")
@click.pass_context
def list_command(ctx: click.Context) -> None:
    """List all network rules, EAIs, and policies recorded in manifest.toml."""
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))
    data = load_manifest(manifest_path)
    rules = data.get("rule", {})
    eais = data.get("eai", {})
    policies = data.get("policy", {})

    if not rules and not eais and not policies:
        if not manifest_path.exists():
            click.echo(f"No manifest found at {manifest_path}. Run 'nw rule create' first.")
        else:
            click.echo("No entries found in manifest.toml.")
        return

    def _status_style(status: str) -> str:
        if status == "COMPLETE":
            return click.style(status, fg="green")
        if "IN_PROGRESS" in status:
            return click.style(status, fg="yellow")
        if status == "REMOVED":
            return click.style(status, fg="red")
        return status

    # EAI groups
    for eai_label, eai in eais.items():
        op = eai.get("operation", "")
        click.echo(
            f"\n  EAI: {click.style(eai.get('name', eai_label), bold=True)}"
            f"  [{op}]  {_status_style(eai.get('status', '—'))}"
        )
        click.echo(f"  {'─' * 60}")
        for rule_label, _rule_fqn in eai.get("rules", {}).items():
            rule = rules.get(rule_label, {})
            mode = rule.get("rule_mode", "—")
            rtype = rule.get("rule_type", "—")
            vals = ", ".join(rule.get("value_list", []))
            status = _status_style(rule.get("status", "—"))
            click.echo(f"    {rule_label:<30} {mode:<12} {rtype:<10} {status}  {vals[:40]}")

    # Policy groups
    for pol_label, pol in policies.items():
        op = pol.get("operation", "")
        click.echo(
            f"\n  POLICY: {click.style(pol.get('name', pol_label), bold=True)}"
            f"  [{op}]  {_status_style(pol.get('status', '—'))}"
        )
        click.echo(f"  {'─' * 60}")
        for rule_label, _rule_fqn in pol.get("rules", {}).items():
            rule = rules.get(rule_label, {})
            mode = rule.get("rule_mode", "—")
            rtype = rule.get("rule_type", "—")
            vals = ", ".join(rule.get("value_list", []))
            status = _status_style(rule.get("status", "—"))
            click.echo(f"    {rule_label:<30} {mode:<12} {rtype:<10} {status}  {vals[:40]}")

    # Standalone rules (no eai or policy back-reference)
    grouped_labels: set[str] = set()
    for eai in eais.values():
        grouped_labels.update(eai.get("rules", {}).keys())
    for pol in policies.values():
        grouped_labels.update(pol.get("rules", {}).keys())

    standalone = {k: v for k, v in rules.items() if k not in grouped_labels}
    if standalone:
        click.echo("\n  STANDALONE RULES:")
        click.echo(f"  {'─' * 60}")
        click.echo(f"  {'LABEL':<30} {'MODE':<12} {'TYPE':<10} {'STATUS':<12} VALUES")
        for label, rule in standalone.items():
            mode = rule.get("rule_mode", "—")
            rtype = rule.get("rule_type", "—")
            vals = ", ".join(rule.get("value_list", []))
            status = _status_style(rule.get("status", "—"))
            click.echo(f"  {label:<30} {mode:<12} {rtype:<10} {status}  {vals[:40]}")
    click.echo()


@cli.command(name="validate-manifest")
@click.option(
    "--fix",
    is_flag=True,
    default=False,
    help=(
        "Fill in any missing sections with sensible defaults before validating. "
        "Useful for repairing manifests from older projects."
    ),
)
@click.pass_context
def validate_manifest_command(ctx: click.Context, fix: bool) -> None:
    """Validate manifest.toml structure and report issues.

    Checks that all required sections and fields are present and well-formed.
    Exits with code 1 if validation fails so it can gate CI/CD workflows.

    Use --fix to automatically fill in any missing sections with defaults.

    \b
    Example:
        nw validate-manifest
        nw validate-manifest --fix   # repair then validate
    """
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))

    if not manifest_path.exists():
        if fix:
            data: dict = {}
            ensure_manifest_defaults(data, manifest_path)
            save_manifest(manifest_path, data)
            click.echo(f"✓ Created {manifest_path} with default structure")
        else:
            raise click.ClickException(
                f"manifest.toml not found at {manifest_path}. "
                "Run 'nw setup-connection' to initialise, "
                "or use --fix to create a skeleton."
            )
    else:
        data = load_manifest(manifest_path)

    if fix:
        before = validate_manifest(data)
        ensure_manifest_defaults(data, manifest_path)
        was_migrated = migrate_v1_to_v2(data)
        if was_migrated:
            click.echo("[manifest] Schema migrated: v1 → v2")
        save_manifest(manifest_path, data)
        after = validate_manifest(data)
        fixed_count = len(before) - len(after)
        if fixed_count > 0:
            click.echo(f"✓ Repaired {fixed_count} issue(s) in {manifest_path}")
        data = load_manifest(manifest_path)

    issues = validate_manifest(data)

    if issues:
        if fix:
            # Structural repair succeeded; remaining gaps are configuration next-steps,
            # not failures. Emit as informational guidance and exit 0.
            click.echo(f"\n  {len(issues)} next step(s) needed to complete setup:")
            for issue in issues:
                click.echo(f"   → {issue}")
            click.echo(
                "\n  Run 'nw setup-connection -c <name>' then 'nw check-setup' to continue."
            )
            return  # exit 0
        click.echo(f"✗ manifest.toml validation failed ({len(issues)} issue(s)):", err=True)
        for issue in issues:
            click.echo(f"  ✗ {issue}", err=True)
        click.echo(
            "  Tip: run 'nw validate-manifest --fix' to repair structural gaps",
            err=True,
        )
        raise click.ClickException("Fix the issues above and re-run.")

    rule_count = len(data.get("rule", {}))
    click.echo(
        f"✓ manifest.toml is valid  "
        f"(connection: {data.get('snowflake', {}).get('connection', '(not set)')}, "
        f"rules: {rule_count})"
    )


@cli.command(name="setup-connection")
@click.option(
    "--connection",
    "-c",
    required=True,
    help="Snowflake connection name to use for this project (from snow connection list)",
)
@click.option(
    "--admin-role",
    default=None,
    help="Admin role to cache in manifest.toml (default: ACCOUNTADMIN)",
)
@click.pass_context
def setup_connection_command(
    ctx: click.Context,
    connection: str,
    admin_role: str | None,
) -> None:
    """Persist a Snowflake connection to manifest.toml and cache its metadata.

    Run this once per project after picking a connection from 'snow connection list'.
    Writes [snowflake].connection + account/user/account_url to manifest.toml so
    manifest.toml becomes the source of truth for this project.

    \b
    Example:
        snow connection list              # see available connections
        nw setup-connection -c local-oauth
    """
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))

    set_connection(connection)

    click.echo(f"Testing connection '{connection}'...")
    _meta: dict = {}
    try:
        _res = subprocess.run(
            ["snow", "connection", "test", "-c", connection, "--format", "json"],
            capture_output=True, text=True, check=False,
        )
        if _res.returncode == 0 and _res.stdout.strip():
            _data = json.loads(_res.stdout)
            _meta = {
                "account":     str(_data.get("Account") or _data.get("account") or "").strip(),
                "user":        str(_data.get("User") or _data.get("user") or "").strip(),
                "account_url": (
                    f"https://{_data.get('Host') or _data.get('host') or ''}"
                ).strip(),
            }
        else:
            click.echo(
                click.style(
                    "⚠ Connection test failed — saving connection name anyway.", fg="yellow"
                )
            )
    except Exception:
        pass

    data = load_manifest(manifest_path)
    ensure_manifest_defaults(data, manifest_path)

    sf = data["snowflake"]
    sf["connection"] = connection
    if _meta.get("account"):
        sf["account"] = _meta["account"]
    if _meta.get("account_url") and _meta["account_url"] != "https://":
        sf["account_url"] = _meta["account_url"]
    if _meta.get("user"):
        sf["user"] = _meta["user"]
    if admin_role:
        sf["admin_role"] = admin_role

    save_manifest(manifest_path, data)

    click.echo(f"✓ Connection '{connection}' saved to {manifest_path}")
    if _meta.get("account"):
        click.echo(f"  account:     {_meta['account']}")
    if _meta.get("account_url") and _meta["account_url"] != "https://":
        click.echo(f"  account_url: {_meta['account_url']}")
    if _meta.get("user"):
        click.echo(f"  user:        {_meta['user']}")


def _parse_legacy_manifest(path: Path) -> dict:
    """Extract structured data from a legacy sfutils-manifest.md file.

    sfutils-manifest.md is the authoritative record of what was created.
    Returns a dict with whatever fields could be parsed; missing fields are
    absent from the dict (not None/empty) so callers can chain fallbacks.

    Parsed fields: project_name, tools_verified, admin_role, rule_name,
    policy_name, rule_mode, rule_type, value_list, sf_utils_db, status,
    created_at, resources (dict of FQN strings).
    """
    if not path.exists():
        return {}
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    result: dict = {}

    def _s(m_: re.Match | None) -> str | None:
        return m_.group(1).strip() if m_ else None

    # ── Global sections ───────────────────────────────────────────────────────
    if v := _s(re.search(r"^project_name:\s*(.+?)$", content, re.MULTILINE)):
        result["project_name"] = v
    if v := _s(re.search(r"^tools_verified:\s*(.+?)$", content, re.MULTILINE)):
        result["tools_verified"] = v
    # admin_role stored as "sfutils-networks: ROLE"
    if v := _s(re.search(r"^sfutils-networks:\s*(.+?)$", content, re.MULTILINE)):
        result["admin_role"] = v

    # ── Network rule section ──────────────────────────────────────────────────
    # Find the first sfutils-networks block
    start = content.find("<!-- START -- sfutils-networks:")
    end_marker = "<!-- END -- sfutils-networks:"
    end = content.find(end_marker)
    section = content[start: end if end != -1 else len(content)] if start != -1 else ""

    if section:
        _kv = [
            ("rule_name",   r"\*\*Rule Name:\*\*\s*(\S+)"),
            ("sf_utils_db", r"\*\*Database:\*\*\s*(\S+)"),
            ("status",      r"(?:\*\*Status:\*\*|^Status:)\s*(\S+)"),
            ("created_at",  r"\*\*Created:\*\*\s*(.+?)$"),
        ]
        for field, pattern in _kv:
            if v := _s(re.search(pattern, section, re.MULTILINE)):
                result[field] = v

        # Resource FQNs from the resources table
        # Row: | N | Type | Name | Location | Status |
        resources: dict = {}
        cleanup: dict = {}
        for row in re.finditer(
            r"\|\s*\d+\s*\|\s*(.+?)\s*\|\s*(\S+)\s*\|\s*(.+?)\s*\|\s*\w+\s*\|",
            section,
        ):
            rtype = row.group(1).strip().lower()
            rname = row.group(2).strip()
            rloc  = row.group(3).strip()
            if "network rule" in rtype:
                if "." in rloc:
                    result.setdefault("sf_utils_db", rloc.split(".")[0])
                resources["network_rule"] = (
                    f"{rloc}.{rname}" if rloc not in ("Account", "—") else rname
                )
                cleanup["rule_name"] = rname
                cleanup["db"] = rloc.split(".")[0] if "." in rloc else result.get("sf_utils_db", "")
            elif "network policy" in rtype:
                resources["network_policy"] = rname
                cleanup["policy_name"] = rname
                result["policy_name"] = rname

        if resources:
            result["resources"] = resources
        if cleanup:
            result["cleanup"] = cleanup

    # Derive rule_mode / rule_type from CLI cleanup command if present
    # e.g.  nw rule create --name X --mode egress --type host_port
    _cmd_match = re.search(
        r"nw\s+rule\s+create[^\n]*--mode\s+(\w+)[^\n]*--type\s+(\w+)", section, re.IGNORECASE
    )
    if _cmd_match:
        result.setdefault("rule_mode", _cmd_match.group(1).upper())
        result.setdefault("rule_type", _cmd_match.group(2).upper())

    # Default mode/type if still missing
    result.setdefault("rule_mode", "INGRESS")
    result.setdefault("rule_type", "IPV4")

    # Migrate legacy bare status → named states
    _status_migration = {"IN_PROGRESS": "CREATE_IN_PROGRESS"}
    if "status" in result:
        result["status"] = _status_migration.get(result["status"], result["status"])

    return result


@cli.command(name="migrate")
@click.option(
    "--env-path",
    type=click.Path(path_type=Path),
    default=Path(".env"),
    help=".env file to read connection from (default: .env)",
)
@click.option(
    "--manifest-md",
    type=click.Path(path_type=Path),
    default=Path(".sfutils/sfutils-manifest.md"),
    help="Existing markdown manifest to read resources from "
         "(default: .sfutils/sfutils-manifest.md)",
)
@click.option("--dry-run", is_flag=True, help="Print what would be written without writing")
@click.pass_context
def migrate_command(
    ctx: click.Context,
    env_path: Path,
    manifest_md: Path,
    dry_run: bool,
) -> None:
    """Migrate .env + sfutils-manifest.md to manifest.toml.

    sfutils-manifest.md is the PRIMARY source — it contains rule_name,
    policy_name, sf_utils_db, admin_role, project_name, prereqs, resource
    FQNs, mode/type, and status.
    .env is SUPPLEMENTARY — it adds the Snowflake connection name that was
    never stored in the old markdown manifest.

    Always sets infra_ready = false — only check-setup sets it to true.
    Status defaults to REMOVED if not found in manifest.

    Works correctly even when .env is absent or empty.
    Does NOT delete the old files.

    \b
    Example:
        nw migrate
        nw migrate --dry-run
        nw migrate --manifest-md /path/to/sfutils-manifest.md
    """
    manifest_path: Path = ctx.obj.get("manifest_path", Path(".sfutils/manifest.toml"))

    # Read legacy markdown manifest (PRIMARY source)
    legacy = _parse_legacy_manifest(manifest_md)

    # Read .env (SUPPLEMENTARY — connection name only)
    env_vals: dict = {}
    if env_path.exists():
        with contextlib.suppress(Exception):
            env_vals = dict(dotenv_values(env_path))

    # Load or initialise manifest.toml
    data = load_manifest(manifest_path)
    ensure_manifest_defaults(data, manifest_path)

    # ── Project metadata ──────────────────────────────────────────────────────
    if legacy.get("project_name"):
        data["project_name"] = legacy["project_name"]

    # ── Snowflake connection (from .env only, manifest.md didn't store it) ────
    conn = (
        env_vals.get("SNOWFLAKE_DEFAULT_CONNECTION_NAME")
        or data.get("snowflake", {}).get("connection")
        or ""
    )
    if conn:
        data["snowflake"]["connection"] = conn

    # Populate other [snowflake] fields from .env supplementary
    for env_key, sf_key in [
        ("SNOWFLAKE_ACCOUNT",  "account"),
        ("SNOWFLAKE_USER",     "user"),
        ("SNOWFLAKE_ACCOUNT_URL", "account_url"),
    ]:
        val = env_vals.get(env_key, "")
        if val and not data["snowflake"].get(sf_key):
            data["snowflake"][sf_key] = val

    # sf_utils_db from legacy manifest
    sf_utils_db = (
        legacy.get("sf_utils_db")
        or env_vals.get("SF_UTILS_DB")
        or env_vals.get("SNOW_UTILS_DB")
        or data["snowflake"].get("sf_utils_db", "")
    )
    if sf_utils_db:
        data["snowflake"]["sf_utils_db"] = sf_utils_db

    # admin_role from legacy manifest
    admin_role = (
        legacy.get("admin_role")
        or data["snowflake"].get("admin_role", "ACCOUNTADMIN")
    )
    data["snowflake"]["admin_role"] = admin_role

    # ── prereqs — infra_ready ALWAYS false after migrate ─────────────────────
    tools_verified = (
        legacy.get("tools_verified")
        or data.get("prereqs", {}).get("tools_verified", "")
    )
    data["prereqs"] = {
        "tools_verified": tools_verified or datetime.date.today().isoformat(),
        "infra_ready": False,
    }

    # ── Rule entry ────────────────────────────────────────────────────────────
    rule_name = legacy.get("rule_name", "")
    if rule_name:
        label = rule_name.lower().replace("_", "-")

        # Remove stale entries for the same rule_name under different labels
        for _lbl in list(data.get("rule", {}).keys()):
            if (
                _lbl != label
                and data["rule"][_lbl].get("rule_name", "").upper() == rule_name.upper()
            ):
                del data["rule"][_lbl]

        status = legacy.get("status", "REMOVED")
        _now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        rule_config: dict = {
            "status":      status,
            "created_at":  legacy.get("created_at", _now),
            "updated_at":  _now,
            "rule_name":   rule_name.upper(),
            "rule_mode":   legacy.get("rule_mode", "INGRESS"),
            "rule_type":   legacy.get("rule_type", "IPV4"),
            "value_list":  [],
            "policy_name": legacy.get("policy_name", ""),
            "allow_github": False,
            "allow_google": False,
            "sf_utils_db": sf_utils_db.upper() if sf_utils_db else "",
            "admin_role":  admin_role,
        }
        if legacy.get("resources"):
            rule_config["resources"] = legacy["resources"]
        if legacy.get("cleanup"):
            rule_config["cleanup"] = legacy["cleanup"]

        data.setdefault("rule", {})[label] = rule_config

    if dry_run:
        click.echo("# Dry-run — would write to manifest.toml:")
        click.echo(f"  project_name: {data.get('project_name')}")
        click.echo(f"  [snowflake].connection: {data.get('snowflake', {}).get('connection')}")
        click.echo(f"  [snowflake].sf_utils_db: {data.get('snowflake', {}).get('sf_utils_db')}")
        click.echo("  [prereqs].infra_ready: false")
        if rule_name:
            click.echo(f"  [rule.{label}].rule_name: {rule_name.upper()}")
            click.echo(f"  [rule.{label}].status: {status}")
        return

    save_manifest(manifest_path, data)
    click.echo(f"✓ Migrated to {manifest_path}")
    if rule_name:
        click.echo(f"  Rule entry: [rule.{label}] → {rule_name.upper()} ({status})")
    click.echo("  [prereqs].infra_ready = false — run 'nw check-setup' to verify infra")

    # Migrate schema version
    was_migrated = migrate_v1_to_v2(data)
    if was_migrated:
        save_manifest(manifest_path, data)
        click.echo("  Schema: upgraded to v2 (EAI/Policy sections promoted)")

    # Test connection; warn if it fails (don't block migration)
    if conn:
        _test = subprocess.run(
            ["snow", "connection", "test", "-c", conn, "--format", "json"],
            capture_output=True, text=True, check=False,
        )
        if _test.returncode != 0:
            click.echo(
                click.style(
                    f"⚠ Connection '{conn}' test failed. "
                    "Run 'nw setup-connection -c <name>' to set a working connection.",
                    fg="yellow",
                )
            )
        else:
            click.echo(f"  connection '{conn}' verified ✓")
    else:
        click.echo(
            click.style(
                "⚠ No connection found. Run 'nw setup-connection -c <name>' to set one.",
                fg="yellow",
            )
        )


if __name__ == "__main__":
    cli()
