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

import re

import click
from dotenv import load_dotenv
from snow_utils_networks._presets import (
    NetworkRuleMode,
    NetworkRuleType,
    collect_ipv4_cidrs,
    get_valid_types_for_mode,
    validate_mode_type,
)
from snow_utils_networks._snow import (
    run_snow_sql,
    run_snow_sql_stdin,
    set_snow_cli_options,
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
    value_list = ", ".join(f"'{v}'" for v in values)
    comment_text = comment or "Created by snow-utils"
    return f"""CREATE OR REPLACE NETWORK RULE {db}.{schema}.{name}
    MODE = {mode.value}
    TYPE = {rule_type.value}
    VALUE_LIST = ({value_list})
    COMMENT = '{comment_text}';"""


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
    rule_list = ", ".join(rule_refs)
    comment_text = comment or "Created by snow-utils"
    return f"""CREATE NETWORK POLICY IF NOT EXISTS {policy_name}
    ALLOWED_NETWORK_RULE_LIST = ({rule_list})
    COMMENT = '{comment_text}';"""


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

        setup_sql = f"USE ROLE {admin_role};\nCREATE DATABASE IF NOT EXISTS {db};\nCREATE SCHEMA IF NOT EXISTS {db}.{schema};\n"
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
    value_list = ", ".join(f"'{v}'" for v in values)
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
    run_snow_sql_stdin(f"USE ROLE {admin_role};\nDROP NETWORK RULE IF EXISTS {db}.{schema}.{name}")


def delete_network_policy(policy_name: str, admin_role: str = "accountadmin") -> None:
    """Delete a network policy (idempotent)."""
    run_snow_sql_stdin(f"USE ROLE {admin_role};\nDROP NETWORK POLICY IF EXISTS {policy_name}")


def list_network_rules(db: str, schema: str, admin_role: str = "accountadmin") -> list[dict]:
    """List network rules in a schema."""
    return run_snow_sql(f"SHOW NETWORK RULES IN SCHEMA {db}.{schema}", role=admin_role) or []


def list_network_policies(admin_role: str = "accountadmin") -> list[dict]:
    """List all network policies."""
    return run_snow_sql("SHOW NETWORK POLICIES", role=admin_role) or []


def network_policy_exists(policy_name: str, admin_role: str = "accountadmin") -> bool:
    """Check if a network policy exists by trying to describe it directly.

    Uses exact name lookup instead of listing all policies to avoid
    privilege errors on policies we don't own.
    """
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
    sql = f"USE ROLE {admin_role};\nALTER NETWORK POLICY IF EXISTS {policy_name} SET ALLOWED_NETWORK_RULE_LIST = ();"
    run_snow_sql_stdin(sql)


def reattach_rule_to_policy(
    policy_name: str, rule_fqn: str, admin_role: str = "accountadmin"
) -> None:
    """Re-attach a rule to a policy."""
    sql = f"USE ROLE {admin_role};\nALTER NETWORK POLICY IF EXISTS {policy_name} SET ALLOWED_NETWORK_RULE_LIST = ('{rule_fqn}');"
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
        comment=f"Used by {user_part} - {project_part} app - managed by snow-utils-networks",
        force=force,
    )

    policy_sql = get_network_policy_sql(
        policy_name=policy_name,
        rule_refs=[rule_fqn],
        comment=f"Used by {user_part} - {project_part} app - managed by snow-utils-networks",
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
        comment=f"{ctx} network rule - managed by snow-utils-pat",
        dry_run=dry_run,
        force=force,
        admin_role=admin_role,
    )

    create_network_policy(
        policy_name=policy_name,
        rule_refs=[rule_fqn],
        comment=f"{ctx} network policy - managed by snow-utils-pat",
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
    run_snow_sql_stdin(
        f"USE ROLE {admin_role};\nALTER USER {user} SET NETWORK_POLICY = '{policy_name}';"
    )


def unassign_network_policy_from_user(user: str, admin_role: str = "accountadmin") -> None:
    """Remove network policy from a user (idempotent)."""
    run_snow_sql_stdin(
        f"USE ROLE {admin_role};\nALTER USER IF EXISTS {user} UNSET NETWORK_POLICY;", check=False
    )


MODE_CHOICES = ["ingress", "internal_stage", "egress", "postgres_ingress", "postgres_egress"]
TYPE_CHOICES = ["ipv4", "host_port", "private_host_port", "awsvpceid"]


# Auto-load .env from current working directory so callers
# don't need ``set -a && source .env && set +a`` before invoking.
load_dotenv()


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--debug", "-d", is_flag=True, help="Enable debug output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, debug: bool) -> None:
    """
    Snowflake Network Rule Manager.

    Create and manage network rules with IPv4 presets for GitHub Actions,
    Google services, and local IP detection.

    \b
    Commands:
      rule    - Manage network rules (create, list, delete)
      policy  - Manage network policies (create, list, delete)
    """
    set_snow_cli_options(verbose=verbose, debug=debug)
    ctx.ensure_object(dict)


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
    "-o", "--output", type=click.Choice(["text", "json"]), default="text", help="Output format"
)
@click.option(
    "--yes", "-y", is_flag=True, default=False,
    help="Skip interactive confirmation (use after reviewing dry-run output)",
)
def rule_create(
    name: str,
    db: str,
    schema: str,
    mode: str,
    rule_type: str,
    values: str | None,
    allow_local: bool,
    allow_gh: bool,
    allow_google: bool,
    dry_run: bool,
    force: bool,
    policy_name: str | None,
    policy_mode: str,
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

    has_presets = allow_local or allow_gh or allow_google
    if has_presets and type_enum != NetworkRuleType.IPV4:
        raise click.ClickException(
            f"IPv4 presets (--with-local, --allow-gh, --allow-google) "
            f"only valid for --type ipv4, not {rule_type}"
        )

    if type_enum == NetworkRuleType.IPV4:
        extra = [v.strip() for v in values.split(",")] if values else None
        all_values = collect_ipv4_cidrs(allow_local, allow_gh, allow_google, extra)
    else:
        if not values:
            raise click.ClickException(f"--values required for type {rule_type}")
        all_values = [v.strip() for v in values.split(",")]

    if not all_values:
        raise click.ClickException("No values specified.")

    click.echo(
        f"Creating {mode.upper()} network rule ({rule_type.upper()}) "
        f"with {len(all_values)} value(s)..."
    )

    if dry_run:
        click.echo("SQL that would be executed:")
        click.echo("─" * 60)
    elif output == "text" and not yes:
        if not click.confirm("\nProceed with network rule creation?", default=True):
            click.echo("Aborted.")
            return

    fqn = create_network_rule(
        name.upper(),
        db.upper(),
        schema.upper(),
        all_values,
        mode_enum,
        type_enum,
        dry_run=dry_run,
        force=force,
    )

    if not dry_run:
        click.echo(f"✓ Created rule: {fqn}")

    if policy_name:
        policy_upper = policy_name.upper()
        if policy_mode.lower() == "alter":
            click.echo(f"Adding rule to policy: {policy_upper}")
            alter_network_policy(policy_upper, [fqn], dry_run=dry_run)
            if not dry_run:
                click.echo(f"✓ Updated policy: {policy_upper}")
        else:
            click.echo(f"Creating policy: {policy_upper}")
            create_network_policy(policy_upper, [fqn], dry_run=dry_run, force=force)
            if not dry_run:
                click.echo(f"✓ Created policy: {policy_upper}")


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
@click.option("--allow-gh", "-G", is_flag=True, help="Include GitHub Actions IPs (IPV4 only)")
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

        # Replace with GitHub Actions IPs
        network.py rule update --name ci_rule --db my_db --allow-gh --no-local

        # Replace with specific CIDRs
        network.py rule update --name my_rule --db my_db --values "10.0.0.0/8,192.168.1.0/24" --no-local
    """
    extra = [v.strip() for v in values.split(",")] if values else None
    all_values = collect_ipv4_cidrs(allow_local, allow_gh, allow_google, extra)

    if not all_values:
        raise click.ClickException(
            "No values specified. Use --allow-local, --allow-gh, --allow-google, or --values"
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
@click.confirmation_option(prompt="Delete this network rule?")
def rule_delete_cmd(name: str, db: str, schema: str) -> None:
    """Delete a network rule."""
    fqn = f"{db}.{schema}.{name}".upper()
    click.echo(f"Deleting network rule: {fqn}")
    delete_network_rule(name.upper(), db.upper(), schema.upper())
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
def policy_create_cmd(name: str, rules: str, dry_run: bool, force: bool, output: str, yes: bool) -> None:
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
def policy_list_cmd(admin_role: str) -> None:
    """List all network policies."""
    click.echo("Network policies:")
    policies = list_network_policies(admin_role=admin_role)

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


if __name__ == "__main__":
    cli()
