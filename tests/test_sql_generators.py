"""Tests for pure SQL generation functions in sfutils_networks.network.

Zero mocking — all functions are pure transformations on their inputs.
Covers: _sql_str, _assert_safe_identifier, normalize_identifier,
get_network_rule_sql, get_network_policy_sql, get_alter_network_policy_sql,
get_update_network_rule_sql, get_setup_network_for_user_sql.
"""

from __future__ import annotations

import pytest
import click

from sfutils_networks.network import (
    _sql_str,
    _assert_safe_identifier,
    normalize_identifier,
    get_network_rule_sql,
    get_network_policy_sql,
    get_alter_network_policy_sql,
    get_update_network_rule_sql,
    get_setup_network_for_user_sql,
)
from sfutils_networks._presets import NetworkRuleMode, NetworkRuleType


# ---------------------------------------------------------------------------
# _sql_str
# ---------------------------------------------------------------------------


class TestSqlStr:
    def test_escapes_single_quote(self):
        assert _sql_str("it's") == "it''s"

    def test_leaves_clean_string(self):
        assert _sql_str("hello world") == "hello world"

    def test_escapes_multiple_quotes(self):
        assert _sql_str("a'b'c") == "a''b''c"

    def test_empty_string(self):
        assert _sql_str("") == ""

    def test_cidr_unchanged(self):
        assert _sql_str("10.0.0.0/8") == "10.0.0.0/8"


# ---------------------------------------------------------------------------
# _assert_safe_identifier
# ---------------------------------------------------------------------------


class TestAssertSafeIdentifier:
    def test_valid_uppercase(self):
        _assert_safe_identifier("MY_RULE")  # no exception

    def test_valid_mixed_case(self):
        _assert_safe_identifier("MyRule1")  # no exception

    def test_valid_with_dollar(self):
        _assert_safe_identifier("DB1$")  # no exception

    def test_valid_leading_underscore(self):
        _assert_safe_identifier("_PRIVATE")  # no exception

    def test_rejects_space(self):
        with pytest.raises(click.ClickException, match="Invalid"):
            _assert_safe_identifier("MY RULE")

    def test_rejects_hyphen(self):
        with pytest.raises(click.ClickException, match="Invalid"):
            _assert_safe_identifier("MY-RULE")

    def test_rejects_leading_digit(self):
        with pytest.raises(click.ClickException, match="Invalid"):
            _assert_safe_identifier("1RULE")

    def test_rejects_semicolon_injection(self):
        with pytest.raises(click.ClickException, match="Invalid"):
            _assert_safe_identifier("RULE'; DROP TABLE X")

    def test_custom_label_in_message(self):
        with pytest.raises(click.ClickException, match="db"):
            _assert_safe_identifier("bad-name", label="db")


# ---------------------------------------------------------------------------
# normalize_identifier
# ---------------------------------------------------------------------------


class TestNormalizeIdentifier:
    def test_snowflake_spaces_to_underscores_uppercase(self):
        assert normalize_identifier("my cool rule", "snowflake") == "MY_COOL_RULE"

    def test_aws_spaces_to_hyphens_lowercase(self):
        assert normalize_identifier("My Project", "aws") == "my-project"

    def test_strips_special_chars_snowflake(self):
        # "!" is removed; space→"_"; uppercased
        assert normalize_identifier("My Cool!", "snowflake") == "MY_COOL"

    def test_collapses_multiple_spaces(self):
        assert normalize_identifier("a  b", "snowflake") == "A_B"

    def test_strips_leading_trailing_separators(self):
        assert normalize_identifier("_hello_", "snowflake") == "HELLO"

    def test_already_clean_snowflake_is_idempotent(self):
        assert normalize_identifier("MY_DB", "snowflake") == "MY_DB"

    def test_default_style_is_snowflake(self):
        assert normalize_identifier("hello world") == "HELLO_WORLD"


# ---------------------------------------------------------------------------
# get_network_rule_sql
# ---------------------------------------------------------------------------


class TestGetNetworkRuleSql:
    def test_basic_ingress_ipv4(self):
        sql = get_network_rule_sql("MY_RULE", "MY_DB", "NETWORKS", ["1.2.3.4/32"])
        assert "CREATE OR REPLACE NETWORK RULE MY_DB.NETWORKS.MY_RULE" in sql
        assert "MODE = INGRESS" in sql
        assert "TYPE = IPV4" in sql
        assert "'1.2.3.4/32'" in sql

    def test_multiple_values_comma_separated(self):
        sql = get_network_rule_sql(
            "MY_RULE", "MY_DB", "NETWORKS", ["1.2.3.4/32", "5.6.7.8/32"]
        )
        assert "'1.2.3.4/32', '5.6.7.8/32'" in sql

    def test_egress_host_port(self):
        sql = get_network_rule_sql(
            "MY_EGRESS",
            "MY_DB",
            "NETWORKS",
            ["api.example.com:443"],
            mode=NetworkRuleMode.EGRESS,
            rule_type=NetworkRuleType.HOST_PORT,
        )
        assert "MODE = EGRESS" in sql
        assert "TYPE = HOST_PORT" in sql
        assert "'api.example.com:443'" in sql

    def test_custom_comment_included(self):
        sql = get_network_rule_sql(
            "MY_RULE", "MY_DB", "NETWORKS", ["1.2.3.4/32"], comment="Dev access"
        )
        assert "Dev access" in sql

    def test_comment_single_quote_escaped(self):
        sql = get_network_rule_sql(
            "MY_RULE", "MY_DB", "NETWORKS", ["1.2.3.4/32"], comment="It's a rule"
        )
        assert "It''s a rule" in sql

    def test_default_comment_when_empty(self):
        sql = get_network_rule_sql("MY_RULE", "MY_DB", "NETWORKS", ["1.2.3.4/32"])
        assert "Created by sfutils" in sql

    def test_rejects_bad_rule_name(self):
        with pytest.raises(click.ClickException):
            get_network_rule_sql("MY-BAD-RULE", "MY_DB", "NETWORKS", ["1.2.3.4/32"])

    def test_rejects_bad_db_name(self):
        with pytest.raises(click.ClickException):
            get_network_rule_sql("MY_RULE", "my-db", "NETWORKS", ["1.2.3.4/32"])

    def test_ends_with_semicolon(self):
        sql = get_network_rule_sql("MY_RULE", "MY_DB", "NETWORKS", ["1.2.3.4/32"])
        assert sql.strip().endswith(";")


# ---------------------------------------------------------------------------
# get_network_policy_sql
# ---------------------------------------------------------------------------


class TestGetNetworkPolicySql:
    def test_basic_single_rule(self):
        sql = get_network_policy_sql("MY_POLICY", ["MY_DB.NETWORKS.MY_RULE"])
        assert "CREATE NETWORK POLICY IF NOT EXISTS MY_POLICY" in sql
        assert "MY_DB.NETWORKS.MY_RULE" in sql

    def test_multiple_rules_comma_separated(self):
        sql = get_network_policy_sql(
            "MY_POLICY",
            ["MY_DB.NETWORKS.RULE1", "MY_DB.NETWORKS.RULE2"],
        )
        assert "MY_DB.NETWORKS.RULE1, MY_DB.NETWORKS.RULE2" in sql

    def test_default_comment(self):
        sql = get_network_policy_sql("MY_POLICY", ["MY_DB.NETWORKS.MY_RULE"])
        assert "Created by sfutils" in sql

    def test_rejects_bad_policy_name(self):
        with pytest.raises(click.ClickException):
            get_network_policy_sql("MY-POLICY", ["MY_DB.NETWORKS.MY_RULE"])

    def test_ends_with_semicolon(self):
        sql = get_network_policy_sql("MY_POLICY", ["MY_DB.NETWORKS.MY_RULE"])
        assert sql.strip().endswith(";")


# ---------------------------------------------------------------------------
# get_alter_network_policy_sql
# ---------------------------------------------------------------------------


class TestGetAlterNetworkPolicySql:
    def test_alter_add_syntax(self):
        sql = get_alter_network_policy_sql("MY_POLICY", ["MY_DB.NETWORKS.NEW_RULE"])
        assert "ALTER NETWORK POLICY MY_POLICY" in sql
        assert "ADD ALLOWED_NETWORK_RULE_LIST" in sql
        assert "MY_DB.NETWORKS.NEW_RULE" in sql

    def test_multiple_rules(self):
        sql = get_alter_network_policy_sql(
            "MY_POLICY", ["MY_DB.NETWORKS.RULE1", "MY_DB.NETWORKS.RULE2"]
        )
        assert "MY_DB.NETWORKS.RULE1, MY_DB.NETWORKS.RULE2" in sql

    def test_rejects_bad_policy_name(self):
        with pytest.raises(click.ClickException):
            get_alter_network_policy_sql("MY POLICY", ["MY_DB.NETWORKS.RULE"])

    def test_ends_with_semicolon(self):
        sql = get_alter_network_policy_sql("MY_POLICY", ["MY_DB.NETWORKS.RULE"])
        assert sql.strip().endswith(";")


# ---------------------------------------------------------------------------
# get_update_network_rule_sql
# ---------------------------------------------------------------------------


class TestGetUpdateNetworkRuleSql:
    def test_alter_set_value_list(self):
        sql = get_update_network_rule_sql("MY_RULE", "MY_DB", "NETWORKS", ["1.2.3.4/32"])
        assert "ALTER NETWORK RULE MY_DB.NETWORKS.MY_RULE" in sql
        assert "SET VALUE_LIST" in sql
        assert "'1.2.3.4/32'" in sql

    def test_multiple_values(self):
        sql = get_update_network_rule_sql(
            "MY_RULE", "MY_DB", "NETWORKS", ["1.2.3.4/32", "5.6.7.8/32"]
        )
        assert "'1.2.3.4/32', '5.6.7.8/32'" in sql

    def test_ends_with_semicolon(self):
        sql = get_update_network_rule_sql("MY_RULE", "MY_DB", "NETWORKS", ["1.2.3.4/32"])
        assert sql.strip().endswith(";")


# ---------------------------------------------------------------------------
# get_setup_network_for_user_sql
# ---------------------------------------------------------------------------


class TestGetSetupNetworkForUserSql:
    def test_contains_rule_and_policy(self):
        sql = get_setup_network_for_user_sql("alice", "MY_DB", ["1.2.3.4/32"])
        assert "CREATE OR REPLACE NETWORK RULE" in sql
        assert "CREATE NETWORK POLICY" in sql

    def test_uppercases_user_for_naming(self):
        sql = get_setup_network_for_user_sql("alice", "MY_DB", ["1.2.3.4/32"])
        assert "ALICE_NETWORK_RULE" in sql
        assert "ALICE_NETWORK_POLICY" in sql

    def test_uppercases_db(self):
        sql = get_setup_network_for_user_sql("alice", "my_db", ["1.2.3.4/32"])
        assert "MY_DB.NETWORKS.ALICE_NETWORK_RULE" in sql

    def test_rule_fqn_referenced_in_policy(self):
        sql = get_setup_network_for_user_sql("alice", "MY_DB", ["1.2.3.4/32"])
        # The policy's ALLOWED_NETWORK_RULE_LIST should reference the rule FQN
        assert "MY_DB.NETWORKS.ALICE_NETWORK_RULE" in sql

    def test_starts_with_use_role(self):
        sql = get_setup_network_for_user_sql("alice", "MY_DB", ["1.2.3.4/32"])
        assert sql.startswith("USE ROLE ")

    def test_custom_admin_role(self):
        sql = get_setup_network_for_user_sql(
            "alice", "MY_DB", ["1.2.3.4/32"], admin_role="SYSADMIN"
        )
        assert "USE ROLE SYSADMIN" in sql

    def test_cidr_in_rule(self):
        sql = get_setup_network_for_user_sql("alice", "MY_DB", ["203.0.113.1/32"])
        assert "203.0.113.1/32" in sql
