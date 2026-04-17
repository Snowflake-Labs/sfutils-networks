"""Tests for sfutils_networks CLI commands via CliRunner.

Mocks the subprocess boundary (run_snow_sql_stdin, run_snow_sql) so no
live Snowflake connection is required.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from sfutils_networks.network import cli


# ---------------------------------------------------------------------------
# rule create
# ---------------------------------------------------------------------------


class TestRuleCreate:
    def test_dry_run_prints_sql(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "rule", "create",
                "--name", "MY_RULE",
                "--db", "MY_DB",
                "--dry-run",
                "--no-local",
                "--values", "1.2.3.4/32",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "CREATE OR REPLACE NETWORK RULE" in result.output
        assert "MY_DB.NETWORKS.MY_RULE" in result.output
        assert "1.2.3.4/32" in result.output

    def test_confirm_no_aborts(self):
        runner = CliRunner()
        with patch("sfutils_networks.network.collect_ipv4_cidrs", return_value=["1.2.3.4/32"]):
            result = runner.invoke(
                cli,
                ["rule", "create", "--name", "MY_RULE", "--db", "MY_DB"],
                input="n\n",
            )
        assert result.exit_code == 0
        assert "Aborted." in result.output

    def test_yes_skips_confirm(self):
        runner = CliRunner()
        with (
            patch("sfutils_networks.network.collect_ipv4_cidrs", return_value=["1.2.3.4/32"]),
            patch("sfutils_networks.network.run_snow_sql", return_value=[]),
            patch("sfutils_networks.network.run_snow_sql_stdin"),
        ):
            result = runner.invoke(
                cli,
                ["rule", "create", "--name", "MY_RULE", "--db", "MY_DB", "--yes"],
            )
        assert result.exit_code == 0, result.output
        assert "Created rule" in result.output

    def test_invalid_mode_type_combo_errors(self):
        runner = CliRunner()
        # allow_local=True (default) with --type host_port triggers the preset guard
        result = runner.invoke(
            cli,
            ["rule", "create", "--name", "MY_RULE", "--db", "MY_DB", "--type", "host_port"],
        )
        assert result.exit_code == 1
        assert "ipv4" in result.output.lower() or "invalid" in result.output.lower()

    def test_no_values_raises(self):
        runner = CliRunner()
        # --no-local with no --values → collect_ipv4_cidrs returns [] → "No values specified"
        result = runner.invoke(
            cli,
            ["rule", "create", "--name", "MY_RULE", "--db", "MY_DB", "--no-local"],
        )
        assert result.exit_code == 1
        assert "No values" in result.output


# ---------------------------------------------------------------------------
# rule update
# ---------------------------------------------------------------------------


class TestRuleUpdate:
    def test_dry_run_prints_sql(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "rule", "update",
                "--name", "MY_RULE",
                "--db", "MY_DB",
                "--dry-run",
                "--no-local",
                "--values", "1.2.3.4/32",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "ALTER NETWORK RULE" in result.output
        assert "MY_DB.NETWORKS.MY_RULE" in result.output


# ---------------------------------------------------------------------------
# rule delete
# ---------------------------------------------------------------------------


class TestRuleDelete:
    def test_yes_executes_delete(self):
        runner = CliRunner()
        with patch("sfutils_networks.network.run_snow_sql_stdin"):
            result = runner.invoke(
                cli,
                ["rule", "delete", "--name", "MY_RULE", "--db", "MY_DB", "--yes"],
            )
        assert result.exit_code == 0, result.output
        assert "Deleted" in result.output


# ---------------------------------------------------------------------------
# rule list
# ---------------------------------------------------------------------------


class TestRuleList:
    def test_empty_shows_none(self):
        runner = CliRunner()
        with patch("sfutils_networks.network.run_snow_sql", return_value=[]):
            result = runner.invoke(cli, ["rule", "list", "--db", "MY_DB"])
        assert result.exit_code == 0
        assert "(none)" in result.output

    def test_lists_rules(self):
        runner = CliRunner()
        mock_rules = [{"name": "MY_RULE", "type": "IPV4", "mode": "INGRESS"}]
        with patch("sfutils_networks.network.run_snow_sql", return_value=mock_rules):
            result = runner.invoke(cli, ["rule", "list", "--db", "MY_DB"])
        assert result.exit_code == 0
        assert "MY_RULE" in result.output
        assert "INGRESS" in result.output


# ---------------------------------------------------------------------------
# policy create
# ---------------------------------------------------------------------------


class TestPolicyCreate:
    def test_dry_run_prints_sql(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "policy", "create",
                "--name", "MY_POLICY",
                "--rules", "MY_DB.NETWORKS.MY_RULE",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "CREATE NETWORK POLICY" in result.output
        assert "MY_POLICY" in result.output


# ---------------------------------------------------------------------------
# policy alter
# ---------------------------------------------------------------------------


class TestPolicyAlter:
    def test_dry_run_prints_sql(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "policy", "alter",
                "--name", "MY_POLICY",
                "--rules", "MY_DB.NETWORKS.EXTRA_RULE",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "ALTER NETWORK POLICY" in result.output
        assert "MY_POLICY" in result.output


# ---------------------------------------------------------------------------
# policy delete
# ---------------------------------------------------------------------------


class TestPolicyDelete:
    def test_yes_executes_delete(self):
        runner = CliRunner()
        with patch("sfutils_networks.network.run_snow_sql_stdin"):
            result = runner.invoke(
                cli,
                ["policy", "delete", "--name", "MY_POLICY", "--yes"],
            )
        assert result.exit_code == 0, result.output
        assert "Deleted" in result.output


# ---------------------------------------------------------------------------
# policy list
# ---------------------------------------------------------------------------


class TestPolicyList:
    def test_empty_shows_none(self):
        runner = CliRunner()
        with patch("sfutils_networks.network.run_snow_sql", return_value=[]):
            result = runner.invoke(cli, ["policy", "list"])
        assert result.exit_code == 0
        assert "(none)" in result.output

    def test_lists_policies(self):
        runner = CliRunner()
        mock_policies = [{"name": "MY_POLICY"}]
        with patch("sfutils_networks.network.run_snow_sql", return_value=mock_policies):
            result = runner.invoke(cli, ["policy", "list"])
        assert result.exit_code == 0
        assert "MY_POLICY" in result.output


# ---------------------------------------------------------------------------
# policy assign
# ---------------------------------------------------------------------------


class TestPolicyAssign:
    def test_assign_executes(self):
        runner = CliRunner()
        with patch("sfutils_networks.network.run_snow_sql_stdin") as mock_exec:
            result = runner.invoke(
                cli,
                ["policy", "assign", "--name", "MY_POLICY", "--user", "MY_USER"],
            )
        assert result.exit_code == 0, result.output
        assert "MY_POLICY" in result.output
        assert "MY_USER" in result.output
        mock_exec.assert_called_once()
