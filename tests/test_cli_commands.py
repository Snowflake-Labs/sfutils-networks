"""Tests for sfutils_networks CLI commands via CliRunner.

Mocks the subprocess boundary (run_snow_sql_stdin, run_snow_sql) so no
live Snowflake connection is required.
"""

from __future__ import annotations

import textwrap
from unittest.mock import patch

from click.testing import CliRunner

from sfutils_networks._toml_manifest import load_manifest
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
        # --allow-gh (explicitly set IPv4 preset) with --type host_port triggers the guard
        result = runner.invoke(
            cli,
            ["rule", "create", "--name", "MY_RULE", "--db", "MY_DB",
             "--type", "host_port", "--allow-gh", "--policy", "P"],
        )
        assert result.exit_code == 1
        assert "ipv4" in result.output.lower() or "invalid" in result.output.lower()

    def test_allow_local_auto_coerced_for_host_port(self):
        """--allow-local default (True) is silently coerced off for HOST_PORT rules."""
        runner = CliRunner()
        # With auto-coerce: --type host_port no longer errors on the preset guard;
        # instead it hits "No values specified" (correct behaviour for no-value HOST_PORT)
        result = runner.invoke(
            cli,
            ["rule", "create", "--name", "MY_RULE", "--db", "MY_DB", "--type", "host_port"],
        )
        assert result.exit_code == 1
        # Must NOT error with "ipv4 presets" message — that would mean coerce failed
        assert "ipv4 presets" not in result.output.lower()
        # Must error with "no values" since no --preset or --values provided
        assert "no values" in result.output.lower() or "values" in result.output.lower()

    def test_no_values_raises(self):
        runner = CliRunner()
        # --no-local with no --values → collect_ipv4_cidrs returns [] → "No values specified"
        result = runner.invoke(
            cli,
            ["rule", "create", "--name", "MY_RULE", "--db", "MY_DB", "--no-local"],
        )
        assert result.exit_code == 1
        assert "No values" in result.output

    def test_preset_auto_derives_egress_host_port(self):
        """--preset alone auto-sets mode=EGRESS and type=HOST_PORT from PRESET_REGISTRY."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["rule", "create", "--name", "SLACK_RULE", "--db", "MY_DB",
             "--preset", "slack", "--dry-run"],
        )
        assert result.exit_code == 0, result.output
        assert "EGRESS" in result.output
        assert "HOST_PORT" in result.output
        assert "*.slack.com:443" in result.output
        # Confirm local IP is NOT included (auto-coerced off for HOST_PORT)
        assert "allow_local" not in result.output.lower() or "192." not in result.output


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


_ALTERED_POLICY_MANIFEST = textwrap.dedent("""\
    schema_version = "1"
    project_name   = "test-project"
    created_at     = "2026-01-01T00:00:00Z"

    [snowflake]
    connection   = "local-oauth"
    sf_utils_db  = "TEST_DB"
    admin_role   = "ACCOUNTADMIN"

    [prereqs]
    tools_verified = "2026-01-01"
    infra_ready    = true

    [rule.my-pg-rule]
    status      = "COMPLETE"
    rule_name   = "MY_PG_RULE"
    rule_mode   = "POSTGRES_INGRESS"
    rule_type   = "IPV4"
    value_list  = ["1.2.3.4/32"]
    policy      = "MY_POLICY"
    eai         = ""
    sf_utils_db = "TEST_DB"
    admin_role  = "ACCOUNTADMIN"
    created_at  = "2026-01-01T00:00:00Z"
    updated_at  = "2026-01-01T00:00:00Z"

    [rule.my-pg-rule.cleanup]
    rule_name = "MY_PG_RULE"
    db        = "TEST_DB"

    [policy.my-policy]
    name       = "MY_POLICY"
    status     = "COMPLETE"
    operation  = "ALTERED"
    created_at = "2026-01-01T00:00:00Z"
    updated_at = "2026-01-01T00:00:00Z"
    admin_role = "ACCOUNTADMIN"

    [policy.my-policy.rules]
    my-pg-rule = "TEST_DB.NETWORKS.MY_PG_RULE"
""")

_ALTERED_EAI_MANIFEST = textwrap.dedent("""\
    schema_version = "1"
    project_name   = "test-project"
    created_at     = "2026-01-01T00:00:00Z"

    [snowflake]
    connection   = "local-oauth"
    sf_utils_db  = "TEST_DB"
    admin_role   = "ACCOUNTADMIN"

    [prereqs]
    tools_verified = "2026-01-01"
    infra_ready    = true

    [rule.my-egress-rule]
    status      = "COMPLETE"
    rule_name   = "MY_EGRESS_RULE"
    rule_mode   = "EGRESS"
    rule_type   = "HOST_PORT"
    value_list  = ["api.example.com:443"]
    eai         = "MY_EAI"
    policy      = ""
    sf_utils_db = "TEST_DB"
    admin_role  = "ACCOUNTADMIN"
    created_at  = "2026-01-01T00:00:00Z"
    updated_at  = "2026-01-01T00:00:00Z"

    [rule.my-egress-rule.cleanup]
    rule_name = "MY_EGRESS_RULE"
    db        = "TEST_DB"

    [eai.my-eai]
    name       = "MY_EAI"
    status     = "COMPLETE"
    operation  = "ALTERED"
    created_at = "2026-01-01T00:00:00Z"
    updated_at = "2026-01-01T00:00:00Z"
    admin_role = "ACCOUNTADMIN"

    [eai.my-eai.rules]
    my-egress-rule = "TEST_DB.NETWORKS.MY_EGRESS_RULE"
""")

_CREATED_EAI_MANIFEST = textwrap.dedent("""\
    schema_version = "1"
    project_name   = "test-project"
    created_at     = "2026-01-01T00:00:00Z"

    [snowflake]
    connection   = "local-oauth"
    sf_utils_db  = "TEST_DB"
    admin_role   = "ACCOUNTADMIN"

    [prereqs]
    tools_verified = "2026-01-01"
    infra_ready    = true

    [rule.my-egress-rule]
    status      = "COMPLETE"
    rule_name   = "MY_EGRESS_RULE"
    rule_mode   = "EGRESS"
    rule_type   = "HOST_PORT"
    value_list  = ["api.example.com:443"]
    eai         = "MY_EAI"
    policy      = ""
    sf_utils_db = "TEST_DB"
    admin_role  = "ACCOUNTADMIN"
    created_at  = "2026-01-01T00:00:00Z"
    updated_at  = "2026-01-01T00:00:00Z"

    [rule.my-egress-rule.cleanup]
    rule_name = "MY_EGRESS_RULE"
    db        = "TEST_DB"

    [eai.my-eai]
    name       = "MY_EAI"
    status     = "COMPLETE"
    operation  = "CREATED"
    created_at = "2026-01-01T00:00:00Z"
    updated_at = "2026-01-01T00:00:00Z"
    admin_role = "ACCOUNTADMIN"

    [eai.my-eai.rules]
    my-egress-rule = "TEST_DB.NETWORKS.MY_EGRESS_RULE"
""")

_CREATED_POLICY_MANIFEST = textwrap.dedent("""\
    schema_version = "1"
    project_name   = "test-project"
    created_at     = "2026-01-01T00:00:00Z"

    [snowflake]
    connection   = "local-oauth"
    sf_utils_db  = "TEST_DB"
    admin_role   = "ACCOUNTADMIN"

    [prereqs]
    tools_verified = "2026-01-01"
    infra_ready    = true

    [rule.my-ingress-rule]
    status      = "COMPLETE"
    rule_name   = "MY_INGRESS_RULE"
    rule_mode   = "INGRESS"
    rule_type   = "IPV4"
    value_list  = ["1.2.3.4/32"]
    policy      = "MY_POLICY"
    eai         = ""
    sf_utils_db = "TEST_DB"
    admin_role  = "ACCOUNTADMIN"
    created_at  = "2026-01-01T00:00:00Z"
    updated_at  = "2026-01-01T00:00:00Z"

    [rule.my-ingress-rule.cleanup]
    rule_name = "MY_INGRESS_RULE"
    db        = "TEST_DB"

    [policy.my-policy]
    name       = "MY_POLICY"
    status     = "COMPLETE"
    operation  = "CREATED"
    created_at = "2026-01-01T00:00:00Z"
    updated_at = "2026-01-01T00:00:00Z"
    admin_role = "ACCOUNTADMIN"

    [policy.my-policy.rules]
    my-ingress-rule = "TEST_DB.NETWORKS.MY_INGRESS_RULE"
""")


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

    def test_altered_policy_last_rule_removed_sets_status_removed(self):
        """Bug fix: removing last rule from ALTERED policy must write REMOVED, not EMPTY."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            import os
            os.makedirs(".sfutils", exist_ok=True)
            with open(".sfutils/manifest.toml", "w") as f:
                f.write(_ALTERED_POLICY_MANIFEST)
            with (
                patch("sfutils_networks.network.run_snow_sql_stdin"),
                patch("sfutils_networks.network.delete_network_rule"),
            ):
                result = runner.invoke(
                    cli,
                    ["rule", "delete", "--name", "MY_PG_RULE", "--db", "TEST_DB", "--yes"],
                )
            assert result.exit_code == 0, result.output
            data = load_manifest(".sfutils/manifest.toml")
            pol = data["policy"]["my-policy"]
            assert pol["status"] == "REMOVED", (
                f"Expected 'REMOVED' but got '{pol['status']}' — EMPTY bug still present"
            )
            assert "removed_at" in pol

    def test_altered_eai_last_rule_removed_sets_status_removed(self):
        """Bug fix: removing last rule from ALTERED EAI must write REMOVED, not EMPTY."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            import os
            os.makedirs(".sfutils", exist_ok=True)
            with open(".sfutils/manifest.toml", "w") as f:
                f.write(_ALTERED_EAI_MANIFEST)
            with (
                patch("sfutils_networks.network.run_snow_sql_stdin"),
                patch("sfutils_networks.network.delete_network_rule"),
                patch("sfutils_networks.network.get_eai_current_rules", return_value=[]),
            ):
                result = runner.invoke(
                    cli,
                    ["rule", "delete", "--name", "MY_EGRESS_RULE", "--db", "TEST_DB", "--yes"],
                )
            assert result.exit_code == 0, result.output
            data = load_manifest(".sfutils/manifest.toml")
            eai = data["eai"]["my-eai"]
            assert eai["status"] == "REMOVED", (
                f"Expected 'REMOVED' but got '{eai['status']}' — EMPTY bug still present"
            )
            assert "removed_at" in eai

    def test_created_eai_rules_dict_cleared_on_deletion(self):
        """Bug fix: dropping a CREATED EAI must clear [eai.*.rules] — no stale entries."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            import os
            os.makedirs(".sfutils", exist_ok=True)
            with open(".sfutils/manifest.toml", "w") as f:
                f.write(_CREATED_EAI_MANIFEST)
            with (
                patch("sfutils_networks.network.run_snow_sql_stdin"),
                patch("sfutils_networks.network.delete_network_rule"),
                patch("sfutils_networks.network.delete_external_access_integration"),
            ):
                result = runner.invoke(
                    cli,
                    ["rule", "delete", "--name", "MY_EGRESS_RULE", "--db", "TEST_DB", "--yes"],
                )
            assert result.exit_code == 0, result.output
            data = load_manifest(".sfutils/manifest.toml")
            eai = data["eai"]["my-eai"]
            assert eai["status"] == "REMOVED"
            assert "removed_at" in eai
            assert eai.get("rules", {}) == {}, (
                "CREATED EAI rules dict should be empty after deletion — stale entry bug present"
            )

    def test_created_policy_rules_dict_cleared_on_deletion(self):
        """Bug fix: dropping a CREATED policy must clear [policy.*.rules] — no stale entries."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            import os
            os.makedirs(".sfutils", exist_ok=True)
            with open(".sfutils/manifest.toml", "w") as f:
                f.write(_CREATED_POLICY_MANIFEST)
            with (
                patch("sfutils_networks.network.run_snow_sql_stdin"),
                patch("sfutils_networks.network.delete_network_rule"),
                patch("sfutils_networks.network.delete_network_policy"),
            ):
                result = runner.invoke(
                    cli,
                    ["rule", "delete", "--name", "MY_INGRESS_RULE", "--db", "TEST_DB", "--yes"],
                )
            assert result.exit_code == 0, result.output
            data = load_manifest(".sfutils/manifest.toml")
            pol = data["policy"]["my-policy"]
            assert pol["status"] == "REMOVED"
            assert "removed_at" in pol
            assert pol.get("rules", {}) == {}, (
                "CREATED policy rules dict should be empty after deletion — stale entry bug present"
            )


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
