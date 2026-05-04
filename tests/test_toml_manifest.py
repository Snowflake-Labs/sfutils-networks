"""Tests for sfutils_networks._toml_manifest schema helpers."""

from __future__ import annotations

from sfutils_networks._toml_manifest import (
    ensure_manifest_defaults,
    get_eai_entry,
    get_eai_label_for_name,
    get_policy_label_for_name,
    load_manifest,
    promote_legacy_eai_policy_refs,
    save_manifest,
    upsert_eai,
    validate_manifest,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_valid_data() -> dict:
    """Return a minimal manifest dict that passes validate_manifest."""
    return {
        "schema_version": "1",
        "project_name": "test-project",
        "created_at": "2026-01-01T00:00:00Z",
        "snowflake": {
            "connection": "local-oauth",
            "sf_utils_db": "TEST_DB",
            "admin_role": "ACCOUNTADMIN",
        },
        "prereqs": {
            "tools_verified": "2026-01-01",
            "infra_ready": True,
        },
        "rule": {},
        "eai": {},
        "policy": {},
    }


# ---------------------------------------------------------------------------
# EAI helpers
# ---------------------------------------------------------------------------

class TestUpsertEai:
    def test_upsert_creates_entry(self):
        data: dict = {"eai": {}}
        cfg = {"name": "MY_EAI", "status": "COMPLETE", "operation": "CREATED"}
        upsert_eai(data, "my-eai", cfg)
        assert data["eai"]["my-eai"]["name"] == "MY_EAI"

    def test_upsert_replaces_entry(self):
        data: dict = {"eai": {"my-eai": {"name": "OLD_EAI"}}}
        upsert_eai(data, "my-eai", {"name": "NEW_EAI"})
        assert data["eai"]["my-eai"]["name"] == "NEW_EAI"


class TestGetEaiEntry:
    def test_get_by_label(self):
        data = {"eai": {"my-eai": {"name": "MY_EAI", "status": "COMPLETE"}}}
        entry = get_eai_entry(data, label="my-eai")
        assert entry is not None
        assert entry["name"] == "MY_EAI"

    def test_get_by_name(self):
        data = {"eai": {"my-eai": {"name": "MY_EAI", "status": "COMPLETE"}}}
        entry = get_eai_entry(data, name="my_eai")  # case-insensitive
        assert entry is not None
        assert entry["name"] == "MY_EAI"

    def test_get_missing_returns_none(self):
        data: dict = {"eai": {}}
        assert get_eai_entry(data, label="nope") is None


class TestGetLabelForName:
    def test_get_eai_label_case_insensitive(self):
        data = {"eai": {"my-eai": {"name": "MY_EAI"}}}
        assert get_eai_label_for_name(data, "my_eai") == "my-eai"
        assert get_eai_label_for_name(data, "MY_EAI") == "my-eai"

    def test_get_eai_label_missing_returns_none(self):
        data: dict = {"eai": {}}
        assert get_eai_label_for_name(data, "nope") is None

    def test_get_policy_label_case_insensitive(self):
        data = {"policy": {"my-pol": {"name": "MY_POL"}}}
        assert get_policy_label_for_name(data, "my_pol") == "my-pol"
        assert get_policy_label_for_name(data, "MY_POL") == "my-pol"


# ---------------------------------------------------------------------------
# Legacy promotion
# ---------------------------------------------------------------------------

class TestPromoteLegacyEaiPolicyRefs:
    def _legacy_data(self) -> dict:
        return {
            "rule": {
                "my-rule": {
                    "status": "COMPLETE",
                    "rule_name": "MY_RULE",
                    "rule_mode": "EGRESS",
                    "rule_type": "HOST_PORT",
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "admin_role": "ACCOUNTADMIN",
                    "resources": {
                        "network_rule": "TESTDB.NETWORKS.MY_RULE",
                        "integration_name": "MY_EAI",
                        "network_policy": "MY_POL",
                    },
                    "cleanup": {
                        "rule_name": "MY_RULE",
                        "db": "TESTDB",
                        "integration_name": "MY_EAI",
                        "policy_name": "MY_POL",
                    },
                    "policy_name": "MY_POL",
                }
            }
        }

    def test_promotes_integration_name_to_eai_section(self):
        data = self._legacy_data()
        result = promote_legacy_eai_policy_refs(data)
        assert result is True
        assert "my-eai" in data.get("eai", {})
        assert data["eai"]["my-eai"]["name"] == "MY_EAI"

    def test_promotes_policy_name_to_policy_section(self):
        data = self._legacy_data()
        promote_legacy_eai_policy_refs(data)
        assert "my-pol" in data.get("policy", {})
        assert data["policy"]["my-pol"]["name"] == "MY_POL"

    def test_idempotent_when_eai_section_present(self):
        data = self._legacy_data()
        data["eai"] = {"my-eai": {"name": "MY_EAI", "status": "COMPLETE", "operation": "CREATED"}}
        result = promote_legacy_eai_policy_refs(data)
        assert result is False

    def test_returns_false_when_nothing_to_promote(self):
        data: dict = {"rule": {}}
        result = promote_legacy_eai_policy_refs(data)
        assert result is False


# ---------------------------------------------------------------------------
# validate_manifest
# ---------------------------------------------------------------------------

class TestValidateManifest:
    def test_accepts_valid_eai_section(self):
        data = _minimal_valid_data()
        data["eai"] = {
            "my-eai": {
                "name": "MY_EAI",
                "status": "COMPLETE",
                "operation": "CREATED",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "admin_role": "ACCOUNTADMIN",
            }
        }
        issues = validate_manifest(data)
        assert issues == []

    def test_rejects_invalid_operation_value(self):
        data = _minimal_valid_data()
        data["eai"] = {
            "bad-eai": {
                "name": "BAD_EAI",
                "status": "COMPLETE",
                "operation": "DELETED",  # invalid
            }
        }
        issues = validate_manifest(data)
        assert any("invalid operation" in i for i in issues)

    def test_rejects_missing_name_field(self):
        data = _minimal_valid_data()
        data["eai"] = {
            "no-name-eai": {
                "status": "COMPLETE",
                "operation": "CREATED",
                # no "name"
            }
        }
        issues = validate_manifest(data)
        assert any("name" in i for i in issues)


# ---------------------------------------------------------------------------
# save/load round-trip
# ---------------------------------------------------------------------------

class TestSaveLoadRoundTrip:
    def test_roundtrip_preserves_eai_and_policy_with_rules(self, tmp_path):
        manifest_file = tmp_path / ".sfutils" / "manifest.toml"
        data = _minimal_valid_data()
        data["eai"] = {
            "my-eai": {
                "name": "MY_EAI",
                "status": "COMPLETE",
                "operation": "CREATED",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "admin_role": "ACCOUNTADMIN",
                "rules": {"my-rule": "DB.NETWORKS.MY_RULE"},
            }
        }
        data["policy"] = {
            "my-pol": {
                "name": "MY_POL",
                "status": "COMPLETE",
                "operation": "CREATED",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "admin_role": "ACCOUNTADMIN",
                "rules": {"my-rule": "DB.NETWORKS.MY_RULE"},
            }
        }
        save_manifest(manifest_file, data)
        loaded = load_manifest(manifest_file)

        assert loaded["eai"]["my-eai"]["name"] == "MY_EAI"
        assert loaded["eai"]["my-eai"]["rules"]["my-rule"] == "DB.NETWORKS.MY_RULE"
        assert loaded["policy"]["my-pol"]["name"] == "MY_POL"
        assert loaded["policy"]["my-pol"]["rules"]["my-rule"] == "DB.NETWORKS.MY_RULE"


# ---------------------------------------------------------------------------
# ensure_manifest_defaults triggers promotion
# ---------------------------------------------------------------------------

class TestEnsureManifestDefaultsTriggersPromotion:
    def test_triggers_legacy_promotion(self, tmp_path):
        manifest_file = tmp_path / ".sfutils" / "manifest.toml"
        data: dict = {
            "schema_version": "1",
            "project_name": "test",
            "created_at": "2026-01-01T00:00:00Z",
            "rule": {
                "my-rule": {
                    "status": "COMPLETE",
                    "rule_name": "MY_RULE",
                    "rule_mode": "EGRESS",
                    "rule_type": "HOST_PORT",
                    "created_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "admin_role": "ACCOUNTADMIN",
                    "resources": {
                        "network_rule": "DB.NETWORKS.MY_RULE",
                        "integration_name": "MY_EAI",
                    },
                    "cleanup": {
                        "rule_name": "MY_RULE",
                        "db": "DB",
                    },
                }
            },
        }
        ensure_manifest_defaults(data, manifest_file)
        # Should have promoted EAI from resources.integration_name
        assert "my-eai" in data.get("eai", {})
        assert data["eai"]["my-eai"]["name"] == "MY_EAI"
