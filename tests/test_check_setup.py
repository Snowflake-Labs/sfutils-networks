"""Tests for pure utility functions in sfutils_networks.check_setup.

No subprocess calls — covers only resolved_sf_utils_db and
resolved_sa_admin_role, which are pure env-variable resolvers.
"""

from __future__ import annotations

from sfutils_networks.check_setup import resolved_sa_admin_role, resolved_sf_utils_db

# ---------------------------------------------------------------------------
# resolved_sf_utils_db
# ---------------------------------------------------------------------------


class TestResolvedSfUtilsDb:
    def test_explicit_arg_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("SF_UTILS_DB", "ENV_DB")
        result = resolved_sf_utils_db(database="ARG_DB", default_db="DEFAULT")
        assert result == "ARG_DB"

    def test_sf_utils_db_env_wins_over_default(self, monkeypatch):
        monkeypatch.delenv("SF_UTILS_DB", raising=False)
        monkeypatch.delenv("SNOW_UTILS_DB", raising=False)
        monkeypatch.setenv("SF_UTILS_DB", "ENV_DB")
        result = resolved_sf_utils_db(database=None, default_db="DEFAULT")
        assert result == "ENV_DB"

    def test_legacy_snow_utils_db_env_fallback(self, monkeypatch):
        monkeypatch.delenv("SF_UTILS_DB", raising=False)
        monkeypatch.setenv("SNOW_UTILS_DB", "LEGACY_DB")
        result = resolved_sf_utils_db(database=None, default_db="DEFAULT")
        assert result == "LEGACY_DB"

    def test_falls_back_to_default_db(self, monkeypatch):
        monkeypatch.delenv("SF_UTILS_DB", raising=False)
        monkeypatch.delenv("SNOW_UTILS_DB", raising=False)
        result = resolved_sf_utils_db(database=None, default_db="MY_DEFAULT")
        assert result == "MY_DEFAULT"

    def test_sf_utils_db_takes_precedence_over_legacy(self, monkeypatch):
        monkeypatch.setenv("SF_UTILS_DB", "PRIMARY")
        monkeypatch.setenv("SNOW_UTILS_DB", "LEGACY")
        result = resolved_sf_utils_db(database=None, default_db="DEFAULT")
        assert result == "PRIMARY"


# ---------------------------------------------------------------------------
# resolved_sa_admin_role
# ---------------------------------------------------------------------------


class TestResolvedSaAdminRole:
    def test_explicit_arg_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("SA_ADMIN_ROLE", "ENV_ROLE")
        result = resolved_sa_admin_role(admin_role="ARG_ROLE")
        assert result == "ARG_ROLE"

    def test_sa_admin_role_env_used_when_no_arg(self, monkeypatch):
        monkeypatch.delenv("SA_ADMIN_ROLE", raising=False)
        monkeypatch.setenv("SA_ADMIN_ROLE", "ENV_ROLE")
        result = resolved_sa_admin_role(admin_role=None)
        assert result == "ENV_ROLE"

    def test_defaults_to_accountadmin(self, monkeypatch):
        monkeypatch.delenv("SA_ADMIN_ROLE", raising=False)
        result = resolved_sa_admin_role(admin_role=None)
        assert result == "ACCOUNTADMIN"

    def test_blank_arg_falls_through_to_env(self, monkeypatch):
        monkeypatch.setenv("SA_ADMIN_ROLE", "ENV_ROLE")
        # Empty string is falsy — the resolver skips it and checks env next
        result = resolved_sa_admin_role(admin_role="")
        assert result == "ENV_ROLE"
