"""Tests for sfutils_networks._presets module.

Covers: _validate_cidr, _is_ipv4_cidr, NetworkRuleMode, NetworkRuleType,
validate_mode_type, get_valid_types_for_mode, get_github_actions_ips,
get_google_ips, get_local_ip, collect_ipv4_cidrs.
"""

import pytest
import requests
from unittest.mock import MagicMock, patch

import click

from sfutils_networks._presets import (
    _validate_cidr,
    _is_ipv4_cidr,
    NetworkRuleMode,
    NetworkRuleType,
    validate_mode_type,
    get_valid_types_for_mode,
    get_github_actions_ips,
    get_google_ips,
    get_local_ip,
    collect_ipv4_cidrs,
)

# ---------------------------------------------------------------------------
# _validate_cidr
# ---------------------------------------------------------------------------


class TestValidateCidr:
    def test_valid_host_cidr(self):
        assert _validate_cidr("192.168.1.5/32") == "192.168.1.5/32"

    def test_valid_network_cidr(self):
        assert _validate_cidr("10.0.0.0/8") == "10.0.0.0/8"

    def test_host_bits_normalised_with_strict_false(self):
        # strict=False: 192.168.1.5/24 normalises host bits → 192.168.1.0/24
        assert _validate_cidr("192.168.1.5/24") == "192.168.1.0/24"

    def test_valid_ipv6(self):
        assert _validate_cidr("2001:db8::/32") == "2001:db8::/32"

    def test_invalid_cidr_raises(self):
        with pytest.raises(click.ClickException, match="Invalid CIDR"):
            _validate_cidr("not-an-ip")

    def test_invalid_prefix_length_raises(self):
        with pytest.raises(click.ClickException, match="Invalid CIDR"):
            _validate_cidr("10.0.0.0/33")

    def test_empty_string_raises(self):
        with pytest.raises(click.ClickException, match="Invalid CIDR"):
            _validate_cidr("")

    def test_returns_string(self):
        result = _validate_cidr("10.0.0.0/8")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# _is_ipv4_cidr
# ---------------------------------------------------------------------------


class TestIsIpv4Cidr:
    def test_ipv4_cidr_is_true(self):
        assert _is_ipv4_cidr("192.168.1.0/24") is True

    def test_ipv4_single_host_is_true(self):
        assert _is_ipv4_cidr("10.0.0.1/32") is True

    def test_ipv6_is_false(self):
        assert _is_ipv4_cidr("2001:db8::/32") is False

    def test_ipv6_loopback_is_false(self):
        assert _is_ipv4_cidr("::1/128") is False

    def test_colon_detection(self):
        # The check is purely colon-based
        assert _is_ipv4_cidr("no-colon") is True
        assert _is_ipv4_cidr("has:colon") is False


# ---------------------------------------------------------------------------
# Enum values
# ---------------------------------------------------------------------------


class TestNetworkRuleMode:
    def test_ingress(self):
        assert NetworkRuleMode.INGRESS.value == "INGRESS"

    def test_internal_stage(self):
        assert NetworkRuleMode.INTERNAL_STAGE.value == "INTERNAL_STAGE"

    def test_egress(self):
        assert NetworkRuleMode.EGRESS.value == "EGRESS"

    def test_postgres_ingress(self):
        assert NetworkRuleMode.POSTGRES_INGRESS.value == "POSTGRES_INGRESS"

    def test_postgres_egress(self):
        assert NetworkRuleMode.POSTGRES_EGRESS.value == "POSTGRES_EGRESS"

    def test_five_modes(self):
        assert len(NetworkRuleMode) == 5

    def test_str_enum(self):
        # str subclass: member compares equal to its string value (used in SQL/comparisons)
        # Note: str() on (str, Enum) returns "ClassName.MEMBER" in Python 3.12+;
        # use .value or == for actual string comparisons.
        assert NetworkRuleMode.INGRESS == "INGRESS"


class TestNetworkRuleType:
    def test_ipv4(self):
        assert NetworkRuleType.IPV4.value == "IPV4"

    def test_host_port(self):
        assert NetworkRuleType.HOST_PORT.value == "HOST_PORT"

    def test_private_host_port(self):
        assert NetworkRuleType.PRIVATE_HOST_PORT.value == "PRIVATE_HOST_PORT"

    def test_awsvpceid(self):
        assert NetworkRuleType.AWSVPCEID.value == "AWSVPCEID"

    def test_four_types(self):
        assert len(NetworkRuleType) == 4


# ---------------------------------------------------------------------------
# validate_mode_type / get_valid_types_for_mode
# ---------------------------------------------------------------------------


class TestValidateModeType:
    @pytest.mark.parametrize(
        "mode,rule_type,expected",
        [
            (NetworkRuleMode.INGRESS, NetworkRuleType.IPV4, True),
            (NetworkRuleMode.INGRESS, NetworkRuleType.AWSVPCEID, True),
            (NetworkRuleMode.INGRESS, NetworkRuleType.HOST_PORT, False),
            (NetworkRuleMode.INGRESS, NetworkRuleType.PRIVATE_HOST_PORT, False),
            (NetworkRuleMode.EGRESS, NetworkRuleType.IPV4, True),
            (NetworkRuleMode.EGRESS, NetworkRuleType.HOST_PORT, True),
            (NetworkRuleMode.EGRESS, NetworkRuleType.AWSVPCEID, False),
            (NetworkRuleMode.EGRESS, NetworkRuleType.PRIVATE_HOST_PORT, False),
            (NetworkRuleMode.INTERNAL_STAGE, NetworkRuleType.IPV4, True),
            (NetworkRuleMode.INTERNAL_STAGE, NetworkRuleType.AWSVPCEID, True),
            (NetworkRuleMode.INTERNAL_STAGE, NetworkRuleType.HOST_PORT, False),
            (NetworkRuleMode.POSTGRES_INGRESS, NetworkRuleType.IPV4, True),
            (NetworkRuleMode.POSTGRES_INGRESS, NetworkRuleType.AWSVPCEID, True),
            (NetworkRuleMode.POSTGRES_INGRESS, NetworkRuleType.HOST_PORT, False),
            (NetworkRuleMode.POSTGRES_EGRESS, NetworkRuleType.IPV4, True),
            (NetworkRuleMode.POSTGRES_EGRESS, NetworkRuleType.HOST_PORT, True),
            (NetworkRuleMode.POSTGRES_EGRESS, NetworkRuleType.AWSVPCEID, False),
        ],
    )
    def test_mode_type_combinations(self, mode, rule_type, expected):
        assert validate_mode_type(mode, rule_type) == expected


class TestGetValidTypesForMode:
    def test_ingress_types(self):
        assert set(get_valid_types_for_mode(NetworkRuleMode.INGRESS)) == {"IPV4", "AWSVPCEID"}

    def test_egress_types(self):
        assert set(get_valid_types_for_mode(NetworkRuleMode.EGRESS)) == {"IPV4", "HOST_PORT"}

    def test_internal_stage_types(self):
        assert set(get_valid_types_for_mode(NetworkRuleMode.INTERNAL_STAGE)) == {
            "IPV4",
            "AWSVPCEID",
        }

    def test_postgres_ingress_types(self):
        assert set(get_valid_types_for_mode(NetworkRuleMode.POSTGRES_INGRESS)) == {
            "IPV4",
            "AWSVPCEID",
        }

    def test_postgres_egress_types(self):
        assert set(get_valid_types_for_mode(NetworkRuleMode.POSTGRES_EGRESS)) == {
            "IPV4",
            "HOST_PORT",
        }

    def test_returns_list_of_strings(self):
        result = get_valid_types_for_mode(NetworkRuleMode.INGRESS)
        assert isinstance(result, list)
        assert all(isinstance(t, str) for t in result)


# ---------------------------------------------------------------------------
# Fixture data for external API mocks
# ---------------------------------------------------------------------------

GITHUB_META_RESPONSE = {
    "actions": [
        "192.30.252.0/22",
        "185.199.108.0/22",
        "2001:db8::/32",  # IPv6 — should be filtered out
    ]
}

GSTATIC_RESPONSE = {
    "prefixes": [
        {"ipv4Prefix": "8.8.8.0/24"},
        {"ipv4Prefix": "8.8.4.0/24"},
        {"ipv6Prefix": "2001:db8::/32"},  # no ipv4Prefix key — should be skipped
    ]
}


# ---------------------------------------------------------------------------
# get_github_actions_ips
# ---------------------------------------------------------------------------


class TestGetGithubActionsIps:
    def test_returns_ipv4_only(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = GITHUB_META_RESPONSE
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            result = get_github_actions_ips()
        assert "192.30.252.0/22" in result
        assert "185.199.108.0/22" in result

    def test_filters_ipv6_addresses(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = GITHUB_META_RESPONSE
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            result = get_github_actions_ips()
        assert not any(":" in ip for ip in result)

    def test_returns_tuple(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = GITHUB_META_RESPONSE
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            result = get_github_actions_ips()
        assert isinstance(result, tuple)

    def test_empty_actions_list_returns_empty_tuple(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"actions": []}
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            result = get_github_actions_ips()
        assert result == ()

    def test_http_error_propagates(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.HTTPError("403")
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            with pytest.raises(requests.HTTPError):
                get_github_actions_ips()

    def test_cidrs_are_normalised_via_validate_cidr(self):
        # 10.0.0.5/24 has host bits set; strict=False normalises to 10.0.0.0/24
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"actions": ["10.0.0.5/24"]}
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            result = get_github_actions_ips()
        assert result == ("10.0.0.0/24",)

    def test_calls_api_endpoint(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"actions": []}
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp) as mock_get:
            get_github_actions_ips()
        mock_get.assert_called_once_with("https://api.github.com/meta", timeout=30)


# ---------------------------------------------------------------------------
# get_google_ips
# ---------------------------------------------------------------------------


class TestGetGoogleIps:
    def test_returns_ipv4_prefixes(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = GSTATIC_RESPONSE
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            result = get_google_ips()
        assert "8.8.8.0/24" in result
        assert "8.8.4.0/24" in result

    def test_skips_ipv6_only_entries(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = GSTATIC_RESPONSE
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            result = get_google_ips()
        assert not any(":" in ip for ip in result)

    def test_returns_tuple(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = GSTATIC_RESPONSE
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            result = get_google_ips()
        assert isinstance(result, tuple)

    def test_empty_prefixes_returns_empty_tuple(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"prefixes": []}
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            result = get_google_ips()
        assert result == ()

    def test_http_error_propagates(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.HTTPError("500")
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            with pytest.raises(requests.HTTPError):
                get_google_ips()

    def test_calls_gstatic_endpoint(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"prefixes": []}
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp) as mock_get:
            get_google_ips()
        mock_get.assert_called_once_with(
            "https://www.gstatic.com/ipranges/goog.json", timeout=30
        )


# ---------------------------------------------------------------------------
# get_local_ip
# ---------------------------------------------------------------------------


class TestGetLocalIp:
    def test_appends_slash_32(self):
        mock_resp = MagicMock()
        mock_resp.text = "203.0.113.42"
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            result = get_local_ip()
        assert result == "203.0.113.42/32"

    def test_strips_whitespace(self):
        mock_resp = MagicMock()
        mock_resp.text = "  10.0.0.1  \n"
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            result = get_local_ip()
        assert result == "10.0.0.1/32"

    def test_invalid_ip_from_ipify_raises(self):
        mock_resp = MagicMock()
        mock_resp.text = "not-an-ip"
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            with pytest.raises(click.ClickException, match="Invalid CIDR"):
                get_local_ip()

    def test_http_error_propagates(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.ConnectionError("timeout")
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp):
            with pytest.raises(requests.ConnectionError):
                get_local_ip()

    def test_calls_ipify(self):
        mock_resp = MagicMock()
        mock_resp.text = "1.2.3.4"
        with patch("sfutils_networks._presets.requests.get", return_value=mock_resp) as mock_get:
            get_local_ip()
        mock_get.assert_called_once_with("https://api.ipify.org", timeout=10)


# ---------------------------------------------------------------------------
# collect_ipv4_cidrs
# ---------------------------------------------------------------------------


class TestCollectIpv4Cidrs:
    def test_local_only(self):
        with patch("sfutils_networks._presets.get_local_ip", return_value="1.2.3.4/32"):
            result = collect_ipv4_cidrs(with_local=True, with_gh=False, with_google=False)
        assert result == ["1.2.3.4/32"]

    def test_gh_only(self):
        with patch("sfutils_networks._presets.get_github_actions_ips", return_value=("10.0.0.0/8",)):
            result = collect_ipv4_cidrs(with_local=False, with_gh=True, with_google=False)
        assert result == ["10.0.0.0/8"]

    def test_google_only(self):
        with patch("sfutils_networks._presets.get_google_ips", return_value=("8.8.8.0/24",)):
            result = collect_ipv4_cidrs(with_local=False, with_gh=False, with_google=True)
        assert result == ["8.8.8.0/24"]

    def test_all_presets_combined(self):
        with (
            patch("sfutils_networks._presets.get_local_ip", return_value="1.2.3.4/32"),
            patch(
                "sfutils_networks._presets.get_github_actions_ips", return_value=("10.0.0.0/8",)
            ),
            patch("sfutils_networks._presets.get_google_ips", return_value=("8.8.8.0/24",)),
        ):
            result = collect_ipv4_cidrs(with_local=True, with_gh=True, with_google=True)
        assert "1.2.3.4/32" in result
        assert "10.0.0.0/8" in result
        assert "8.8.8.0/24" in result

    def test_extra_cidrs_appended(self):
        result = collect_ipv4_cidrs(
            with_local=False,
            with_gh=False,
            with_google=False,
            extra_cidrs=["192.168.1.0/24", "172.16.0.0/12"],
        )
        assert result == ["192.168.1.0/24", "172.16.0.0/12"]

    def test_extra_cidrs_normalised_via_validate(self):
        # 10.0.0.5/24 has host bits → normalised to 10.0.0.0/24
        result = collect_ipv4_cidrs(with_local=False, extra_cidrs=["10.0.0.5/24"])
        assert result == ["10.0.0.0/24"]

    def test_deduplication_preserves_first_occurrence(self):
        with patch("sfutils_networks._presets.get_local_ip", return_value="1.2.3.4/32"):
            result = collect_ipv4_cidrs(with_local=True, extra_cidrs=["1.2.3.4/32"])
        assert result.count("1.2.3.4/32") == 1

    def test_order_preserved_local_before_gh(self):
        with (
            patch("sfutils_networks._presets.get_local_ip", return_value="1.2.3.4/32"),
            patch(
                "sfutils_networks._presets.get_github_actions_ips", return_value=("10.0.0.0/8",)
            ),
        ):
            result = collect_ipv4_cidrs(with_local=True, with_gh=True)
        assert result[0] == "1.2.3.4/32"
        assert result[1] == "10.0.0.0/8"

    def test_all_false_no_extra_returns_empty(self):
        result = collect_ipv4_cidrs(with_local=False, with_gh=False, with_google=False)
        assert result == []

    def test_invalid_extra_cidr_raises(self):
        with pytest.raises(click.ClickException, match="Invalid CIDR"):
            collect_ipv4_cidrs(with_local=False, extra_cidrs=["not-a-cidr"])

    def test_returns_list(self):
        with patch("sfutils_networks._presets.get_local_ip", return_value="1.2.3.4/32"):
            result = collect_ipv4_cidrs(with_local=True)
        assert isinstance(result, list)
