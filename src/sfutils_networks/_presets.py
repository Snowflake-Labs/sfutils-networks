"""
IPv4 preset providers and network rule enums for Snowflake.

Provides:
- NetworkRuleMode and NetworkRuleType enums
- Mode/type validation
- IPv4 preset fetchers (GitHub Actions, Google App Scripts, local IP)
- CIDR collection utility
"""

import ipaddress
from enum import StrEnum
from functools import lru_cache

import click
import requests

# Snowflake-managed GitHub Actions SaaS rule — always current, no manual refresh.
# Add to a network policy's ALLOWED_NETWORK_RULE_LIST instead of inlining snapshot CIDRs.
# Not available in gov regions.
SNOWFLAKE_MANAGED_GITHUB_ACTIONS_RULE_FQN = (
    "SNOWFLAKE.NETWORK_SECURITY.GITHUBACTIONS_GLOBAL"
)

# Intent Vocabulary for EGRESS HOST_PORT external access.
# Named concepts bridging human language to HOST:PORT specs.
# Only applicable when mode=EGRESS AND type=HOST_PORT.
# Grounded in real production EAI usage (KAMESH_DEMOS.NETWORKS.*).
EAI_HOST_PRESETS: dict[str, list[str]] = {
    "slack":        ["*.slack.com:443"],
    "github":       ["*.github.com:443"],
    "google-apis":  ["www.googleapis.com:443", "oauth2.googleapis.com:443",
                     "admin.googleapis.com:443", "accounts.google.com:443"],
    "google-drive": ["drive.google.com:443", "www.googleapis.com:443",
                     "oauth2.googleapis.com:443", "admin.googleapis.com:443",
                     "accounts.google.com:443"],
    "aws":          ["*.amazonaws.com:443", "*.amazon.com:443"],
    "snowflake":    ["*.snowflakecomputing.com:443"],
    "openai":       ["api.openai.com:443"],
    "anthropic":    ["api.anthropic.com:443"],
    "huggingface":  ["huggingface.co:443", "api-inference.huggingface.co:443"],
    "pypi":         ["pypi.org:443", "files.pythonhosted.org:443"],
    "sharepoint":   ["*.sharepoint.com:443", "graph.microsoft.com:443",
                     "login.microsoftonline.com:443"],
}
EGRESS_PRESET_NAMES: list[str] = sorted(EAI_HOST_PRESETS)


def collect_egress_hosts(
    presets: list[str] | None = None,
    custom_values: list[str] | None = None,
) -> list[str]:
    """Resolve intent vocabulary presets to concrete HOST:PORT strings. Deduplicates."""
    hosts: list[str] = []
    for name in (presets or []):
        hosts.extend(EAI_HOST_PRESETS.get(name, []))
    hosts.extend(custom_values or [])
    return list(dict.fromkeys(hosts))


def _validate_cidr(cidr: str) -> str:
    """Validate and normalise a CIDR string. Raises ClickException on bad input."""
    try:
        return str(ipaddress.ip_network(cidr, strict=False))
    except ValueError as e:
        raise click.ClickException(f"Invalid CIDR '{cidr}': {e}") from e


class NetworkRuleMode(StrEnum):
    """Snowflake network rule modes."""

    INGRESS = "INGRESS"
    INTERNAL_STAGE = "INTERNAL_STAGE"
    EGRESS = "EGRESS"
    POSTGRES_INGRESS = "POSTGRES_INGRESS"
    POSTGRES_EGRESS = "POSTGRES_EGRESS"


class NetworkRuleType(StrEnum):
    """Snowflake network rule value types."""

    IPV4 = "IPV4"
    HOST_PORT = "HOST_PORT"
    PRIVATE_HOST_PORT = "PRIVATE_HOST_PORT"
    AWSVPCEID = "AWSVPCEID"


VALID_MODE_TYPES: dict[NetworkRuleMode, list[NetworkRuleType]] = {
    NetworkRuleMode.INGRESS: [NetworkRuleType.IPV4, NetworkRuleType.AWSVPCEID],
    NetworkRuleMode.INTERNAL_STAGE: [NetworkRuleType.IPV4, NetworkRuleType.AWSVPCEID],
    NetworkRuleMode.EGRESS: [NetworkRuleType.IPV4, NetworkRuleType.HOST_PORT],
    NetworkRuleMode.POSTGRES_INGRESS: [NetworkRuleType.IPV4, NetworkRuleType.AWSVPCEID],
    NetworkRuleMode.POSTGRES_EGRESS: [NetworkRuleType.IPV4, NetworkRuleType.HOST_PORT],
}


def validate_mode_type(mode: NetworkRuleMode, rule_type: NetworkRuleType) -> bool:
    """Check if mode/type combination is valid per Snowflake docs."""
    return rule_type in VALID_MODE_TYPES.get(mode, [])


def get_valid_types_for_mode(mode: NetworkRuleMode) -> list[str]:
    """Get list of valid type names for a given mode."""
    return [t.value for t in VALID_MODE_TYPES.get(mode, [])]


def _is_ipv4_cidr(cidr: str) -> bool:
    """Check if a CIDR is IPv4 (not IPv6). IPv6 CIDRs contain ':'."""
    return ":" not in cidr


@lru_cache(maxsize=1)
def get_github_actions_ips() -> tuple[str, ...]:
    """Fetch GitHub Actions runner IPv4 CIDRs from GitHub meta API.

    See: https://api.github.com/meta
    """
    response = requests.get("https://api.github.com/meta", timeout=30)
    response.raise_for_status()
    all_ips = response.json().get("actions", [])
    return tuple(_validate_cidr(ip) for ip in all_ips if _is_ipv4_cidr(ip))


@lru_cache(maxsize=1)
def get_google_ips() -> tuple[str, ...]:
    """Fetch Google IPv4 ranges from gstatic.com.

    See: https://www.gstatic.com/ipranges/goog.json
    """
    response = requests.get("https://www.gstatic.com/ipranges/goog.json", timeout=30)
    response.raise_for_status()
    prefixes = response.json().get("prefixes", [])
    return tuple(_validate_cidr(p["ipv4Prefix"]) for p in prefixes if "ipv4Prefix" in p)


def get_local_ip() -> str:
    """Get current public IP address with /32 CIDR suffix."""
    response = requests.get("https://api.ipify.org", timeout=10)
    response.raise_for_status()
    cidr = f"{response.text.strip()}/32"
    return _validate_cidr(cidr)


def collect_ipv4_cidrs(
    with_local: bool = True,
    with_gh: bool = False,
    with_google: bool = False,
    extra_cidrs: list[str] | None = None,
) -> list[str]:
    """Collect IPv4 CIDRs from enabled presets and extra values.

    Returns deduplicated list preserving insertion order.
    """
    cidrs: list[str] = []

    if with_local:
        cidrs.append(get_local_ip())
    if with_gh:
        cidrs.extend(get_github_actions_ips())
    if with_google:
        cidrs.extend(get_google_ips())
    if extra_cidrs:
        cidrs.extend(_validate_cidr(c) for c in extra_cidrs)

    return list(dict.fromkeys(cidrs))
