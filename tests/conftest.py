"""Shared pytest fixtures for sfutils-networks test suite."""

import pytest

from sfutils_networks._presets import get_github_actions_ips, get_google_ips


@pytest.fixture(autouse=True)
def clear_preset_caches():
    """Clear lru_cache on preset fetchers before and after each test.

    get_github_actions_ips() and get_google_ips() use @lru_cache(maxsize=1).
    Without clearing, a cached result from one test leaks into the next.
    """
    get_github_actions_ips.cache_clear()
    get_google_ips.cache_clear()
    yield
    get_github_actions_ips.cache_clear()
    get_google_ips.cache_clear()
