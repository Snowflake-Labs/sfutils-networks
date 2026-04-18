"""
Vendored snow CLI utilities for sfutils-networks.

Thin wrappers around the `snow` CLI for executing SQL.
Originally aligned with shared sfutils patterns; this package is self-contained
beyond click/requests. Feel free to customize for network-specific needs.
"""

import json
import os
import subprocess
from dataclasses import dataclass

import click


@dataclass
class SnowCLIOptions:
    """Options for snow CLI commands."""

    verbose: bool = False
    debug: bool = False

    def get_flags(self) -> list[str]:
        flags = []
        if self.debug:
            flags.append("--debug")
        elif self.verbose:
            flags.append("--verbose")
        return flags


_snow_cli_options = SnowCLIOptions()


def set_snow_cli_options(verbose: bool = False, debug: bool = False, **kwargs) -> None:
    """Set global snow CLI options."""
    global _snow_cli_options
    _snow_cli_options = SnowCLIOptions(verbose=verbose, debug=debug)


def get_snow_cli_options() -> SnowCLIOptions:
    """Get current snow CLI options."""
    return _snow_cli_options


def run_snow_sql(
    query: str, *, format: str = "json", check: bool = True, role: str | None = None
) -> dict | list | None:
    """Execute a snow sql command and return parsed JSON output."""
    cmd = ["snow", "sql", *_snow_cli_options.get_flags(), "--query", query, "--format", format]
    if role:
        cmd.extend(["--role", role])

    if _snow_cli_options.debug:
        click.echo(f"[DEBUG] Running: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if _snow_cli_options.debug and result.stderr:
        click.echo(f"[DEBUG] stderr: {result.stderr}")

    if check and result.returncode != 0:
        raise click.ClickException(f"snow sql failed: {result.stderr}")

    if format == "json" and result.stdout.strip():
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
    return None


def run_snow_sql_stdin(sql: str, *, check: bool = True) -> subprocess.CompletedProcess:
    """Execute multi-statement SQL via stdin."""
    cmd = ["snow", "sql", *_snow_cli_options.get_flags(), "--stdin"]

    if _snow_cli_options.debug:
        click.echo(f"[DEBUG] Running: {' '.join(cmd)}")
        click.echo(f"[DEBUG] SQL ({len(sql)} chars — set SFUTILS_DEBUG_SQL=1 to show)")
        if os.environ.get("SFUTILS_DEBUG_SQL"):
            click.echo(sql)

    result = subprocess.run(cmd, input=sql, capture_output=True, text=True, check=False)

    if _snow_cli_options.debug and result.stderr:
        click.echo(f"[DEBUG] stderr: {result.stderr}")
    if _snow_cli_options.debug and result.stdout:
        click.echo(f"[DEBUG] stdout: {result.stdout}")

    if check and result.returncode != 0:
        raise click.ClickException(f"snow sql failed: {result.stderr}")

    return result
