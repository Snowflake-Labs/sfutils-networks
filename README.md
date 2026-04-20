# sfutils-networks

Create and manage Snowflake network rules and policies from the terminal. Supports IPv4 presets for GitHub Actions, Google services, and local IP detection.

**5+ manual steps → single command.**

## Prerequisites

- [Snowflake CLI](https://docs.snowflake.com/developer-guide/snowflake-cli/index) (`snow`) installed and configured
- Python 3.12+
- [Task](https://taskfile.dev) (optional, for task-based workflow)

## Install

```bash
uv sync          # or: pip install .
```

## Quick Start

```bash
# Create a network rule with your local IP (default)
sfutils-networks rule create --name dev_rule --db my_db

# Include GitHub Actions runner IPs for CI/CD
sfutils-networks rule create --name ci_rule --db my_db --allow-gh

# Create rule + network policy in one command
sfutils-networks rule create --name ci_rule --db my_db --allow-gh --policy ci_policy

# Google IPs (App Scripts, Cloud Functions, etc.)
sfutils-networks rule create --name google_rule --db my_db --allow-google

# Egress rule for external APIs
sfutils-networks rule create --name api_egress --db my_db \
    --mode egress --type host_port \
    --values "api.openai.com:443,api.anthropic.com:443"
```

## Task Workflow

```bash
task create NW_RULE_NAME=dev_rule NW_RULE_DB=my_db
task github NW_RULE_NAME=ci_rule NW_RULE_DB=my_db
task google NW_RULE_NAME=google_ips NW_RULE_DB=my_db
task local  NW_RULE_NAME=dev_local NW_RULE_DB=my_db

task policy -- --name ci_policy --rules "DB.NETWORKS.RULE1"
task list-rules NW_RULE_DB=my_db
task list-policies
task update-rule NW_RULE_NAME=my_rule NW_RULE_DB=my_db
task delete-rule NW_RULE_NAME=old_rule NW_RULE_DB=my_db
task delete-policy -- --name old_policy
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `rule create` | Create a network rule with presets and/or custom values |
| `rule update` | Replace values in an existing network rule |
| `rule delete` | Delete a network rule |
| `rule list` | List network rules in a schema |
| `policy create` | Create a network policy with specified rules |
| `policy alter` | Add rules to an existing network policy |
| `policy delete` | Delete a network policy |
| `policy list` | List all network policies |
| `policy assign` | Assign a network policy to a user |

## Supported Rule Modes and Types

| Mode | Valid Types |
|------|------------|
| `ingress` | `ipv4`, `awsvpceid` |
| `egress` | `ipv4`, `host_port` |
| `internal_stage` | `ipv4`, `awsvpceid` |
| `postgres_ingress` | `ipv4`, `awsvpceid` |
| `postgres_egress` | `ipv4`, `host_port` |

## IPv4 Presets

| Flag | Source |
|------|--------|
| `--allow-local` (default ON) | Your current public IP via [ipify.org](https://api.ipify.org) |
| `--allow-gh` | GitHub Actions runner IPs via [GitHub meta API](https://api.github.com/meta) |
| `--allow-google` | Google IP ranges via [gstatic.com](https://www.gstatic.com/ipranges/goog.json) |
| `--values` | Custom comma-separated CIDRs or host:port values |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NW_RULE_NAME` | Network rule name |
| `NW_RULE_DB` | Database for network rules |
| `NW_RULE_SCHEMA` | Schema for network rules (default: `NETWORKS`) |

## Related

- [sf-utils-skills](https://github.com/Snowflake-Labs/sf-utils-skills) — Cortex Code skill `sf-utils-networks` (after repo rename from `snow-utils-skills`)

## License

Apache 2.0
