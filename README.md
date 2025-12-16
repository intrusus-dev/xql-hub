# XQL Hub

**The open community library for Palo Alto Networks Cortex XQL content.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Beta](https://img.shields.io/badge/Status-Beta-blue)]()
[![CI](https://github.com/intrusus-dev/xql-hub/actions/workflows/ci.yml/badge.svg)](https://github.com/intrusus-dev/xql-hub/actions/workflows/ci.yml)

## About the Project

**XQL Hub** is a community-driven repository designed to share high-quality detection and hunting content for the Palo Alto Networks **Cortex** platform. 

This project features an interactive MITRE ATT&CK matrix for intuitive navigation, allowing security professionals to discover content mapped to the kill chain phases they care about most.

## Features

- **Interactive MITRE ATT&CK Matrix** - Browse queries by tactic and technique with visual filtering
- **Multiple Content Types** - Support for hunting queries, BIOC rules, correlation rules, IT hygiene queries, and dashboard widgets
- **Contribution Wizard** - Step-by-step guide for submitting new content with validation
- **Import Support** - Import existing BIOC and correlation rule exports directly from Cortex XSIAM/XDR
- **Dynamic Filtering** - Filter by content type, log source, and MITRE techniques
- **Automated Validation** - GitHub Actions workflows validate all contributions

## Content Types

| Type | Description | Dataset Requirements |
|------|-------------|---------------------|
| **Threat Hunting** | Proactive XQL queries for manual threat hunting | Any XQL dataset |
| **BIOC Rules** | Behavioral Indicators of Compromise for real-time detection | `xdr_data` or `cloud_audit_log` only |
| **Correlation Rules** | Scheduled rules for complex pattern detection | Any XQL dataset |
| **IT Hygiene** | Security posture and compliance queries | Any XQL dataset |
| **Dashboard Widgets** | XQL queries with visualization for dashboards | Any XQL dataset |

## Query Schema

Each query is defined in a YAML file with the following structure:

```yaml
name: "Query Name"
author: "your-handle"
created: "2025-01-15"
description: "What this query detects and why it's useful"
severity: "Low|Medium|High|Critical"  # Required for BIOC and Correlation
content_type: hunting|bioc|correlation|hygiene|widget
mitre_ids:
  - "T1059.001"
  - "T1078"
log_sources:
  - "Cortex XDR Agent"
  - "Windows Event Logs"
tags:
  - "PowerShell"
  - "Execution"
query: |
  dataset = xdr_data 
  | filter event_type = PROCESS
  | filter action_process_image_name ~= "powershell"
  | fields _time, agent_hostname, action_process_command_line
```

### BIOC-Specific Fields

BIOC rules support additional fields:

```yaml
content_type: bioc
bioc_category: "execution|persistence|credential_access|..."
event_type: "PROCESS|FILE|NETWORK|REGISTRY|..."
```

**BIOC Constraints:**
- Must use `xdr_data` or `cloud_audit_log` dataset
- Must filter on `event_type`
- Maximum 3 MITRE techniques
- Cannot use aggregations

### Correlation-Specific Fields

Correlation rules support scheduling options:

```yaml
content_type: correlation
schedule: "10m|20m|30m|1h|1d"
query_timeframe: "15m|30m|1h|4h|12h|24h|7d"
alert_name: "Alert name with $dynamic_fields"
```

## Project Structure

```
xql-hub/
├── main.py                 # FastAPI application
├── requirements.txt        # Python dependencies
├── queries/                # Query YAML files
│   ├── ad_privileged_groups_add.yaml
│   ├── lsass_access.yaml
│   ├── powershell_suspicious.yaml
│   └── rdp_connections.yaml
├── static/
│   ├── style.css          # Main stylesheet
│   ├── wizard.css         # Contribution wizard styles
│   └── mitre_data.json    # MITRE ATT&CK technique mappings
├── templates/
│   ├── index.html         # Main application page
│   ├── wizard.html        # Contribution wizard
│   └── partials/
│       └── query_cards.html
├── tools/
│   └── update_mitre.py    # Script to update MITRE data
└── .github/
    ├── workflows/         # CI/CD automation
    ├── ISSUE_TEMPLATE/    # Issue templates for contributions
    └── CODEOWNERS
```

## Getting Started

For us, the most important thing is that you enjoy using it. We're looking to provide XQL Hub to every possible user of 
the Cortex platform, no matter if you're a customer, partner, security analyst, or engineer. PANW employees are very 
welcome to contribute, as well.

Right now we're looking the most for query contributions. If you have a good query that you think would be useful to 
others, please check out the [Contribution Guide](#how-to-contribute) below.

## How to Contribute

### Option 1: Use the Contribution Wizard (Recommended)

1. Navigate to the [Contribution Wizard](https://xql-hub.com/contribute)
2. Select your content type
3. Fill in the required fields
4. Enter your XQL query and map MITRE techniques
5. Review and submit

The wizard supports:
- Creating queries from scratch
- Importing existing BIOC exports (`.bioc` files)
- Importing correlation rule exports (`.json` files)

### Option 2: Submit via Pull Request

1. Fork the repository
2. Create a new YAML file in the `queries/` directory
3. Follow the [query schema](#query-schema)
4. Submit a Pull Request

### Option 3: Create a GitHub Issue

Use our [contribution issue template](https://github.com/intrusus-dev/xql-hub/issues/new?template=contribution.yml) to submit your query for review.

### Validation

All contributions are automatically validated:

- **Required fields** - name, author, description, content_type, query
- **Content type validation** - Must be one of: `bioc`, `correlation`, `hunting`, `hygiene`, `widget`
- **BIOC constraints** - Dataset and event_type requirements
- **MITRE ID format** - Must match pattern `T####` or `T####.###`
- **Duplicate detection** - Checks for duplicate names and queries

## Roadmap

- [x] **Phase 1** - XQL Query Library with MITRE ATT&CK mapping
- [x] **Phase 2** - Contribution wizard with import support
- [ ] **Phase 3** - XSOAR Playbook support
- [ ] **Phase 4** - Custom parsers and dashboards
- [ ] **Phase 5** - Automated query validation against live environments

## Tech Stack

- **Backend**: Python, FastAPI
- **Frontend**: HTML, CSS, JavaScript, HTMX
- **Data**: YAML, JSON
- **CI/CD**: GitHub Actions

## Security

Please see [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

When contributing queries, ensure:
- No hardcoded credentials or API keys
- No internal IP addresses or hostnames
- No customer-specific data
- No proprietary detection logic that shouldn't be public

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

XQL Hub is an independent community project and is **not affiliated with, endorsed by, or sponsored by Palo Alto Networks**. All content is provided "as is" without warranty. Always test queries in a non-production environment first.

## Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) for the framework
- The Cortex XSIAM/XDR community for inspiration and contributions
- All contributors who share their detection content

---

**Questions?** Open a [Discussion](https://github.com/intrusus-dev/xql-hub/discussions) or check existing [Issues](https://github.com/intrusus-dev/xql-hub/issues).