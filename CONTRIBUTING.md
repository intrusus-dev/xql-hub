# Contributing to XQL Hub

Thank you for your interest in contributing to XQL Hub! 🎉

## Ways to Contribute

### 1. Submit a Query (Easiest)

Use our [Contribution Wizard](https://xql-hub.com/contribute) to submit queries. The wizard will:
- Guide you through the process
- Validate your query
- Generate proper YAML format
- Create a GitHub issue automatically

### 2. Report Issues

Found a bug or have a suggestion? [Open an issue](https://github.com/intrusus-dev/xql-hub/issues/new/choose).

### 3. Improve Documentation

Documentation improvements are always welcome! Submit a PR with your changes.

### 4. Code Contributions

For code contributions:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests locally
5. Submit a Pull Request

## Query Schema
```yaml
name: "Query Name"                    # Required
author: "your-name"                   # Required
created: "2024-01-15"                 # Auto-added if missing
description: "What this detects"      # Required
content_type: hunting                 # Required: hunting|bioc|correlation|hygiene|widget
severity: "Medium"                    # Required for bioc/correlation
mitre_ids:                            # Recommended
  - "T1059.001"
log_sources:                          # Required
  - "Cortex XDR Agent"
tags:                                 # Optional
  - "PowerShell"
query: |                              # Required
  dataset = xdr_data
  | filter ...
```

## Content Type Guidelines

| Type | Dataset | Use Case |
|------|---------|----------|
| `hunting` | Any | Manual threat hunting |
| `bioc` | xdr_data, cloud_audit_log | Real-time behavioral detection |
| `correlation` | Any | Scheduled alerting rules |
| `hygiene` | Any | Security posture assessment |
| `widget` | Any | Dashboard visualizations |

## Code Style

- Python: Follow PEP 8
- YAML: 2-space indentation
- Keep queries readable and well-commented

## Review Process

1. Submit contribution via wizard or PR
2. Automated validation runs
3. Maintainer reviews
4. Feedback/approval
5. Merge to main

## Questions?

- Open a [Discussion](https://github.com/intrusus-dev/xql-hub/discussions)
- Check existing [Issues](https://github.com/intrusus-dev/xql-hub/issues)