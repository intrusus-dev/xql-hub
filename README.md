# XSIAM Hub

**The open community library for Palo Alto Networks Cortex content.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Beta](https://img.shields.io/badge/Status-Beta-blue)]()

## 🚀 About the Project
**XSIAM Hub** is a community-driven repository designed to share high-quality content for Palo Alto Networks **Cortex XSIAM** and **Cortex XDR**.

While the Cortex platform provides powerful capabilities out of the box, the real power comes from the community. This hub aims to be the central place where security engineers, hunters, and analysts can share what works for them.

## 🎯 Current Focus: XQL Queries
We are currently in **Phase 1**, focusing exclusively on building a robust library of **XQL (Cortex Query Language)** queries for hunting and detection.

**What you can find here:**
* **Hunting Queries:** Proactive searches for threat behaviors.
* **Detection Logic:** High-fidelity queries ready for correlation rules.
* **Reporting:** Queries designed for dashboards and metrics.

## 🔮 Roadmap & Future Vision
We are building towards a comprehensive "GitOps" driven content hub.
* **Phase 1 (Now):** XQL Query Library.
* **Phase 2:** Automation Playbooks (XSOAR/Cortex).
* **Phase 3:** Parsers and Custom Dashboards.
* **Phase 4:** Automatic validation (CI/CD) of submitted content.

## 📁 Query Schema

Each query is defined in a YAML file with the following structure:

```yaml
name: "Query Name"
author: "your-handle"
description: "What this query detects"
severity: "Low|Medium|High|Critical"
content_type: xql|correlation|bioc
category: "Identity & Access|Endpoint Security|Network|..."
mitre_ids:
  - "T1098.007"
  - "T1078"
log_sources:
  - "Microsoft Windows"
  - "Cortex XDR"
tags:
  - "Tag1"
  - "Tag2"
query: |
  dataset = ... 
  | filter ...
```

## 🤝 How to Contribute
We're currently building up the project.
Feel free to contribute after we published it.


## ⚠️ Disclaimer
XSIAM Hub is an independent community project and is not affiliated with, endorsed by, or sponsored by Palo Alto Networks. All content is provided "as is" without warranty. Always test queries on alerts that relate to non-critical assets first.