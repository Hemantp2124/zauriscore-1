# ZauriScore(TM) - AI-Powered Smart Contract Vulnerability Analyzer

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 1. Project Overview

**ZauriScore(TM)** is an AI-powered security analysis platform for Ethereum smart contracts.
It combines **static analysis, heuristic rules, and ML/AI insights** to deliver:

- **Trustable risk scores**
- **Audit-ready provenance**
- **Clear remediation steps**
- **Fast, actionable decision-making**

**Core Motive:**
Enable developers, auditors, and founders to make **deployment-safe decisions** with explainable, reproducible, and shareable reports under time pressure.

---

## 2. Unique Selling Proposition (USP) & Features

**USP:**
Deliver **trustable, audit-ready risk decisions** with **provenance, explainability, and repeatable outcomes**, not just raw analysis.

**Key Features:**
- Multi-layered security analysis: **Slither, heuristics, ML risk scoring**
- AI-powered insights using **CodeBERT** and vulnerability pattern learning
- Proxy resolution & implementation verification
- Comprehensive reporting: JSON, Markdown, and PDF
- Provenance metadata: solc version, Slither version, Etherscan source, response hash
- Go/No-Go decision summaries with top reasons
- Exportable, shareable, and versioned reports
- Optional ML augmentation with confidence thresholds

---

## 3. Use Cases

1. **Security Engineer:** Quickly decide if a contract is **deployment-safe** with explainable evidence.
2. **Auditor:** Reproduce findings, verify environment (solc, detector versions), and export audit-ready artifacts.
3. **PM / Founder:** Compare contract risk against baseline and share progress with stakeholders.
4. **DevOps / Security Team:** Track contract risks over time and integrate into CI/CD workflows.
5. **Enterprise Compliance:** Generate reports aligned with SOC2/ISO or internal policy enforcement.

---

## 4. Revenue Model

| Model | Description | Target |
|-------|-------------|--------|
| **Freemium** | Limited contract scans with essential metrics | Individual developers, small teams |
| **Pro Tier** | Full access: multi-chain, ML insights, exportable reports, versioned artifacts | Startups, mid-size teams |
| **Enterprise SaaS** | Team dashboards, RBAC, compliance-ready reports, policy-as-code | Large organizations, auditors |
| **Consulting / Audits** | Custom contract analysis, ML-assisted triage | High-value contracts, enterprises |

---

## 5. Scope of Work (SOW)

### Must-Haves
- Proxy/implementation resolution
- Deterministic static analysis with triage
- Provenance & reproducibility metadata in reports
- Opinionated **Go/No-Go** decisions with reasons

### Nice-to-Haves
- ML augmentation behind confidence thresholds
- Multi-chain support via chainid
- Sharable report links (API / S3 / presigned URLs)

### Deliverables
- CLI and Web UI for contract analysis
- JSON, Markdown, PDF export of reports
- API endpoints for programmatic access
- Audit-ready artifacts with full provenance
- ML/Heuristic risk scoring with explainable insights

---

## 6. Current Implementation Status

### Currently Implemented
- **Core Analysis Engine**: Multi-layered security analysis with Slither integration
- **ML-Powered Risk Scoring**: CodeBERT-based vulnerability pattern detection
- **Blockchain Integration**: Etherscan API for contract source fetching
- **CLI & API Interfaces**: Both command-line and REST API access
- **OpenZeppelin Support**: Full compatibility with OpenZeppelin contracts
- **Report Generation**: JSON and Markdown format reports
- **Real-time Analysis**: Sub-60 second contract analysis

### In Development
- **Enhanced Reporting**: PDF export and advanced formatting
- **Multi-chain Support**: Expansion beyond Ethereum
- **Windows Compatibility**: Full Slither and Mythril support
- **Enterprise Features**: Team dashboards and RBAC

### Key Metrics Achieved
- **Analysis Speed**: ~15 seconds per contract
- **Risk Score Range**: 0.0-10.0 with ML confidence scoring
- **Contract Support**: Full Solidity compatibility
- **API Reliability**: 95%+ successful analysis rate

---

## 7. Technical Architecture

### Core Components
- **Analysis Engine:** Multi-layered static + ML analysis
- **ML Pipeline:** CodeBERT fine-tuning for vulnerability detection
- **Blockchain Integration:** Etherscan API with proxy resolution
- **Reporting Engine:** Multi-format export with provenance metadata
- **Web Interface:** FastAPI-based REST API and CLI

### Technology Stack
- **Backend:** Python 3.8+, FastAPI, SQLAlchemy
- **ML/AI:** PyTorch, Transformers (CodeBERT), scikit-learn
- **Blockchain:** Web3.py, eth-brownie
- **Security Tools:** Slither, Mythril (with Windows compatibility)
- **Database:** PostgreSQL with Redis caching
- **Deployment:** Docker, Kubernetes-ready

---

## 8. Success Metrics

- **Time-to-signal:** < 90s per contract
- **Trust signals:** Solc version, detector versions, verification proof
- **Actionability:** Each flagged issue has remediation steps or references
- **Reproducibility:** 100% reproducible given address + chain + timestamp

---

## 9. License & Acknowledgements

- Licensed under **MIT License**
- Acknowledgements:
  - [Slither](https://github.com/crytic/slither) - Static analysis
  - [CodeBERT](https://github.com/microsoft/CodeBERT) - ML integration
  - Ethereum Smart Contract Security Community
