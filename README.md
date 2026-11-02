# AWS Cloud Misconfiguration Remediation Agent

A local AI agent that reads scanner-style AWS findings, detects 10 common
cloud misconfigurations, maps each to CIS / AWS Foundational Security Best
Practices controls and MITRE ATT&CK techniques, explains the risk in plain
language, and drafts a remediation fix. Sensitive fixes require human
approval before they can be exported. Presented through a Gradio interface.

Capstone project for **Applied AI Agents for Cybersecurity Operations**,
Laurentian University, Fall 2026.

**Group:** Group 5A

**Supervisor:** Farhad Abbasi Amiri

**Authors:**

- Amarish Singh Sajwan
- Jaya Sapkota
- Laura Galvis
- Stanley Stephen Wakdok
- Oluwagbadura Ojo

## Team roles

| Member | Role | Owns | Rubric area |
|---|---|---|---|
| Amarish Singh Sajwan | Core Development & Agent Architecture | Schemas, rule engine, parser, agent loop integration, repo/CI | Agent architecture (20%) |
| Jaya Sapkota | Data Pipeline & Evaluation Lead | `data/generator.py`, `DATA_CARD.md`, Terraform/Trivy samples, `eval/` (metrics, ablation, adversarial tests, rubric scoring) | Data pipeline (15%), Evaluation (15%) |
| Laura Galvis | Cybersecurity Knowledge Base Lead | `kb/controls.md` (CIS/FSBP/MITRE mapping verification), `kb/ingest.py`, `app/tools/retrieval.py`, `app/tools/fix_templates.py` | Cybersecurity correctness (15%) |
| Stanley Stephen Wakdok | Agent Loop & UI Lead | `app/agent/` (Ollama tool-calling loop, prompts, trace logging), Gradio tabs, approval queue/SQLite | Agent architecture (20%, shared), Human-in-the-loop/ethics (10%) |
| Oluwagbadura Ojo | Deployment, Docs & Presentation Lead | Docker Compose, monitoring tab/logging, screenshots, SDLC-stage docs, final report/slide deck | Deployment/demo (10%), Report/presentation (5%), Problem definition (10%) |

## Project scope

See [CLAUDE.md](CLAUDE.md) for the full project specification: the 10
misconfiguration types, architecture, schemas, and hard rules (rules-engine
verdicts, human approval gates, no real AWS access, synthetic data only).
See [data/DATA_CARD.md](data/DATA_CARD.md) for the synthetic dataset used to
develop and evaluate the agent.

## Getting started

```bash
pip install -r requirements.txt
ollama pull qwen2.5:7b
python data/generator.py          # generate synthetic findings
python kb/ingest.py               # build the Chroma index
pytest                            # run the test suite
python app/main.py                # start the Gradio app
docker compose up                 # full stack via Docker Compose
```
