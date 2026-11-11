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

## Problem statement

Cloud security teams drown in scanner output. A small or mid-size company's
analyst can face hundreds of AWS findings a week with no time to triage all
of them, map each to a control framework, or write a correct fix by hand.
This project builds a local AI agent that does that triage: it reads
findings, detects misconfigurations, explains the risk in plain language
with the right compliance and threat-model context, and drafts a fix a
human can review and approve. Nothing in this repo executes a fix or calls
a real AWS API — it recommends only, and a human approves every sensitive
change.

## Architecture

```
Upload (JSON/YAML/CSV)
      |
      v
   Gradio UI
      |
      v
Parser / Normaliser  --->  Finding (validated, Pydantic)
      |
      v
   Agent loop (Ollama tool-calling, Qwen2.5 7B)
      |
      +--> check_misconfig(finding)   -- deterministic rule engine, sets type + severity
      +--> lookup_controls(type, resource) -- RAG over CIS/FSBP/MITRE (Chroma)
      +--> get_fix_template(type)     -- vetted remediation library
      |
      v
   AgentOutput (validated, Pydantic)
      |
      v
   Approval gate (human-in-the-loop, required for High/Critical/IAM fixes)
      |
      v
Export (fix script + audit log) + monitoring
```

**Hard rule:** only `check_misconfig` sets the misconfiguration type and
severity. The LLM explains and drafts remediation text, but it never
overrides a rule-engine verdict — this keeps every security judgment
deterministic and auditable instead of resting on model output.

## Misconfiguration types detected

| ID | Misconfiguration | Resource | Severity | Approval required | AWS FSBP | CIS | MITRE ATT&CK |
|---|---|---|---|---|---|---|---|
| M01 | S3 bucket publicly readable | S3 | High | Yes | S3.1, S3.2, S3.8 | 2.1.x | T1530 |
| M02 | S3 default encryption missing | S3 | Medium | No | S3 encryption | 2.1.x | T1530 |
| M03 | SSH (22) or RDP (3389) open to the internet | EC2 Security Group | High | Yes | EC2.13, EC2.53 | 5.2, 5.3 | T1133, T1110 |
| M04 | IAM policy with `Action: *` and `Resource: *` | IAM | Critical | Yes | IAM.1 | 1.16 | T1078.004, T1098 |
| M05 | Root account without MFA | IAM | Critical | Yes | IAM.9 | 1.5 | T1078.004, T1110 |
| M06 | Active access key older than 90 days | IAM | Medium | Yes (IAM) | IAM.3 | 1.14 | T1078.004, T1552 |
| M07 | CloudTrail missing, stopped, or single-region | CloudTrail | High | Yes | CloudTrail.1 | 3.1 | T1562.008 |
| M08 | RDS instance publicly accessible | RDS | High | Yes | RDS.2 | 2.3.x | T1190, T1110 |
| M09 | RDS storage not encrypted | RDS | Medium | No | RDS.3 | 2.3.1 | T1537 |
| M10 | EBS volume not encrypted | EBS | Medium | No | EC2.7 | 2.2.1 | T1537 |

A finding that matches none of the above is labelled `COMPLIANT`; one the
rule engine can't confidently assess (missing or malformed fields) is
flagged `NEEDS_REVIEW` rather than guessed at.

## Safety and human-in-the-loop design

- **Recommend only.** Nothing in this repo executes a fix or calls a real AWS API — exported fixes are text scripts for a human to run.
- **Human approval required** for every High, Critical, and IAM-related fix (M01, M03-M08). The agent has no permission to approve its own output.
- **Synthetic data only.** No real AWS accounts, credentials, or scanning — see [data/DATA_CARD.md](data/DATA_CARD.md).
- **Untrusted findings.** Finding tags/names are treated as untrusted data; the rule engine never reads them, so a misleading bucket name or prompt-injection text in a tag cannot change a verdict.

## Tech stack

| Layer | Choice |
|---|---|
| Language | Python 3.11 |
| UI | Gradio (Blocks) |
| LLM | Qwen2.5 7B via Ollama (primary); Llama 3.1 8B for comparison |
| Agent | Plain Python loop with Ollama tool calling |
| Embeddings | Sentence Transformers (BGE-small) |
| Vector store | Chroma |
| Validation | Pydantic v2 |
| Storage | SQLite (approvals, audit log); JSON-lines logs |
| Testing | pytest, GitHub Actions, Bandit |
| Packaging | Docker Compose |

## Repository structure

```
app/
  main.py          # Gradio entry point
  schemas/         # Pydantic models: Finding, AgentOutput (shared contract)
  parser/          # JSON / YAML / CSV -> Finding
  tools/           # check_misconfig (rules), lookup_controls, get_fix_template
  agent/           # Ollama tool-calling loop, prompts
  approval/        # approval queue, SQLite, audit log
  ui/              # Gradio tabs
  monitoring/      # JSON-lines logging, metrics
data/
  generator.py         # seeded synthetic finding generator
  terraform_samples/   # misconfigured .tf files, scanned with Trivy
  findings/             # generated findings (JSON/YAML/CSV)
  DATA_CARD.md          # dataset documentation
kb/
  controls.md      # CIS / FSBP / MITRE control reference
  ingest.py        # chunk, embed, load into Chroma
eval/
  metrics.py, ablation.py, test_cases/, rubric.csv, results/
tests/             # pytest suite
```

## Evaluation targets

Detection F1 >= 0.90, control mapping >= 90%, MITRE mapping >= 90%, tool
selection >= 95%, hallucination <= 5%, explanation rubric average >= 4/5,
100% of sensitive fixes routed to approval, 100% of adversarial cases
handled correctly, < 30s per finding, and 8/8 demo cases passing. We also
compare an ablation (rules only vs. LLM only vs. full system) and the two
candidate models (Qwen2.5 vs. Llama 3.1).

Run `python eval/run_eval.py` to score the full system against the dataset
(mock demo mode by default, so it needs no live Ollama) and write a report
to `eval/results/`. Latest run, against all 146 clean synthetic findings:

| Target | Result | Threshold |
|---|---|---|
| Detection F1 | 100% | >= 90% |
| Control mapping accuracy | 100% | >= 90% |
| MITRE mapping accuracy | 100% | >= 90% |
| Tool selection accuracy | 100% | >= 95% |
| Verdict integrity (hallucination stand-in*) | 100% | >= 95% |
| Approval routing compliance | 100% | 100% |
| Adversarial case pass rate | 100% | 100% |
| Under 30s per finding | 100% | 100% |

\* True hallucination detection needs an LLM judge, which is out of scope;
this instead verifies hard rule 1 (the LLM can never override the rule
engine's verdict) holds for every run -- see `eval/metrics.py`.

`python -c "from eval.ablation import ablation_study; ..."` (see
`eval/ablation.py`) compares rules-only detection against the full
pipeline; `eval/ablation.py` also has a `compare_models` hook for Qwen2.5
vs. Llama 3.1 once both are pulled in a live Ollama.

## Current status

- [x] Pydantic schemas for `Finding` and `AgentOutput`
- [x] Seeded synthetic dataset (151 findings, all 10 types + hard cases)
- [x] `check_misconfig` rule engine, validated against the full dataset
- [x] Parser (JSON/YAML/CSV -> `Finding`)
- [x] Knowledge base + `lookup_controls` retrieval
- [x] `get_fix_template` remediation library
- [x] Agent loop (Ollama tool calling)
- [x] Gradio UI + approval queue + export
- [x] Evaluation scripts, ablation, adversarial tests
- [ ] Docker Compose, monitoring, screenshots

For the complete governing specification used to build this project
(hard rules, schemas, exact build order), see [CLAUDE.md](CLAUDE.md).

## Getting started

```bash
pip install -r requirements.txt
ollama pull qwen2.5:7b
python data/generator.py          # generate synthetic findings
python kb/ingest.py               # build the Chroma index
pytest                            # run the test suite
python eval/run_eval.py           # score the full system against the dataset
python app/main.py                # start the Gradio app
docker compose up                 # full stack via Docker Compose
```
