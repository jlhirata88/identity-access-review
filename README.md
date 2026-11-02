# AWS IAM Identity Access Review (Offline Simulation)

A beginner-friendly Cloud Security Analyst portfolio project. It reviews **synthetic AWS-style identity inventory data** for common account and credential risks, then produces an analyst-friendly report.

## What it checks

| Rule | Trigger | Severity |
| --- | --- | --- |
| `MFA_DISABLED` | Active identity has MFA marked inactive | High |
| `UNAPPROVED_ADMIN` | Active identity has exact `AdministratorAccess` policy name without recorded approval | High |
| `INACTIVE_IDENTITY` | Recorded console and active-key use are both older than the threshold, where activity dates exist | Medium |
| `STALE_ACCESS_KEY` | Active key is unused or has no recorded usage date | Medium |

These are **training heuristics**, not production-grade detections. A real review must consider federated users, IAM Identity Center, roles, service credentials, policy documents, access logs, owner approval, and organization-specific controls. A missing MFA flag in this simulated dataset is not equivalent to proving all authentication paths lack MFA. A disabled account is skipped by these rules, but may still require credential and ownership review.

## Run locally

Requires Python 3.10+; no packages, AWS account, or credentials required.

```bash
python analyzer.py data/sample_accounts.csv --as-of 2026-11-02
```

Review:
- `reports/summary.txt` — readable investigation summary
- `reports/findings.csv` — spreadsheet-friendly findings
- `reports/findings.json` — structured findings

Run a clean baseline:

```bash
python analyzer.py data/clean_accounts.csv --as-of 2026-11-02 --output reports/clean
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Sample results

With the fixed review date **2026-11-02**, the sample contains **6 identities** and generates **5 findings** (2 High, 3 Medium). These are intentionally synthetic, not real company or AWS account records.

## Analyst workflow

1. Obtain approved account and credential inventory data.
2. Review findings, prioritizing potentially excessive access and missing MFA.
3. Validate business need, identity ownership, actual access paths, and recent usage.
4. Document evidence and request authorized remediation; do not automatically delete users or keys.
5. Re-run the review after changes and retain evidence under company policy.

See [Investigation walkthrough](docs/INVESTIGATION.md) for an example triage narrative.

## Scope and limitations

- **Offline simulation only**. It does not connect to AWS, retrieve actual IAM credential reports, monitor live events, or send alerts.
- Input CSV is a **simplified training schema**, not the native AWS IAM credential-report format. A real AWS export requires an explicit adapter and additional fields.
- Exact `AdministratorAccess` name matching does not evaluate custom policies, effective permissions, inherited policies, or permission boundaries.
- Inactivity is based on limited recorded fields; missing login dates alone are not proof of inactivity.
- Generated CSV includes basic spreadsheet formula-injection protection, but report contents are not intended for sensitive production data.

## Project structure

```text
analyzer.py              Python review and reporting tool
data/                    Synthetic account inventories
reports/                 Generated example findings
tests/                   Automated unit tests
docs/                    Investigation walkthrough
```

## Future enhancements

- Parse native AWS IAM credential reports.
- Add IAM Access Analyzer findings as a separate input.
- Model effective permissions and approvals more realistically.
- Add optional CI checks after review and publication.
