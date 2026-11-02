"""Offline IAM identity-access review for synthetic CSV account data."""
import argparse
import csv
import json
from datetime import date
from pathlib import Path

FIELDS = ('user', 'account_status', 'mfa_active', 'last_console_login', 'access_key_active', 'access_key_last_used', 'policy', 'role', 'approved_admin')


def parse_date(value):
    if not value.strip():
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError as exc:
        raise ValueError(f'Invalid ISO date: {value!r}') from exc


def parse_bool(value, field):
    value = value.strip().lower()
    if value not in ('true', 'false'):
        raise ValueError(f'{field} must be true or false')
    return value == 'true'


def load_accounts(path):
    with path.open(newline='', encoding='utf-8-sig') as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or any(field not in reader.fieldnames for field in FIELDS):
            raise ValueError('CSV missing required columns: ' + ', '.join(FIELDS))
        accounts = []
        seen = set()
        for line, row in enumerate(reader, 2):
            if not row or not any((v or '').strip() for v in row.values() if isinstance(v, str)):
                continue
            if None in row:
                raise ValueError(f'Line {line}: unexpected extra columns')
            user = (row['user'] or '').strip()
            if not user or user in seen:
                raise ValueError(f'Line {line}: missing or duplicate user')
            seen.add(user)
            if row['account_status'].strip().lower() not in ('active', 'disabled'):
                raise ValueError(f'Line {line}: account_status must be active or disabled')
            account = {field: (row[field] or '').strip() for field in FIELDS}
            account['mfa_active'] = parse_bool(account['mfa_active'], 'mfa_active')
            account['access_key_active'] = parse_bool(account['access_key_active'], 'access_key_active')
            account['approved_admin'] = parse_bool(account['approved_admin'], 'approved_admin')
            account['last_console_login'] = parse_date(account['last_console_login'])
            account['access_key_last_used'] = parse_date(account['access_key_last_used'])
            accounts.append(account)
    return accounts


def audit(accounts, as_of, inactivity_days=90):
    findings = []

    def add(user, rule, severity, evidence, recommendation):
        findings.append({'user': user, 'rule': rule, 'severity': severity,
                         'evidence': evidence, 'recommendation': recommendation})

    for account in accounts:
        if account['account_status'].lower() != 'active':
            continue
        user = account['user']
        if not account['mfa_active']:
            add(user, 'MFA_DISABLED', 'High', 'MFA marked inactive in simulated account inventory',
                'Confirm authentication requirements and enable appropriate MFA controls.')
        if account['policy'] == 'AdministratorAccess' and not account['approved_admin']:
            add(user, 'UNAPPROVED_ADMIN', 'High', 'AdministratorAccess assigned without recorded approval',
                'Validate business need and approval; reduce privileges if not required.')
        login = account['last_console_login']
        key = account['access_key_last_used'] if account['access_key_active'] else None
        dates = [d for d in (login, key) if d is not None]
        if dates and all((as_of - d).days > inactivity_days for d in dates):
            add(user, 'INACTIVE_IDENTITY', 'Medium', f'No recorded console or active-key use within {inactivity_days} days',
                'Confirm all access methods and account ownership before disabling access.')
        if account['access_key_active'] and (key is None or (as_of - key).days > inactivity_days):
            add(user, 'STALE_ACCESS_KEY', 'Medium',
                'Active key has no recorded use' if key is None else f'Active key last used {key.isoformat()}',
                'Verify key usage and retire unnecessary keys after coordination.')
    return sorted(findings, key=lambda f: (f['user'], f['rule']))


def write_reports(findings, output, as_of, account_count):
    output.mkdir(parents=True, exist_ok=True)
    (output / 'findings.json').write_text(json.dumps({'as_of': as_of.isoformat(), 'accounts_reviewed': account_count,
                                                      'findings': findings}, indent=2) + '\n', encoding='utf-8')
    with (output / 'findings.csv').open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=('user', 'rule', 'severity', 'evidence', 'recommendation'))
        writer.writeheader()
        for finding in findings:
            writer.writerow({k: "'" + str(v) if str(v).startswith(('=', '+', '-', '@', '\t', '\r')) else v
                             for k, v in finding.items()})
    summary = [f'Identity Access Review | as of {as_of.isoformat()}',
               f'Accounts reviewed: {account_count}', f'Findings: {len(findings)}', '']
    for finding in findings:
        summary += [f"[{finding['severity']}] {finding['user']} — {finding['rule']}",
                    f"  Evidence: {finding['evidence']}",
                    f"  Recommendation: {finding['recommendation']}", '']
    if not findings:
        summary.append('No findings under the configured rules. This is not proof of a secure environment.')
    (output / 'summary.txt').write_text('\n'.join(summary).rstrip() + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Audit simulated IAM account inventory (offline).')
    parser.add_argument('input', type=Path, help='CSV file containing synthetic IAM account inventory')
    parser.add_argument('--output', type=Path, default=Path('reports'))
    parser.add_argument('--as-of', type=date.fromisoformat, default=date.today(), help='YYYY-MM-DD; use fixed date for reproducibility')
    parser.add_argument('--inactive-days', type=int, default=90)
    args = parser.parse_args()
    if args.inactive_days < 1:
        parser.error('--inactive-days must be positive')
    try:
        accounts = load_accounts(args.input)
        findings = audit(accounts, args.as_of, args.inactive_days)
        write_reports(findings, args.output, args.as_of, len(accounts))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(f'Reviewed {len(accounts)} accounts; generated {len(findings)} findings in {args.output}')


if __name__ == '__main__':
    main()
