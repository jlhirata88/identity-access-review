import csv
import tempfile
import unittest
from datetime import date
from pathlib import Path
from analyzer import audit, load_accounts, write_reports

ROOT = Path(__file__).resolve().parents[1]
AS_OF = date(2026, 11, 2)


class AuditTests(unittest.TestCase):
    def test_expected_findings(self):
        results = audit(load_accounts(ROOT / 'data/sample_accounts.csv'), AS_OF)
        self.assertEqual([(x['user'], x['rule']) for x in results], [
            ('mike.brown', 'INACTIVE_IDENTITY'), ('mike.brown', 'STALE_ACCESS_KEY'),
            ('sarah.jones', 'MFA_DISABLED'), ('sarah.jones', 'UNAPPROVED_ADMIN'),
            ('service.legacy', 'STALE_ACCESS_KEY')])

    def test_clean_sample(self):
        self.assertEqual(audit(load_accounts(ROOT / 'data/clean_accounts.csv'), AS_OF), [])

    def test_disabled_account_not_flagged(self):
        results = audit(load_accounts(ROOT / 'data/sample_accounts.csv'), AS_OF)
        self.assertFalse(any(x['user'] == 'former.employee' for x in results))

    def test_threshold(self):
        results = audit(load_accounts(ROOT / 'data/sample_accounts.csv'), AS_OF, 365)
        self.assertFalse(any(x['rule'] == 'INACTIVE_IDENTITY' for x in results))

    def test_report_outputs(self):
        findings = audit(load_accounts(ROOT / 'data/sample_accounts.csv'), AS_OF)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            write_reports(findings, output, AS_OF, 6)
            self.assertTrue((output / 'summary.txt').exists())
            self.assertTrue((output / 'findings.json').exists())
            with (output / 'findings.csv').open(newline='') as handle:
                self.assertEqual(len(list(csv.DictReader(handle))), 5)

    def test_invalid_bool(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'bad.csv'
            p.write_text((ROOT / 'data/clean_accounts.csv').read_text().replace('true', 'maybe', 1))
            with self.assertRaises(ValueError):
                load_accounts(p)

    def test_duplicate_user(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'bad.csv'
            content = (ROOT / 'data/clean_accounts.csv').read_text()
            p.write_text(content + content.splitlines()[1] + '\n')
            with self.assertRaises(ValueError):
                load_accounts(p)


if __name__ == '__main__':
    unittest.main()
