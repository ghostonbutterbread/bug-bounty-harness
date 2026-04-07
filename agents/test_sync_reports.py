import unittest
from unittest.mock import patch
from pathlib import Path
from agents.sync_reports import sync_reports_main
from agents.findings_ledger import FindingsLedger

class TestSyncReports(unittest.TestCase):

    @patch('agents.sync_reports._load_markdown_findings')
    @patch('agents.findings_ledger.FindingsLedger.check')
    @patch('agents.findings_ledger.FindingsLedger.add')
    def test_sync_reports_import_new_findings(
            self, mock_add, mock_check, mock_load_markdown):
        # Mock data
        program = 'test_program'
        source_dir = Path('/tmp/reports')
        finding1 = {'type': 'xss', 'description': 'XSS in input'}
        finding2 = {'type': 'sqli', 'description': 'SQLi in query'}
        # Mock ledger behavior (no existing findings)
        mock_check.side_effect = [False, False]  # Finding1 and finding 2 are new
        # Mock load markdown - to return two findings
        mock_load_markdown.return_value = [finding1, finding2]
        # Run the function
        sync_reports_main(program, source_dir=source_dir.as_posix())
        # Assertions - must test all the relevant steps from design.  The mock functions are
        # mocked.
        mock_load_markdown.assert_called_once()
        self.assertEqual(mock_check.call_count, 2, "check should be called for each extracted finding")
        self.assertEqual(mock_add.call_count, 2, "add should be called for each new finding")
    @patch('agents.sync_reports._load_markdown_findings')
    @patch('agents.findings_ledger.FindingsLedger.check')
    @patch('agents.findings_ledger.FindingsLedger.add')
    def test_sync_reports_skip_duplicates(
            self, mock_add, mock_check, mock_load_markdown):
        # Mock data
        program = 'test_program'
        source_dir = Path('/tmp/reports')
        finding1 = {'type': 'xss', 'description': 'XSS in input'}
        finding2 = {'type': 'sqli', 'description': 'SQLi in query'}
        # Mock ledger behavior (finding1 exists, finding2 is new)
        mock_check.side_effect = [(True, 'D01', finding1), (False, None, finding2)]
        # Mock load markdown - this now always returns the two findings as well.
        mock_load_markdown.return_value = [finding1, finding2]
        # Run the function
        sync_reports_main(program, source_dir=source_dir.as_posix())
        # Assertions
        self.assertEqual(mock_add.call_count, 1, "add should be called for each new finding")
        self.assertEqual(mock_check.call_count, 2, "checks for each finding")
    @patch('agents.sync_reports._load_markdown_findings')
    @patch('agents.findings_ledger.FindingsLedger.check')
    @patch('agents.findings_ledger.FindingsLedger.add')
    def test_sync_report_ledger_add(
            self, mock_add, mock_check, mock_load_markdown):
        # Mock data
        program = 'test_program'
        source_dir = Path('/tmp/reports')
        finding1 = {'type': 'xss', 'description': 'XSS in input', 'fid': 'G01'}
        # Mock ledger behavior (finding1 exists, finding2 is new)
        mock_check.return_value = (False, None, finding1)  # finding1 is new
        # Mock load markdown - this now always returns the two findings as well.
        mock_load_markdown.return_value = [finding1]
        # Run the function
        sync_reports_main(program, source_dir=source_dir.as_posix())
        # Assertions
        self.assertEqual(mock_add.call_count, 1, "add should be called") # Add one mock.
        mock_add.assert_called_once()

if __name__ == '__main__':
    unittest.main()
