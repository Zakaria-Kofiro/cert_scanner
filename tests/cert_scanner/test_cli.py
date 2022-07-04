import unittest
from click.testing import CliRunner
from cert_scanner import scanner

class TestScanner(unittest.TestCase):
    def test_scanner_default_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, [""])
        output = result.output.split('\n')[0]
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(output, 'Usage: cert-scanner [OPTIONS]')

    def test_scanner_help_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["--help"])
        output = result.output.split('\n')[0]
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(output, 'Usage: cert-scanner [OPTIONS]')

    def test_scanner_error_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["error"])
        output = result.output.split('\n')[0]
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(output, 'Usage: cert-scanner [OPTIONS]')

    def test_scanner_error_char_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["-e"])
        output = result.output.split('\n')[0]
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(output, 'Usage: cert-scanner [OPTIONS]')

    def test_scanner_empty_hostname_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["-h"])
        output = result.output.split('\n')[0]
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(output, "Error: Option '-h' requires an argument.")

    def test_scanner_hostname_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["-h",  "www.testdomain.com"])
        output = result.output.split('\n')[0]
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(output, 'cert_scanner: Python Based SSL/TLS scanner')

    def test_scanner_invalid_hostname_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["-h",  "www.thisdoesnotexist5542.com"])
        output = result.output.split('\n')[0]
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(output, "error: hostname not provided or not known")

    def test_scanner_empty_cert_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["-c"])
        output = result.output.split('\n')[0]
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(output, "Error: Option '-c' requires an argument.")

    def test_scanner_cert_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["-c",  "CA:AD:1A:BE:52:EF:44:4A:31:07:06:FC:17:26:48:E4:53:70:6D:ED"]) # SHA1 from facebook.com
        output = result.output.split('\n')[0]
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(output, "cert_scanner: Python Based SSL/TLS scanner")

    def test_scanner_invalid_cert_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["-h",  "invalid_id"])
        output = result.output.split('\n')[0]
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(output,"error: hostname not provided or not known")