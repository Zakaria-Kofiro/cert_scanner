import unittest
from click.testing import CliRunner
from cert_scanner import scanner

class TestCli(unittest.TestCase):
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

    def test_scanner_valid_hostname_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["-h",  "www.testdomain.com"])
        output = result.output.split('\n')[4]
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(output, "crt.sh status:\t Certificate Found")

    def test_scanner_valid_hostname_no_cert_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["-h",  "www.expired.badssl.com"])
        output = result.output.split('\n')[4]
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(output,"crt.sh status:\t Certificate not found")

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
        result = runner.invoke(scanner.cert_scanner, ["-c",  "08:04:07:55:C8:B6:85:2A:5D:B9:45:A2:B3:80:57:11:11:DE:FD:2D"]) # SHA1 from amazon.com
        output = result.output.split('\n')[4]
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(output, "crt.sh status:\t Certificate Found")

    def test_scanner_invalid_cert_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["-c",  "ae3431341"])
        output = result.output.split('\n')[4]
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(output,"crt.sh status:\t Certificate not found")
    
    def test_scanner_both_cert_option(self):
        runner = CliRunner()
        result = runner.invoke(scanner.cert_scanner, ["-c", "08:04:07:55:C8:B6:85:2A:5D:B9:45:A2:B3:80:57:11:11:DE:FD:2D", "-h",  "invalid_id"])
        output = result.output.split('\n')[4]
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(output, "crt.sh status:\t Certificate Found") # -c command takes precedence over -h, doesn't fail
