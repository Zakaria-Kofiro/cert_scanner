import unittest
from click.testing import CliRunner
from cert_scanner import scanner

class TestScanner(unittest.TestCase):
    def test_scanner_valid_hostname(self):
        result = scanner.scan("www.intuit.com")
        
