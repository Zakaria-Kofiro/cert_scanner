import unittest
import pytest
from cert_scanner import scanner

class TestScan(unittest.TestCase):
    def test_scanner_valid_hostname(self):
        result = scanner.scan("amazon.com")
        subject = result['data']['subject_name']
        pem_cert = result['pem_certificate'].split('\n')[0]
        self.assertEqual(result['valid'], True)
        self.assertEqual(subject["common_name"], "*.peg.a2z.com")
        self.assertEqual(pem_cert, '-----BEGIN CERTIFICATE-----')
    
    def test_scanner_valid_hostname_no_cert(self):
        result = scanner.scan("www.expired.badssl.com")
        self.assertEqual(result['valid'], False)
        self.assertEqual(result['data'], None)
        self.assertEqual(result['pem_certificate'], None)

    def test_scanner_invalid_hostname(self):
        with pytest.raises(SystemExit) as pytest_wrapped_error:
            scanner.scan("www.thisdoesnotexist5542.com")
        self.assertEqual(pytest_wrapped_error.value.code, 'error: hostname not provided or not known')

    def test_scanner_empty_hostname(self):
        with pytest.raises(SystemExit) as pytest_wrapped_error:
            scanner.scan("")
        self.assertEqual(pytest_wrapped_error.value.code, 'error: hostname not provided or not known')

    def test_scanner_valid_cert(self):
        result = scanner.scan(None, "08:04:07:55:C8:B6:85:2A:5D:B9:45:A2:B3:80:57:11:11:DE:FD:2D") # amazon SHA1
        subject = result['data']['subject_name']
        pem_cert = result['pem_certificate']
        self.assertEqual(result['valid'], True)
        self.assertEqual(subject["common_name"], "*.peg.a2z.com")
        self.assertEqual(pem_cert, None) # No PEM since cert option

    def test_scanner_invalid_cert(self):
        result = scanner.scan(None, "ae3431341")
        self.assertEqual(result['valid'], False)
        self.assertEqual(result['data'], None)
        self.assertEqual(result['pem_certificate'], None)

    def test_scanner_empty_cert(self):
        with pytest.raises(SystemExit) as pytest_wrapped_error:
            scanner.scan(None, "")
        self.assertEqual(pytest_wrapped_error.value.code, 'error: hostname not provided or not known')

    def test_scanner_cert_and_valid_hostname(self):
        result = scanner.scan("amazon.com", "08:04:07:55:C8:B6:85:2A:5D:B9:45:A2:B3:80:57:11:11:DE:FD:2D") # amazon hostname + SHA1
        subject = result['data']['subject_name']
        pem_cert = result['pem_certificate']
        self.assertEqual(result['valid'], True)
        self.assertEqual(subject["common_name"], "*.peg.a2z.com")
        self.assertEqual(pem_cert, None)

    def test_scanner_cert_and_invalid_hostname(self):
        result = scanner.scan("www.thisdoesnotexist5542.com", "08:04:07:55:C8:B6:85:2A:5D:B9:45:A2:B3:80:57:11:11:DE:FD:2D")
        subject = result['data']['subject_name']
        pem_cert = result['pem_certificate']
        self.assertEqual(result['valid'], True) # cert option takes over and returns success
        self.assertEqual(subject["common_name"], "*.peg.a2z.com")
        self.assertEqual(pem_cert, None)

        
