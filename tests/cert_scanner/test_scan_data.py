import unittest
import json
from cert_scanner import scanner

class TestScanData(unittest.TestCase):
    def setUp(self):
        hostname_file = open('tests/cert_scanner/data/hostnames.json')
        hostname = json.load(hostname_file)
        cert_file = open('tests/cert_scanner/data/certs.json')
        certs = json.load(cert_file)

        self.valid_hostnames = hostname['hostnames']['valid_hostnames']
        self.invalid_hostnames = hostname['hostnames']['invalid_hostnames']
        
        self.valid_SHA1 = certs['certs']['valid_cert_SHA1']
        self.valid_SHA256 = certs['certs']['valid_cert_SHA256']
        self.valid_cert_id = certs['certs']['valid_cert_id']
        self.invalid_certs = certs['certs']['invalid_certs']

        hostname_file.close()
        cert_file.close()

    # Testing list of valid hostnames
    def test_multiple_valid_hostnames(self):
        for host in self.valid_hostnames:
            with self.subTest(line=host):
                result = scanner.scan(host)
                self.assertEqual(result['valid'], True)
    
    # Testing list of invalid hostnames
    def test_multiple_invalid_hostnames(self):
        for host in self.invalid_hostnames:
            with self.subTest(line=host):
                result = scanner.scan(host)
                self.assertEqual(result['valid'], False)

    def test_multiple_valid_SHA1(self):
        for cert in self.valid_SHA1:
            with self.subTest(line=cert):
                result = scanner.scan(None, cert)
                self.assertEqual(result['valid'], True)

    def test_multiple_valid_SHA256(self):
        for cert in self.valid_SHA256:
            with self.subTest(line=cert):
                result = scanner.scan(None, cert)
                self.assertEqual(result['valid'], True)

    def test_multiple_valid_cert_id(self):
        for cert in self.valid_cert_id:
            with self.subTest(line=cert):
                result = scanner.scan(None, cert)
                self.assertEqual(result['valid'], True)

    def test_multiple_invalid_cert_id(self):
        for cert in self.invalid_certs:
            with self.subTest(line=cert):
                result = scanner.scan(None, cert)
                self.assertEqual(result['valid'], False)


    
    




        
        


    


        
