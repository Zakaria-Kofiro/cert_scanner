import unittest
import pytest
import datetime
from cert_scanner import scanner

class TestHelpers(unittest.TestCase):

    def setUp(self):
        # setting up sample cert inputs for process_cert_data() with shorter alt name list
        self.short_ssl_cert = {  
                                'OCSP': ('http://ocsp.digicert.com',),
                                'caIssuers': ('http://cacerts.digicert.com/DigiCertGlobalCAG2.crt',),
                                'crlDistributionPoints': ('http://crl3.digicert.com/DigiCertGlobalCAG2.crl',
                                                        'http://crl4.digicert.com/DigiCertGlobalCAG2.crl'),
                                'issuer': ((('countryName', 'US'),),
                                           (('organizationName', 'DigiCert Inc'),),
                                           (('commonName', 'DigiCert Global CA G2'),)),
                                'notAfter': 'Sep 19 23:59:59 2022 GMT',
                                'notBefore': 'Oct  6 00:00:00 2021 GMT',
                                'serialNumber': '0E4239AB85E2E6A27C52C6DE9B9078D9',
                                'subject': ((('commonName', '*.peg.a2z.com'),),),
                                'subjectAltName': ( ('DNS', 'amazon.co.uk'),
                                                    ('DNS', 'uedata.amazon.co.uk'),
                                                    ('DNS', 'www.amazon.co.uk'),
                                                    ('DNS', 'origin-www.amazon.co.uk'),
                                                    ('DNS', '*.peg.a2z.com'),
                                                    ('DNS', 'amazon.com')),
                                'version': 3
        }
        self.short_crt_response = {
                                    'id': '5981531243', 
                                    'sha256': '5BF3D7E0E6927F773D5106C822C53F6F52C199F7EB1B3B8154B41F2924391C75', 
                                    'sha1': '08040755C8B6852A5DB945A2B380571111DEFD2D', 
                                    'version': '3', 
                                    'serial': '0e4239ab85e2e6a27c52c6de9b9078d9', 
                                    'signature_algorithm': 'sha256WithRSAEncryption', 
                                    'issuer': 
                                        {
                                        'id': '5886', 
                                        'commonName': 'DigiCert Global CA G2', 
                                        'organizationName': 'DigiCert Inc', 
                                        'countryName': 'US'
                                        }, 
                                    'not_before': datetime.datetime(2021, 10, 6, 0, 0), 
                                    'not_after': datetime.datetime(2022, 9, 19, 23, 59, 59), 
                                    'subject': 
                                        {'commonName': '*.peg.a2z.com'}, 
                                    'publickey': 
                                        {
                                        'sha256': '5dfb8a839c37dc0db3e129b0acefb50923a4d84931596890149e9f1c84baa8ac', 
                                        'algorithm': 'rsaEncryption', 
                                        'size': 2048, 
                                        'modulus': '00bfefee33c3647bea4353a956a1900b5dfacdc07ebf07', # shorten mod, testing format_hex
                                        'exponent': '65537'
                                        }, 
                                    'extensions': 
                                        {
                                            'authority_key_identifier': '246E2B2DD06A925151256901AA9A47A689E74020', 
                                            'subject_key_identifier': '9545143E3A401E9516F082AC457382586D9BF074', 
                                            'alternative_names': 
                                                ['amazon.co.uk', 'uedata.amazon.co.uk', 'www.amazon.co.uk', 'origin-www.amazon.co.uk', '*.peg.a2z.com', 'amazon.com'], 
                                            'key_usage': 
                                                {
                                                'critical': True, 
                                                'usage': ['Digital Signature', 'Key Encipherment']
                                                }, 
                                            'extended_key_usage': 
                                                {
                                                'usage': ['TLS Web Server Authentication', 'TLS Web Client Authentication']}, 
                                                'crl_distribution': {'url': 'http://crl3.digicert.com/DigiCertGlobalCAG2.crl'}, 
                                                'certificate_policies': ['2.23.140.1.2.1'], 
                                                'authority_information_access': 
                                                {
                                                    'OCSP': 'URI:http://ocsp.digicert.com', 
                                                    'CA Issuers': 'URI:http://cacerts.digicert.com/DigiCertGlobalCAG2.crt'
                                                }, 
                                            'basic_constraints': False
                                        }, 
                                        'signature': 'c8b265b86e80159e5f560c5d4b9ef849977b7489c4ba' # shorten sig
        } 
        
    # cert_option_set() code path tested in test_scan via cert tests
    # check_cert() code path tested in test_scan_data via hostname/cert tests

    # ssl_cert() 
    def test_helper_ssl_cert_valid_host(self):
        result = scanner.ssl_cert(('amazon.com', 443))
        common_name = result['subject'][0][0][1]
        self.assertEqual(common_name , '*.peg.a2z.com')

    def test_helper_ssl_cert_invalid_host(self):
        with pytest.raises(SystemExit) as pytest_wrapped_error:
            scanner.ssl_cert(("expired.badssl.com", 443))
        self.assertEqual(pytest_wrapped_error.value.code, "SSL: certificate verify failed: certificate has expired")

    def test_helper_ssl_cert_empty_or_not_known_host(self):
        with pytest.raises(SystemExit) as pytest_wrapped_error:
            scanner.ssl_cert(("", 443))
        self.assertEqual(pytest_wrapped_error.value.code, "error: hostname not provided or not known")

        with pytest.raises(SystemExit) as pytest_wrapped_error:
            scanner.ssl_cert(("www.thisdoesnotexist5542.com", 443))
        self.assertEqual(pytest_wrapped_error.value.code, "error: hostname not provided or not known")

    # process_cert_data()
    def test_helper_default_process_cert_data(self):
        result = scanner.process_cert_data(self.short_ssl_cert, self.short_crt_response)
        # crt_response data
        self.assertEqual(result['subject_name']['common_name'], '*.peg.a2z.com')
        self.assertEqual(result['issuer_name']['common_name'], 'DigiCert Global CA G2')
        self.assertEqual(result['validity']['not_before'], 'Wed, 06 Oct 2021 00:00:00 GMT')
        self.assertEqual(result['public_key_info']['modulus'], '00:BF:EF:EE:33:C3:64:7B:EA:43:53:A9:56:A1:90:0B:5D:FA:CD:C0:7E:BF:07')
        self.assertEqual(result['public_key_info']['public_key'], '5D:FB:8A:83:9C:37:DC:0D:B3:E1:29:B0:AC:EF:B5:09:23:A4:D8:49:31:59:68:90:14:9E:9F:1C:84:BA:A8:AC')
        # ssl_cert data
        self.assertEqual(result['CRL_endpoints']['endpoints'][0], 'http://crl3.digicert.com/DigiCertGlobalCAG2.crl')
        self.assertEqual(result['CRL_endpoints']['endpoints'][1], 'http://crl4.digicert.com/DigiCertGlobalCAG2.crl')
        self.assertEqual(result['authority_information_access']['OCSP'], 'http://ocsp.digicert.com')
        self.assertEqual(result['authority_information_access']['CA_issuers'], 'http://cacerts.digicert.com/DigiCertGlobalCAG2.crt')
    
    def test_helper_process_cert_data_with_cert_option(self):
        result = scanner.process_cert_data(None, self.short_crt_response, True)
        # crt_response data
        self.assertEqual(result['subject_name']['common_name'], '*.peg.a2z.com')
        self.assertEqual(result['issuer_name']['common_name'], 'DigiCert Global CA G2')
        self.assertEqual(result['validity']['not_before'], 'Wed, 06 Oct 2021 00:00:00 GMT')
        self.assertEqual(result['public_key_info']['modulus'], '00:BF:EF:EE:33:C3:64:7B:EA:43:53:A9:56:A1:90:0B:5D:FA:CD:C0:7E:BF:07')
        self.assertEqual(result['public_key_info']['public_key'], '5D:FB:8A:83:9C:37:DC:0D:B3:E1:29:B0:AC:EF:B5:09:23:A4:D8:49:31:59:68:90:14:9E:9F:1C:84:BA:A8:AC')
        # ssl_cert data - should not be in result dict
        self.assertNotIn('CRL_endpoints', result)
        self.assertNotIn('authority_information_access', result)




    

    

    

    
        
    

        
