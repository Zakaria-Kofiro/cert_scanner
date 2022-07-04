import hashlib
import socket
import ssl
from datetime import datetime
from pycrtsh import Crtsh

from pprint import pprint


""" Attempts to retrieve SSL/TLS certificate data from a given host
    If the certificate is valid, prints all relevant certificate data
    and returns the data as a JSON object
    If the certificate is invalid, prints an error message and returns an
    equivalent JSON object incidating an invalid cert 
    
Args:
    hostname (str): used to connect to host and extract certificate information
Returns:
    JSON object: JSON object containing all SSL/TLS certificate data from host
"""
def scan(hostname):
    addr = (hostname, 443) # setting up hostname payload for query
    
    # the ssl python library offers two main methods for certifcate retrival: `SSLSocket.getpeercert` and `ssl.get_server_certificate`
    # `SSLSocket.getpeercert` validates the certificate (raises ssl.SSLCertVerificationError if invalid or returns an empty dict if verify_mode=ssl.CERT_NONE)
    # but `ssl.get_server_certificate` allows users to skip validation to retrieve invalid/outdated PEM certs
    # both functions return the same certificate information if valid so we first call `ssl.get_server_certificate`
    # to get any valid or invalid certificate SHA fingerprints from hosts to check against crt.sh 
    # before calling `SSLSocket.getpeercert` for extra certificate information if the certificate is valid
    try:
        cert = ssl.get_server_certificate(addr)
    except socket.gaierror:
        raise SystemExit("error: hostname not provided or not known")

    DER_cert = ssl.PEM_cert_to_DER_cert(cert) # get the DER-encoded form of SSL/TLS cert from host (used to get SHA fingerprints)
    sha256 = hashlib.sha256(DER_cert).hexdigest() # get SHA-256 fingerprint for crt.sh request
    crt_response = check_cert(sha256) # check SHA256 from cert against crt.sh

    # if validated from crt.sh, get extra certificate information using SSL library, else print invalid certificate message
    if crt_response[0]:
        context = ssl.create_default_context() # create new SSL context with secure default settings
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname) as conn: # set hostname for context and wrap socket
            try:
                conn.settimeout(1) # 1 second timeout
                conn.connect(addr) # connect to host
                dict_cert = conn.getpeercert() # get dict version of cert for certificate data - method also validates cert, fails if invalid
            except ssl.SSLCertVerificationError as e:
                raise SystemExit(e)
            except socket.gaierror:
                raise SystemExit("error: hostname not provided or not known")
    else:
        print_invalid_cert(hostname, crt_response) # print invalid certificate message - matching output style
        error_payload = {'valid': False, 'content': None}
        return error_payload
         
    
    # process all avaliable SSL/TLS certificate data using cert info from both crt.sh and SSL call
    cert_data = process_cert_data(dict_cert, crt_response[1], cert)


def print_cert(hostname, payload):
    border = "─"*60

    print("cert_scanner: Python Based SSL/TLS scanner\n")
    print(f"Scan Results:{border}")
    issuer = payload[0]['issuer'][1][0][1]
    print(f"Website:\t {hostname}")
    print("crt.sh status:\t Certificate found")
    print(f"Verified by:\t {issuer}\n")
    print("Certificate Information:\n\n")
    print(border)


""" This function uses both cert info from the SSL library and crt.sh to
    format the data to allow for easier consumption for output.
    It returns a dictionary with SSL/TLS certificate information with:

    keys: group heading i.e 'Subject Name', 'Issuer Name' 
    values: group data listed under heading i.e 'Common Name', 'Country'

    It also returns the PEM_CERT which is later used in the web app
Args:
    ssl_cert (dict): dict containing SSL/TLS cert info from SSL library 
    crt_response (dict): dict containing SSL/TLS cert info from SSL library 
    pem_cert (string): PEM-encoded certificate used by the web app for download
Returns:
    tuple: tuple containing completed SSL/TLS cert dictionary and PEM certificate
"""
def process_cert_data(ssl_cert, crt_response, pem_cert):
    cert_data = {}

    # easier to process crt.sh dict for shared cert data
    crt_subject = crt_response['subject']
    crt_issuer = crt_response['issuer']
    crt_extensions = crt_response['extensions']
    crt_public_key = crt_response['publickey']

    # Subject Name
    cert_data['subject_name'] = {x.replace("Name", ""):crt_subject[x] for x in crt_subject.keys()} # copy dict keys with some formatting changes 
    cert_data['subject_name']['common_name'] = cert_data['subject_name'].pop('common')
    cert_data['subject_name']['state_or_province'] = cert_data['subject_name'].pop('stateOrProvince')
    # Issuer Name
    cert_data['issuer_name'] = {x.replace("Name", ""):crt_issuer[x] for x in crt_issuer.keys()}
    cert_data['issuer_name']['common_name'] = cert_data['issuer_name'].pop('common')
    # Validity - crt.sh returns timestamps in GMT (strftime returns CST)
    cert_data['validity'] = {
        'not_before': crt_response['not_before'].strftime("%a, %d %b %Y %H:%M:%S GMT"),
        'not_after': crt_response['not_after'].strftime("%a, %d %b %Y %H:%M:%S GMT")
    }
    # Subject Alt Names
    cert_data['subject_alt_names'] = {
        'DNS_name': crt_extensions['alternative_names']
    }
    # Public Key
    cert_data['public_key_info'] = {x:crt_public_key[x] for x in crt_public_key.keys()}
    cert_data['public_key_info']['key_size'] = cert_data['public_key_info'].pop('size')
    cert_data['public_key_info']['public_key'] = format_hex(cert_data['public_key_info'].pop('sha256').upper())
    cert_data['public_key_info']['modulus'] = format_hex(cert_data['public_key_info']['modulus'].upper())
    # Miscellaneous
    cert_data['miscellaneous'] = {
        'serial_number': format_hex(crt_response['serial'].upper()),
        'signature_algorithm': crt_response['signature_algorithm'],
        'version': crt_response['version'],
    }
    # Fingerprints
    cert_data['fingerprints'] = {
        'sha256': format_hex(crt_response['sha256']),
        'sha1': format_hex(crt_response['sha1'])
    }
    # Basic Constraints
    cert_data['basic_constraints'] = {
        'certificate_authority': "Yes" if crt_extensions['basic_constraints'] else "No"
    }
    # Key Usages
    cert_data['key_usages'] = {
        'critical': crt_extensions['key_usage']['critical'],
        'purposes': ", ".join(crt_extensions['key_usage']['usage'])
    }
    # Extended Key Usages
    cert_data['extended_key_usage'] = {
         'purposes': ", ".join(crt_extensions['extended_key_usage']['usage'])
    }
    # Subject + Auth Key ID
    cert_data['subject_key_ID'] = {
        'key_id': format_hex(crt_extensions['subject_key_identifier'])
    }
    cert_data['authority_key_ID'] = {
        'key_id': format_hex(crt_extensions['authority_key_identifier'])
    }

    # SSL cert data has complete, easy to use CRL endpoint and AIA data
    # CRL Endpoints: 
    cert_data['CRL_endpoints'] = ssl_cert['crlDistributionPoints'] 
    # Authority Info (AIA)
    cert_data['authority_information_access'] = {
        'OCSP':  ssl_cert['OCSP'][0],
        'CA_issuers': ssl_cert['caIssuers'][0]
    }
    # Certificate Policies
    cert_data['certificate_policies'] = {
            'policies': [f'Certificate Type ({x})' for x in crt_extensions['certificate_policies']]
    }
    return cert_data


""" Helper function that formats hexstring for output 
    ex: 00cd94836ac9e8 -> 00:CD:94:83:6A:C9:E8
Args:
    key (string): dict hexstring key to format
Returns:
    string: formatted hexstring
"""
def format_hex(key):
    string_len = len(key)
    return ':'.join(key[i:i+2] for i in range(0,string_len,2))


""" This method checks if a given certificate exists in crt.sh
    It uses the crt.sh API and the SHA256 from the certificate 
    for validation, and if it exists, returns a valid flag and crt.sh response
    If it does not exist, the API sends an error and the method returns 
    a invalid flag with the crt.sh error response
Args:
    sha256 (string): sha256 string from a DER encoded certificate
Returns:
    tuple: (validity_flag, crt_response)
"""
def check_cert(sha256):
    c = Crtsh()
    try:
        response = c.get(sha256, type='sha256') # check if cert listed in crt.sh
        return (True, response)
    except Exception as invalid_cert:
        return (False, invalid_cert)


""" Helper function to output invalid certificate information
Args:
    hostname (string): given host to connect to
    crt_response (string): error message from crt.sh API (from `check_cert`)
"""
def print_invalid_cert(hostname, crt_response):
    border = "─"*60
    print(border)
    print(f"Website:\t {hostname}")
    print(f"crt.sh status:\t {crt_response[1]}")
    print("Verified by:\t Not specified\n\n")
    print("\t-- No certificate information to display --\n\n")
    print(border)


if __name__ == "__main__":
    secure_hosts = ["www.google.com", "www.intuit.com"]
    bad_hosts = ["www.expired.badssl.com", "www.go.com", "www.baidu.com"]
    if (1 == 0):
        scan("www.expired.badssl.com")
    else:
        scan("www.intuit.com")