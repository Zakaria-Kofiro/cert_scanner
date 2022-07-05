import hashlib
import socket
import ssl
import click

from datetime import datetime
from pycrtsh import Crtsh, CrtshCertificateNotFound


""" Entrypoint for CLI
Args:
    hostname (str): required CLI arg, used to connect to host and extract certificate information
    cert(str): optional CLI arg, used to validate cert value against crt.sh API
"""
@click.command(no_args_is_help=True)
@click.option('--hostname', '-h', help='Get SSL/TLS certificate for given hostname')
@click.option('--cert', '-c', default=None, help='Queries cert against crt.sh (crt.sh id, sha1, or sha256)')
def cert_scanner(hostname, cert):
    scan(hostname, cert)

""" Attempts to retrieve SSL/TLS certificate data from a given host
    If the certificate is valid, prints all relevant certificate data
    and returns the data as a JSON object
    If the certificate is invalid, prints an error message and returns an
    equivalent JSON object incidating an invalid cert 
Args:
    hostname (str): used to connect to host and extract certificate information (displays cert info)
    cert(str): used to validate cert value against crt.sh API (displays cert info)
Returns:
    hostname option:
            success_payload: dict payload indicating crt_sh found certificate, with payload and pem_cert (if valid cert)
            error_payload: dict payload indicating cert not found/error (if invalid cert)
            
    cert option:
        prints out cert info and returns
"""
def scan(hostname, cert=None):
    """cert_scanner: Python Based SSL/TLS scanner"""

    if cert:
        payload = cert_option_set(cert) # different workflow for checking cert against crt.sh (no hostname)
        return payload
    
    addr = (hostname, 443) # setting up hostname payload for query

    # the ssl python library offers two main methods for certifcate retrival: `SSLSocket.getpeercert` and `ssl.get_server_certificate`
    # `SSLSocket.getpeercert` validates the certificate (raises ssl.SSLCertVerificationError if invalid or returns an empty dict if verify_mode=ssl.CERT_NONE)
    # but `ssl.get_server_certificate` allows users to skip validation to retrieve invalid/outdated PEM certs
    # both functions return the same certificate information if valid so we first call `ssl.get_server_certificate`
    # to get any valid or invalid certificate SHA fingerprints from hosts to check against crt.sh 
    # before calling `SSLSocket.getpeercert` for extra certificate information if the certificate is valid
    try:
        pem_cert = ssl.get_server_certificate(addr)
    except (socket.gaierror, ConnectionRefusedError, ssl.SSLError):
        raise SystemExit("error: hostname not provided or not known")

    DER_cert = ssl.PEM_cert_to_DER_cert(pem_cert) # get the DER-encoded form of SSL/TLS cert from host (used to get SHA fingerprints)
    sha256 = hashlib.sha256(DER_cert).hexdigest() # get SHA-256 fingerprint for crt.sh request
    crt_response = check_cert(sha256) # check SHA256 from cert against crt.sh (using hostname)

    # if validated from crt.sh, get extra certificate information using SSL library, else print invalid certificate message
    if crt_response[0]:
        dict_cert = ssl_cert(addr)
    else:
        print_invalid_cert(hostname, crt_response) 
        error_payload = {'valid': False, 'data': None, 'pem_certificate': None}
        return error_payload
         
    # process and print all avaliable SSL/TLS certificate data using cert info from both crt.sh and SSL call
    cert_data = process_cert_data(dict_cert, crt_response[1])
    print_cert(hostname, cert_data)
    success_payload = {'valid': True, 'data': cert_data, 'pem_certificate': pem_cert}
    return success_payload


""" Helper method that queries cert info against crt.sh given it 
    is one of (crt.sh id, sha1, or sha256)
Args:
    cert (str): cert value used to query crt.sh
"""
def cert_option_set(cert):
    crt_response = check_cert(cert) # check SHA256 from cert against crt.sh (using cert)
    if crt_response[0]:
        cert_data = process_cert_data(None, crt_response[1], True)
        print_cert(crt_response[1]['subject']['commonName'], cert_data)
        success_payload = {'valid': True, 'data': cert_data, 'pem_certificate': None}
        return success_payload
    else:
        print_invalid_cert('Not Specified', crt_response) # print invalid certificate message - matching output style
        error_payload = {'valid': False, 'data': None, 'pem_certificate': None}
        return error_payload


""" Helper method that gets cert info from SSL library
    which is then used with crt.sh certificate data to 
    build a comprehensive certificate payload for output
Args:
    hostname (str): used to connect to host and extract certificate information
    addr (tuple): hostname and port payload used for connection call
Returns:
    dict_cert: dictionary returned from SSL library with certificate info
"""
def ssl_cert(addr):
    context = ssl.create_default_context() # create new SSL context with secure default settings
    context.check_hostname = False
    context.verify_mode = ssl.CERT_OPTIONAL
    with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=addr[0]) as conn: # set hostname for context and wrap socket
        try:
            conn.settimeout(1) # 1 second timeout
            conn.connect(addr) # connect to host
            dict_cert = conn.getpeercert() # get dict version of cert for certificate data - method also validates cert, fails if invalid
        except ssl.SSLCertVerificationError as e:
            raise SystemExit("SSL: certificate verify failed: certificate has expired")
        except (socket.gaierror, socket.timeout, ssl.SSLError, ValueError):
            raise SystemExit("error: hostname not provided or not known")
    return dict_cert


""" This function uses both cert info from the SSL library and crt.sh to
    format the data to allow for easier consumption for output
    It returns a dictionary with SSL/TLS certificate information with:

    keys: group heading i.e 'Subject Name', 'Issuer Name' 
    values: group data listed under heading i.e 'Common Name', 'Country'
Args:
    ssl_cert (dict): dict containing SSL/TLS cert info from SSL library 
    crt_response (dict): dict containing SSL/TLS cert info from SSL library
Returns:
    cert_data: completed SSL/TLS cert dictionary for output
"""
def process_cert_data(ssl_cert, crt_response, cert_option=False):
    cert_data = {}

    # easier to process crt.sh dict for shared cert data
    crt_subject = crt_response['subject']
    crt_issuer = crt_response['issuer']
    crt_extensions = crt_response['extensions']
    crt_public_key = crt_response['publickey']

    # Subject Name
    cert_data['subject_name'] = {x.replace("Name", ""):crt_subject[x] for x in crt_subject.keys()} # copy dict keys with some formatting changes 
    cert_data['subject_name']['common_name'] = cert_data['subject_name'].pop('common')
    if 'stateOrProvince' in cert_data['subject_name']:
        cert_data['subject_name']['state_or_province'] = cert_data['subject_name'].pop('stateOrProvince')
    # Issuer Name 
    cert_data['issuer_name'] = {x.replace("Name", ""):crt_issuer[x] for x in crt_issuer.keys()}
    cert_data['issuer_name']['common_name'] = cert_data['issuer_name'].pop('common')
    if 'stateOrProvince' in cert_data['issuer_name']:
        cert_data['issuer_name']['state_or_province'] = cert_data['issuer_name'].pop('stateOrProvince')
    cert_data['issuer_name'].pop('id') # id and org unit from crt.sh, not needed for output
    if 'organizationalUnit' in cert_data:
        cert_data['issuer_name'].pop('organizationalUnit')
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
    if 'size' in cert_data['public_key_info']:
        cert_data['public_key_info']['key_size'] = cert_data['public_key_info'].pop('size')
    if 'sha256' in cert_data['public_key_info']:
        cert_data['public_key_info']['public_key'] = format_hex(cert_data['public_key_info'].pop('sha256').upper()) 
    if 'modulus' in cert_data['public_key_info']:
        cert_data['public_key_info']['modulus'] = format_hex(cert_data['public_key_info']['modulus'].upper())
    
    # Miscellaneous
    cert_data['miscellaneous'] = {
        'serial_number': format_hex(crt_response['serial'].upper()),
        'signature_algorithm': crt_response['signature_algorithm'],
        'version': crt_response['version'],
    }
    # Fingerprints
    cert_data['fingerprints'] = {
        'SHA256': format_hex(crt_response['sha256']),
        'SHA1': format_hex(crt_response['sha1'])
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
        'key_ID': format_hex(crt_extensions['subject_key_identifier'])
    }
    cert_data['authority_key_ID'] = {
        'key_ID': format_hex(crt_extensions['authority_key_identifier'])
    }
    # cert option skips parsing through ssl_cert since it can't make call
    # to SSL library without hostname (crt.sh returns wildcard common names)
    if not cert_option: 
    # CRL Endpoints: 
        if 'crlDistributionPoints' in ssl_cert: # SSL cert data has complete, easy to use CRL endpoint and AIA data
            cert_data['CRL_endpoints'] = {
                'endpoints': ssl_cert['crlDistributionPoints']
            }
        # Authority Info (AIA)
        cert_data['authority_information_access'] = {
            'OCSP':  ssl_cert['OCSP'][0],
            'CA_issuers': ssl_cert['caIssuers'][0]
        }
    # Certificate Policies
    cert_data['certificate_policies'] = {
            'policies': crt_extensions['certificate_policies']
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
    except IndexError:
        return (False, 'crt.sh call failed, please retry request or re-run tests')
    except CrtshCertificateNotFound as invalid_cert:
        return (False, invalid_cert)


""" Prints header information for the final certificate output 
Args:
    hostname (str): used to output host/website name
    payload (dict): certificate info dict containing all certificate output data
"""
def print_cert(hostname, payload):
    border = "─"*60
    print("cert_scanner: Python Based SSL/TLS scanner\n") # Certificate information header 
    print(border)
    print(f"Website:\t {hostname}")
    print("crt.sh status:\t Certificate Found")
    print(f"Verified by:\t {payload['issuer_name']['organization']}\n\n")
    print("\t     --   Certificate Information   --\n")
    print_payload(payload)
    print(border)


""" Helper function to print all certificate information from payload
    Since the payload was formatted for easier output, this method 
    iterates through the <k,v> pairs of the dictionary and prints most
    pairs as is with little formatting with some more formatting for 
    special keys and values (i.e alt names list)
Args:
    payload (dict): certificate info dict containing all certificate output data
"""
def print_payload(payload):
    output_string = ""
    for group, group_items in payload.items():
        header = " ".join([x[0].upper() + x[1:] for x in group.replace("_", " ").split(" ")])
        print(f"{header}:")
        print("─"*30)
        for key, value in group_items.items():
            if key == "DNS_name": # handle alt name list seperately 
                for name in value:
                    print(f"   DNS Name: {name}")
                continue
            if key == "endpoints": # handle CRL endpoints list seperately
                for endpoint in value:
                    print(f"   Distribution Point: {endpoint}")
                continue
            if key == 'policies':
                for certificate in value:
                    print(f"   Policy: {certificate}")
                continue
            
            field = " ".join([x[0].upper() + x[1:] for x in key.replace("_", " ").split(" ")])
            print(f"   {field}: {value}")
        print("")


""" Helper function to output invalid certificate information
Args:
    hostname (string): given host to connect to
    crt_response (string): error message from crt.sh API (from `check_cert`)
"""
def print_invalid_cert(hostname, crt_response):
    print("cert_scanner: Python Based SSL/TLS scanner\n")
    border = "─"*60
    print(border)
    print(f"Website:\t {hostname}")
    print(f"crt.sh status:\t {crt_response[1]}")
    print("Verified by:\t Not specified\n\n")
    print("\t-- No certificate information to display --\n\n")
    print(border)


if __name__ == "__main__":
    cert_scanner()