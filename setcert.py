#!/usr/bin/env python3
####################
#
# Copyright (c) 2024 Dirk-jan Mollema (@_dirkjan)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
# Add a certificate to a computer object via LDAP (for hybrid AAD device)
#
####################
import sys
import argparse
import random
import datetime
import string
import getpass
import os
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from ldap3 import NTLM, Server, Connection, ALL, LEVEL, BASE, MODIFY_DELETE, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS
from lib.utils.kerberos import ldap_kerberos
import ldap3
from ldap3.protocol.microsoft import security_descriptor_control
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))

def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))

def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))

def main():
    parser = argparse.ArgumentParser(description='Add cert to device for hybrid join')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    #Main parameters
    parser.add_argument("host", metavar='HOSTNAME', help="Hostname/ip or ldap://host:port connection string to connect to")
    parser.add_argument("-u", "--user", metavar='USERNAME', help="DOMAIN\\username for authentication")
    parser.add_argument("-p", "--password", metavar='PASSWORD', help="Password or LM:NTLM hash, will prompt if not specified")
    parser.add_argument("-t", "--target", metavar='TARGET', help="Computername or username to target (FQDN or COMPUTER$ name, if unspecified user with -u is target)")
    parser.add_argument("-T", "--target-type", metavar='TARGETTYPE', choices=('samname','hostname','auto'), default='auto', help="Target type (samname or hostname) If unspecified, will assume it's a hostname if there is a . in the name and a SAM name otherwise.")
    parser.add_argument("-cert", metavar='CERT', help="Certificate in PEM format to set.")
    parser.add_argument("-r", "--overwrite", action='store_true', help="Overwrite an existing certificate")
    parser.add_argument("-c", "--clear", action='store_true', help="Clear, i.e. remove all certs")
    parser.add_argument("-q", "--query", action='store_true', help="Show the current target certs instead of modifying anything")
    parser.add_argument('-k', '--kerberos', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
   
    args = parser.parse_args()

    #Prompt for password if not set
    authentication = None
    if not args.user or not '\\' in args.user:
        print_f('Username must include a domain, use: DOMAIN\\username')
        sys.exit(1)
    domain, user = args.user.split('\\', 1)
    if not args.kerberos:
        authentication = NTLM
        sasl_mech = None
        if args.password is None:
            args.password = getpass.getpass()
    else:
        TGT = None
        TGS = None
        try:
            # Hashes
            lmhash, nthash = args.password.split(':')
            assert len(nthash) == 32
            password = ''
        except:
            # Password
            lmhash = ''
            nthash = ''
            password = args.password
        if 'KRB5CCNAME' in os.environ and os.path.exists(os.environ['KRB5CCNAME']):
            domain, user, TGT, TGS = CCache.parseFile(domain, user, 'ldap/%s' % args.host)
        if args.dc_ip is None:
            kdcHost = domain
        else:
            kdcHost = args.dc_ip
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if not TGT and not TGS:
            if not args.password and not nthash:
                password = getpass.getpass()
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, args.aesKey, kdcHost)
        elif TGT:
            # Has TGT
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']
        if not TGS:
            # Request TGS
            serverName = Principal('ldap/%s' % args.host, type=constants.PrincipalNameType.NT_SRV_INST.value)
            TGS = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
        else:
            # Convert to tuple expected
            TGS = (TGS['KDC_REP'], TGS['cipher'], TGS['sessionKey'], TGS['sessionKey'])
        authentication = SASL
        sasl_mech = KERBEROS

    # define the server and the connection
    s = Server(args.host, get_info=ALL)
    print_m('Connecting to host...')
    c = Connection(s, user=args.user, password=args.password, authentication=authentication, sasl_mechanism=sasl_mech)
    print_m('Binding to host')
    # perform the Bind operation
    if authentication == NTLM:
        if not c.bind():
            print_f('Could not bind with specified credentials')
            print_f(c.result)
            sys.exit(1)
    else:
        ldap_kerberos(domain, kdcHost, None, userName, c, args.host, TGS)
    print_o('Bind OK')
    # Find service connection
    scp = "CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,"+s.info.other['configurationNamingContext'][0]
    c.search(scp, '(objectClass=*)', search_scope=BASE, attributes=['keywords'])
    try:
        servicecon = c.entries[0]
        data = {}
        for kw in servicecon.keywords:
            kwkey, kwval = kw.split(':')
            data[kwkey] = kwval
        if 'azureADId' in data:
            print_o(f"Found Azure AD tenant ID for hybrid join: {data['azureADId']}")
    except IndexError:
        print_f('Service configuration point not found, unable to look up tenant ID. This domain may not be configured for hybrid join!')

    targetuser = args.target
    if not targetuser:
        targetuser = user

    if ('.' in targetuser and args.target_type != 'samname') or args.target_type == 'hostname':
        if args.target_type == 'auto':
            print_m('Assuming target is a hostname. If this is incorrect use --target-type samname')
        search = '(dnsHostName=%s)' % targetuser
    else:
        search = '(SAMAccountName=%s)' % targetuser
    c.search(s.info.other['defaultNamingContext'][0], search, attributes=['SAMAccountName', 'userCertificate', 'objectGUID', 'objectSid'])

    try:
        targetobject = c.entries[0]
        print_o('Found modification target')
    except IndexError:
        print_f('Target not found!')
        return

    if args.query:
        # If we only want to query it
        print(targetobject)
        return

    if args.clear:
        print_o('Printing object before clearing')
        print(targetobject)
        c.modify(targetobject.entry_dn, {'userCertificate':[(ldap3.MODIFY_REPLACE, [])]})
    else:
        if len(targetobject.usercertificate) > 0:
            if not args.overwrite:
                print('Certificate exists, use --overwrite to force overwriting')
                return

        if args.cert:
            try:
                with open(args.cert, "rb") as certf:
                    cert = x509.load_pem_x509_certificate(certf.read())
                certdata = cert.public_bytes(serialization.Encoding.DER)
            except FileNotFoundError:
                print_f(f"Invalid file path: {args.cert}")
                sys.exit(1)
            except ValueError:
                print_f(f"Error while loading {args.cert}, the certificate must be in PEM format.")
                sys.exit(1)

        else:
            if targetuser[-1] == '$':
                outfile = targetuser[:-1]
            else:
                outfile = targetuser
            privout = f"{outfile}.key"
            certout = f"{outfile}.pem"
            # Create self-signed cert
            # Generate our key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            # Write device key to disk
            print_m(f'Saving private key to {privout}')
            with open(privout, "wb") as keyf:
                keyf.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))

            # Generate a self-signed cert
            guid = str(targetobject.objectGUID)[1:-1]
            objectsid = str(targetobject.objectSid)
            print_m(f"Device ID: {guid}")
            print_m(f"Device SID: {objectsid}")
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, guid),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Our certificate will be valid for 10 years
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            ).sign(key, hashes.SHA256())

            # Write our certificate out to disk.
            
            print_m(f'Saving certificate key to {certout}')
            with open(certout, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            # Use binary data for writing to object
            certdata = cert.public_bytes(serialization.Encoding.DER)
            c.modify(targetobject.entry_dn, {'userCertificate':[(ldap3.MODIFY_REPLACE, [certdata])]})


    if c.result['result'] == 0:
        print_o('Certificate Modified successfully')
    else:
        if c.result['result'] == 50:
            print_f('Could not modify object, the server reports insufficient rights: %s' % c.result['message'])
        elif c.result['result'] == 19:
            print_f('Could not modify object, the server reports a constrained violation')
        else:
            print_f('The server returned an error: %s' % c.result['message'])

if __name__ == '__main__':
    main()
