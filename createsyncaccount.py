import logging
import random
import string
import codecs
import argparse
import json
from io import BytesIO, StringIO
import xml.etree.ElementTree as ET
import requests
from lib.wcf.records import Record, print_records
from lib.wcf.xml2records import XMLParser
from lib.wcf.records import dump_records
from lib.utils.xml import xmlesc
from roadtools.roadlib.auth import Authentication



REQ_TEMPLATE = '''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
 <s:Header>
  <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/online/aws/change/2010/01/IProvisioningWebService/GetServiceAccount</a:Action>
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
   <TrackingId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">6e408838-7a85-42e3-8600-8e53709ef1a7</TrackingId>
  </SyncToken>
  <a:MessageID>urn:uuid:cf2a6706-fb6e-4572-99a0-a6dc6757f7aa</a:MessageID>
  <a:ReplyTo>
   <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
  </a:ReplyTo>
  <a:To s:mustUnderstand="1">https://adminwebservice.microsoftonline.com/provisioningservice.svc</a:To>
 </s:Header>
 <s:Body>
  <GetServiceAccount xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
   <identifier>{identifier}</identifier>
  </GetServiceAccount>
 </s:Body>
</s:Envelope>'''


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--access-token', action='store', help='Access token for Azure AD Graph. If not specified, taken from .roadtools_auth')
    parser.add_argument('-i', '--identifier', action='store', help='Name to use for sync account, often in the format: Sync_HOSTNAME_RANDOMGUID. If not specified, random generated')
    parser.add_argument('-n', '--hostname', action='store', help='Hostname to user for sync account name if identifier is not specified')
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

    # Headers
    hdata = '''Content-Type: application/soap+msbin1
x-ms-aadmsods-apiaction: GetServiceAccount
x-ms-aadmsods-appid: 1651564e-7ce4-4d99-88be-0a65050d8dc3
client-request-id: 6e408838-7a85-42e3-8600-8e53709ef1a7
x-ms-aadmsods-clientversion: 8.0
x-ms-aadmsods-dirsyncbuildnumber: 2.1.19.0
x-ms-aadmsods-fimbuildnumber: 2.1.19.0
x-ms-aadmsods-tenantid: 6287f28f-4f7f-4322-9651-a8697d8fe1bc
x-ms-aadmsods-machineid:\x20
x-ms-aadmsods-provisioningsessiondesc: Connector-c7a8a4f7-0f68-4f7c-b688-88e6306d3894
x-ms-aadmsods-scenario: export-scheduled-regular
Expect: 100-continue'''
    headers = {}
    for hdrdata in hdata.split('\n'):
        header, value = hdrdata.split(': ')
        headers[header] = value

    if args.identifier:
        identifier = args.identifier
    else:
        if args.hostname:
            hostname = args.hostname
        else:
            hostname = 'DESKTOP-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        identifier = f"Sync_{hostname}_{suffix}"

    logging.info(f"Creating sync account with identifier {identifier}")

    # Create payload
    body = REQ_TEMPLATE.format(token=xmlesc(tokenobject['accessToken']), identifier=xmlesc(identifier))
    logging.debug(body)

    # Encode body in binary format
    parser = XMLParser.parse(body)
    data = dump_records(parser)

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
        els = tree.find('.//{http://schemas.microsoft.com/online/aws/change/2010/01}GetServiceAccountResult')
        if els:
            result = els.find('{http://schemas.microsoft.com/online/aws/change/2014/06}UserName')
            if result is not None:
                username = result.text
                logging.info('Sync account username: %s', username)
            else:
                logging.error('Could not find username in XML')
            result = els.find('{http://schemas.microsoft.com/online/aws/change/2014/06}Password')
            if result is not None:
                password = result.text
                logging.info('Sync account password: %s', password)
            else:
                logging.error('Could not find password in XML')
        else:
            logging.error('Could not find result in XML')

if __name__ == '__main__':
    main()
