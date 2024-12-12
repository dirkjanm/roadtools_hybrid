from lib.wcf.records import Record, print_records
from lib.wcf.xml2records import XMLParser
from lib.wcf.records import dump_records
from io import BytesIO
from roadtools.roadlib.auth import Authentication, get_data, WELLKNOWN_CLIENTS, WELLKNOWN_RESOURCES
from impacket.ldap.ldaptypes import LDAP_SID
import xml.etree.ElementTree as ET
import base64
import sys
import logging
import requests
import argparse
import codecs
import json

REQ_TEMPLATE = '''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
 <s:Header>
  <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/online/aws/change/2010/01/IProvisioningWebService/ProvisionAzureADSyncObjects2</a:Action>
  <SyncToken s:role="urn:microsoft.online.administrativeservice" xmlns="urn:microsoft.online.administrativeservice" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
   <ApplicationId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">6eb59a73-39b2-4c23-a70f-e2e3ce8965b1</ApplicationId>
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
   <TrackingId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">b1350d02-ff9e-4cff-a713-0e687a1446ed</TrackingId>
  </SyncToken>
  <a:MessageID>urn:uuid:23bef3ea-b582-43d0-9325-561d0a2f4365</a:MessageID>
  <a:ReplyTo>
   <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
  </a:ReplyTo>
  <a:To s:mustUnderstand="1">https://adminwebservice.microsoftonline.com/provisioningservice.svc</a:To>
 </s:Header>
 <s:Body>
  <ProvisionAzureADSyncObjects2 xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
   <syncRequest xmlns:b="http://schemas.microsoft.com/online/aws/change/2014/06" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
    <b:SyncObjects>
     <b:AzureADSyncObject>
      <b:PropertyValues xmlns:c="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
       {props}
      </b:PropertyValues>
      <b:SyncObjectType>User</b:SyncObjectType>
      <b:SyncOperation>Add</b:SyncOperation>
     </b:AzureADSyncObject>
    </b:SyncObjects>
   </syncRequest>
  </ProvisionAzureADSyncObjects2>
 </s:Body>
</s:Envelope>'''

PROPS_TEMPLATE = {
    'SourceAnchor': '''<c:KeyValueOfstringanyType>
        <c:Key>SourceAnchor</c:Key>
        <c:Value i:type="d:string" xmlns:d="http://www.w3.org/2001/XMLSchema">{propvalue}</c:Value>
       </c:KeyValueOfstringanyType>''',
    'accountEnabled': '''<c:KeyValueOfstringanyType>
        <c:Key>accountEnabled</c:Key>
        <c:Value i:type="d:boolean" xmlns:d="http://www.w3.org/2001/XMLSchema">{propvalue}</c:Value>
       </c:KeyValueOfstringanyType>
    ''',
    'onPremiseSecurityIdentifier':'''<c:KeyValueOfstringanyType>
        <c:Key>onPremiseSecurityIdentifier</c:Key>
        <c:Value i:type="d:base64Binary" xmlns:d="http://www.w3.org/2001/XMLSchema">{propvalue}</c:Value>
       </c:KeyValueOfstringanyType>''',
    'onPremisesSamAccountName':'''<c:KeyValueOfstringanyType>
        <c:Key>onPremisesSamAccountName</c:Key>
        <c:Value i:type="d:string" xmlns:d="http://www.w3.org/2001/XMLSchema">{propvalue}</c:Value>
       </c:KeyValueOfstringanyType>
    ''',
    'userPrincipalName': '''<c:KeyValueOfstringanyType>
        <c:Key>userPrincipalName</c:Key>
        <c:Value i:type="d:string" xmlns:d="http://www.w3.org/2001/XMLSchema">{propvalue}</c:Value>
       </c:KeyValueOfstringanyType>
    '''
}

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--access-token', action='store', help='Access token for Azure AD Graph. If not specified, taken from .roadtools_auth')
    parser.add_argument('-a', '--sourceanchor', action='store', help='Source anchor of object to modify')
    parser.add_argument('--accountenabled', action='store', help='Account enabled (either true or false)')
    parser.add_argument('-sid', '--securityidentifier', action='store', help='onPremiseSecurityIdentifier to set on the account')
    parser.add_argument('-sam', '--samaccountname', action='store', help='onPremisesSamAccountName to set on the account')
    parser.add_argument('-u', '--userprincipalname', action='store', help='userPrincipalName to set on the account')
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

    if not args.sourceanchor:
        logging.error('No source anchor was specified. This parameter is required to indicate the user to modify')
        return

    # All ok, starting request parsing

    props = []
    if args.securityidentifier:
        sid = LDAP_SID()
        sid.fromCanonical(args.securityidentifier)
        binsid = base64.b64encode(sid.getData()).decode('utf-8')
        props.append(PROPS_TEMPLATE['onPremiseSecurityIdentifier'].format(propvalue=binsid))
    if args.sourceanchor:
        props.append(PROPS_TEMPLATE['SourceAnchor'].format(propvalue=args.sourceanchor))
    if args.samaccountname:
        props.append(PROPS_TEMPLATE['onPremisesSamAccountName'].format(propvalue=args.samaccountname))
    if args.userprincipalname:
        props.append(PROPS_TEMPLATE['userPrincipalName'].format(propvalue=args.userprincipalname))
    if args.accountenabled:
        props.append(PROPS_TEMPLATE['accountEnabled'].format(propvalue=str(args.accountenabled)))

    propstring = '\n'.join(props)

    body = REQ_TEMPLATE.format(token=tokenobject['accessToken'], props=propstring)
    logging.debug(body)

    if len(props) == 1:
        # Always at least 1 since sourceanchor is mandatory
        logging.error('No properties specified to modify, exiting here')
        return


    # Encode body in binary format
    parser = XMLParser.parse(body)
    data = dump_records(parser)

    # Headers
    hdata = '''Content-Type: application/soap+msbin1
Content-Type: application/soap+msbin1
x-ms-aadmsods-apiaction: Provision2
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
    logging.debug(records)
    if res.status_code == 200:
        logging.info('Modification OK')
    else:
        logging.error('Received an error from the provisiong service:')
        print(records)

if __name__ == '__main__':
    main()
