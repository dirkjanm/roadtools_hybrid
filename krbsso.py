import struct
import os
import datetime
import base64
import sys
from binascii import unhexlify
from pyasn1.type.univ import noValue
from pyasn1.codec.der import decoder, encoder
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.spnego import ASN1_OID, asn1encode, ASN1_AID, asn1decode
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp, ASN1_OID, asn1encode, ASN1_AID
from impacket.krb5.gssapi import KRB5_AP_REQ, GSS_C_DELEG_FLAG
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, EncTicketPart, AD_IF_RELEVANT, Ticket as TicketAsn1, KRB_CRED, EncKrbCredPart

from impacket.krb5.crypto import Key, _enctype_table, Enctype
from impacket import LOG
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGS
from impacket.krb5.ccache import CCache
from struct import pack, unpack
import logging
def build_auth(ccache):

    thing = struct.pack('B', ASN1_AID) + asn1encode( struct.pack('B', ASN1_OID) + asn1encode(
    TypesMech['KRB5 - Kerberos 5'] ) + KRB5_AP_REQ)

    # Do we have a TGT cached?
    tgt = None
    try:
        ccache = CCache.loadFile(ccache)
        logging.debug("Using Kerberos Cache: %s" % ccache)
        creds = ccache.getCredential('http/autologon.microsoftazuread-sso.com', False)
        if creds is not None:
            TGS = creds.toTGS()
            tgs, cipher, sessionKey = TGS['KDC_REP'], TGS['cipher'], TGS['sessionKey']
            oldSessionKey = sessionKey
            logging.info('Using ST from cache')
        else:
            logging.error("No valid credentials found in cache. ")
            return
    except:
        # No cache present
        logging.error("Cache file not valid or not found")
        return
    blob = SPNEGO_NegTokenInit()

    # Kerberos v5 mech
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5'], TypesMech['KRB5 - Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec = TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = list()
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq,'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = str(tgs['crealm'])

    clientName = Principal()
    clientName.from_asn1( tgs, 'crealm', 'cname')

    seq_set(authenticator, 'cname', clientName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = pack('B', ASN1_AID) + asn1encode(pack('B', ASN1_OID) + asn1encode(
        TypesMech['KRB5 - Kerberos 5']) + KRB5_AP_REQ + encoder.encode(apReq))
    return blob.getData()


def main():
    if len(sys.argv) < 2:
        print('Kerberos Service Ticket to HTTP auth blob for Azure AD Seamless Single Sign On')
        print('Request a service ticket with your favorite tool first, using SPN http/autologon.microsoftazuread-sso.com')
        print('Usage: krbsso.py user.ccache')
        return
    auth = build_auth(sys.argv[1])
    print(base64.b64encode(auth).decode('utf-8'))

if __name__ == '__main__':
    main()
