from pyasn1.codec.der import decoder, encoder
from impacket.krb5.asn1 import AS_REP, EncASRepPart
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum
from impacket.krb5.ccache import CCache
import logging
import binascii
import json
import codecs
import base64

with codecs.open('roadtx.prt','r', 'utf-8') as prtfile:
	data = json.load(prtfile)
ticketdata = json.loads(data['tgt_cloud'])
ticketbin = base64.b64decode(ticketdata['messageBuffer'])
try:
    sessionkey = binascii.unhexlify(data['tgt_cloud_sessionkey'])
except KeyError:
    sessionkey = base64.b64decode(ticketdata['clientKey'])
asRep = decoder.decode(ticketbin, asn1Spec=AS_REP())[0]
# print(asRep)
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

ccache = CCache()
ccache.fromTGT(tgt, key, sessionKey)
ccache.saveFile('tgt_cloud.ccache')

