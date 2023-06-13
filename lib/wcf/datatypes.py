# vim: set ts=4 sw=4 tw=79 fileencoding=utf-8:
#  Copyright (c) 2011, Timo Schmid <tschmid@ernw.de>
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#  * Neither the name of the ERMW GmbH nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from __future__ import unicode_literals

from builtins import str, bytes

import struct
import logging
import sys

log = logging.getLogger(__name__)


class MultiByteInt31(object):

    def __init__(self, *args):
        self.value = args[0] if len(args) else None

    def to_bytes(self):
        """
        >>> MultiByteInt31(268435456).to_bytes()
        b'\\x80\\x80\\x80\\x80\\x01'
        >>> MultiByteInt31(0x7f).to_bytes()
        b'\\x7f'
        >>> MultiByteInt31(0x3fff).to_bytes()
        b'\\xff\\x7f'
        >>> MultiByteInt31(0x1fffff).to_bytes()
        b'\\xff\\xff\\x7f'
        >>> MultiByteInt31(0xfffffff).to_bytes()
        b'\\xff\\xff\\xff\\x7f'
        >>> MultiByteInt31(0x3fffffff).to_bytes()
        b'\\xff\\xff\\xff\\xff\\x03'
        """
        value_a = self.value & 0x7F
        value_b = (self.value >> 7) & 0x7F
        value_c = (self.value >> 14) & 0x7F
        value_d = (self.value >> 21) & 0x7F
        value_e = (self.value >> 28) & 0x03
        if value_e != 0:
            ret = struct.pack(b'<BBBBB',
                              value_a | 0x80,
                              value_b | 0x80,
                              value_c | 0x80,
                              value_d | 0x80,
                              value_e)
        elif value_d != 0:
            ret = struct.pack(b'<BBBB',
                              value_a | 0x80,
                              value_b | 0x80,
                              value_c | 0x80,
                              value_d)
        elif value_c != 0:
            ret = struct.pack(b'<BBB',
                              value_a | 0x80,
                              value_b | 0x80,
                              value_c)
        elif value_b != 0:
            ret = struct.pack(b'<BB',
                              value_a | 0x80,
                              value_b)
        else:
            ret = struct.pack(b'<B',
                              value_a)
        return bytes(ret)

    def __str__(self):
        return str(self.value)

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x7f')
        >>> mb = MultiByteInt31.parse(fp)
        >>> mb.value
        127
        >>> fp = BytesIO(b'\\xff\\x7f')
        >>> mb = MultiByteInt31.parse(fp)
        >>> mb.value
        16383
        >>> fp = BytesIO(b'\\xb9\\x0a')
        >>> mb = MultiByteInt31.parse(fp)
        >>> mb.value
        1337
        """
        v = 0
        # tmp = ''
        for pos in range(4):
            b = fp.read(1)
            if not b:
                break
            # tmp += b
            value = struct.unpack(b'<B', b)[0]
            v |= (value & 0x7F) << 7*pos
            if not value & 0x80:
                break
        # print ('%s => 0x%X' % (repr(tmp), v))

        return cls(v)


class Utf8String(object):

    def __init__(self, *args):
        self.value = args[0] if len(args) else None
        if isinstance(self.value, bytes):
            self.value = str(self.value, 'utf-8')

    def to_bytes(self):
        """
        >>> Utf8String("abc").to_bytes()
        b'\\x03\x61\x62\x63'
        >>> Utf8String("\xfcber").to_bytes()
        b'\\x05\\xc3\\xbcber'
        >>> Utf8String(b"\\xc3\\xbcber".decode('utf-8')).to_bytes()
        b'\\x05\\xc3\\xbcber'
        """
        data = self.value.encode('utf-8')
        strlen = len(data)

        return bytes(MultiByteInt31(strlen).to_bytes() + data)

    def __str__(self):
        return str(self.value)

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b"\\x05\\xc3\\xbcber")
        >>> s = Utf8String.parse(fp)
        >>> s.to_bytes()
        b'\\x05\\xc3\\xbcber'
        >>> print(str(s))
        über
        """
        lngth = struct.unpack(b'<B', fp.read(1))[0]

        return cls(fp.read(lngth).decode('utf-8'))


class Decimal(object):
    def __init__(self, sign, high, low, scale):

        if not 0 <= scale <= 28:
            raise ValueError('scale %d isn\'t between 0 and 28' % scale)
        self.sign = sign
        self.high = high
        self.low = low
        self.scale = scale

    def to_bytes(self):
        """
        >>> Decimal(False, 0, 5123456, 6).to_bytes()
        b'\\x00\\x00\\x06\\x00\\x00\\x00\\x00\\x00\\x80-N\\x00\\x00\\x00\\x00\\x00'
        """
        log.warn('Possible false interpretation')
        bt = struct.pack(b'<H', 0)
        bt += struct.pack(b'<B', self.scale)
        bt += struct.pack(b'<B', 0x80 if self.sign else 0x00)
        bt += struct.pack(b'<I', self.high)
        bt += struct.pack(b'<Q', self.low)

        return bytes(bt)

    def __str__(self):
        """
        >>> str(Decimal(False, 0, 1234, 3))
        '1.234'
        >>> str(Decimal(False, 0, 1234, 1))
        '123.4'
        >>> str(Decimal(True, 0, 1234, 1))
        '-123.4'
        >>> str(Decimal(False, 0, 5123456, 6))
        '5.123456'
        """
        log.warn('Possible false interpretation')
        value = str(self.high * 2**64 + self.low)
        if self.scale > 0:
            value = value[:-self.scale] + '.' + value[-self.scale:]

        if self.sign:
            value = '-%s' % value
        return value

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> buf = BytesIO(b'\\x00\\x00\\x06\\x00\\x00\\x00\\x00\\x00\\x80-N\\x00\\x00\\x00\\x00\\x00')
        >>> str(Decimal.parse(buf))
        '5.123456'
        """
        log.warn('Possible false interpretation')
        fp.read(2)
        scale = struct.unpack(b'<B', fp.read(1))[0]
        sign = struct.unpack(b'<B', fp.read(1))[0] & 0x80
        high = struct.unpack(b'<I', fp.read(4))[0]
        low = struct.unpack(b'<Q', fp.read(8))[0]

        return cls(sign, high, low, scale)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
