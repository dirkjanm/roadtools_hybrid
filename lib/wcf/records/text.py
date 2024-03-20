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
from __future__ import absolute_import, unicode_literals, division

from builtins import str, chr, bytes, int
from lib.utils.xml import xmlesc

import struct
import base64
import datetime
import logging
import uuid

try:
    from htmlentitydefs import codepoint2name
except ImportError:
    from html.entities import codepoint2name


def escapecp(cp):
    return '&%s;' % codepoint2name[cp] if (cp in codepoint2name) else chr(cp)


def escape(text):
    newtext = ''
    for c in text:
        newtext += escapecp(ord(c))
    return newtext


log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

from lib.wcf.datatypes import *
from lib.wcf.records.base import *
from lib.wcf.dictionary import dictionary


class ZeroTextRecord(Text):
    type = 0x80

    def __str__(self):
        return '0'

    @classmethod
    def parse(cls, fp):
        return cls()


class OneTextRecord(Text):
    type = 0x82

    def __str__(self):
        return '1'

    @classmethod
    def parse(cls, fp):
        return cls()


class FalseTextRecord(Text):
    type = 0x84

    def __str__(self):
        return 'false'

    @classmethod
    def parse(cls, fp):
        return cls()


class TrueTextRecord(Text):
    type = 0x86

    def __str__(self):
        return 'true'

    @classmethod
    def parse(cls, fp):
        return cls()


class Int8TextRecord(Text):
    type = 0x88

    def __init__(self, value):
        self.value = value

    def to_bytes(self):
        r"""
        >>> Int8TextRecord(42).to_bytes()
        b'\x88*'
        """
        return bytes(super(Int8TextRecord, self).to_bytes() +
                     struct.pack(b'<b', self.value))

    def __str__(self):
        r"""
        >>> str(Int8TextRecord(42))
        '42'
        """
        return str(self.value)

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\xff')
        >>> Int8TextRecord.parse(fp).value
        -1
        """
        return cls(struct.unpack(b'<b', fp.read(1))[0])


class Int16TextRecord(Int8TextRecord):
    type = 0x8A

    def to_bytes(self):
        r"""
        >>> Int16TextRecord(1337).to_bytes()
        b'\x8a9\x05'
        """
        return bytes(struct.pack(b'<B', self.type) +
                     struct.pack(b'<h', self.value))

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\xff\xff')
        >>> Int16TextRecord.parse(fp).value
        -1
        """
        return cls(struct.unpack(b'<h', fp.read(2))[0])


class Int32TextRecord(Int8TextRecord):
    type = 0x8C

    def to_bytes(self):
        r"""
        >>> Int32TextRecord(1337).to_bytes()
        b'\x8c9\x05\x00\x00'
        """
        return bytes(struct.pack(b'<B', self.type) +
                     struct.pack(b'<i', self.value))

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\xff\xff\xff\xff')
        >>> Int32TextRecord.parse(fp).value
        -1
        """
        return cls(struct.unpack(b'<i', fp.read(4))[0])


class Int64TextRecord(Int8TextRecord):
    type = 0x8E

    def to_bytes(self):
        r"""
        >>> Int64TextRecord(1337).to_bytes()
        b'\x8e9\x05\x00\x00\x00\x00\x00\x00'
        """
        return bytes(struct.pack(b'<B', self.type) +
                     struct.pack(b'<q', self.value))

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\xff\xff\xff\xff\xff\xff\xff\xff')
        >>> Int64TextRecord.parse(fp).value
        -1
        """
        return cls(struct.unpack(b'<q', fp.read(8))[0])


class UInt64TextRecord(Int64TextRecord):
    type = 0xB2

    def to_bytes(self):
        r"""
        >>> UInt64TextRecord(1337).to_bytes()
        b'\xb29\x05\x00\x00\x00\x00\x00\x00'
        """
        return bytes(struct.pack(b'<B', self.type) +
                     struct.pack(b'<Q', self.value))

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\xff\xff\xff\xff\xff\xff\xff\xff')
        >>> int(UInt64TextRecord.parse(fp).value)
        18446744073709551615
        """
        return cls(struct.unpack(b'<Q', fp.read(8))[0])


class BoolTextRecord(Text):
    type = 0xB4

    def __init__(self, value):
        self.value = value

    def to_bytes(self):
        r"""
        >>> BoolTextRecord(True).to_bytes()
        b'\xb4\x01'
        >>> BoolTextRecord(False).to_bytes()
        b'\xb4\x00'
        """
        return bytes(struct.pack(b'<B', self.type) +
                     struct.pack(b'<B', 1 if self.value else 0))

    def __str__(self):
        r"""
        >>> str(BoolTextRecord(True))
        'True'
        """
        return str(self.value)

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x01')
        >>> BoolTextRecord.parse(fp).value
        True
        """
        value = True if struct.unpack(b'<B', fp.read(1))[0] == 1 else False
        return cls(value)


class UnicodeChars8TextRecord(Text):
    type = 0xB6

    def __init__(self, string):
        if isinstance(string, str):
            self.value = string
        else:
            self.value = str(string)

    def to_bytes(self):
        """
        >>> UnicodeChars8TextRecord('abc').to_bytes()
        b'\\xb6\\x06a\\x00b\\x00c\\x00'
        >>> UnicodeChars8TextRecord(u'abc').to_bytes()
        b'\\xb6\\x06a\\x00b\\x00c\\x00'
        """
        data = self.value.encode('utf-16')[2:]  # skip bom
        bt = struct.pack(b'<B', self.type)
        bt += struct.pack(b'<B', len(data))
        bt += data
        return bytes(bt)

    def __str__(self):
        r"""
        >>> str(UnicodeChars8TextRecord('abc'))
        'abc'
        """
        return self.value

    def escaped(self):
        return xmlesc(self.value)

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x06a\\x00b\\x00c\\x00')
        >>> str(UnicodeChars8TextRecord.parse(fp))
        'abc'
        """
        ln = struct.unpack(b'<B', fp.read(1))[0]
        data = fp.read(ln)
        return cls(data.decode('utf-16'))


class UnicodeChars16TextRecord(UnicodeChars8TextRecord):
    type = 0xB8

    def to_bytes(self):
        """
        >>> UnicodeChars16TextRecord('abc').to_bytes()
        b'\\xb8\\x06\\x00a\\x00b\\x00c\\x00'
        >>> UnicodeChars16TextRecord(u'abc').to_bytes()
        b'\\xb8\\x06\\x00a\\x00b\\x00c\\x00'
        """
        data = self.value.encode('utf-16')[2:]  # skip bom
        bt = struct.pack(b'<B', self.type)
        bt += struct.pack(b'<H', len(data))
        bt += data
        return bytes(bt)

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x06\\x00a\\x00b\\x00c\\x00')
        >>> str(UnicodeChars16TextRecord.parse(fp))
        'abc'
        """
        ln = struct.unpack(b'<H', fp.read(2))[0]
        data = fp.read(ln)
        return cls(data.decode('utf-16'))


class UnicodeChars32TextRecord(UnicodeChars8TextRecord):
    type = 0xBA

    def to_bytes(self):
        """
        >>> UnicodeChars32TextRecord('abc').to_bytes()
        b'\\xba\\x06\\x00\\x00\\x00a\\x00b\\x00c\\x00'
        >>> UnicodeChars32TextRecord(u'abc').to_bytes()
        b'\\xba\\x06\\x00\\x00\\x00a\\x00b\\x00c\\x00'
        """
        data = self.value.encode('utf-16')[2:]  # skip bom
        bt = struct.pack(b'<B', self.type)
        bt += struct.pack(b'<I', len(data))
        bt += data
        return bytes(bt)

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x06\\x00\\x00\\x00a\\x00b\\x00c\\x00')
        >>> str(UnicodeChars32TextRecord.parse(fp))
        'abc'
        """
        ln = struct.unpack(b'<I', fp.read(4))[0]
        data = fp.read(ln)
        return cls(data.decode('utf-16'))


class QNameDictionaryTextRecord(Text):
    type = 0xBC

    def __init__(self, prefix, index):
        self.prefix = prefix
        self.index = index

    def to_bytes(self):
        """
        >>> QNameDictionaryTextRecord('b', 2).to_bytes()
        b'\\xbc\\x01\\x00\\x00\\x02'
        """
        bt = struct.pack(b'<B', self.type)
        bt += struct.pack(b'<B', ord(self.prefix) - ord('a'))
        bt += MultiByteInt31(self.index).to_bytes()
        return bytes(bt)

    def __str__(self):
        """
        >>> str(QNameDictionaryTextRecord('b', 2))
        'b:Envelope'
        """
        return '%s:%s' % (self.prefix, dictionary[self.index])

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x01\\x00\\x00\\x02')
        >>> str(QNameDictionaryTextRecord.parse(fp))
        'b:Envelope'
        """
        prefix = chr(struct.unpack(b'<B', fp.read(1))[0] + ord('a'))
        index = MultiByteInt31.parse(fp).value
        return cls(prefix, index)


class FloatTextRecord(Text):
    type = 0x90

    def __init__(self, value):
        self.value = value

    def to_bytes(self):
        r"""
        >>> FloatTextRecord(1.337).to_bytes()
        b'\x90\xd1"\xab?'
        """
        bt = super(FloatTextRecord, self).to_bytes()
        bt += struct.pack(b'<f', self.value)
        return bytes(bt)

    def __str__(self):
        """
        >>> str(FloatTextRecord(float('-inf')))
        '-INF'
        >>> str(FloatTextRecord(-0.0))
        '-0'
        >>> str(FloatTextRecord(1.337))
        '1.337'
        """
        try:
            if self.value == int(self.value):
                return '%.0f' % self.value
            else:
                return str(self.value)
        except:
            return str(self.value).upper()

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\xd1"\xab?')
        >>> FloatTextRecord.parse(fp).value
        1.3370000123977661
        """
        value = struct.unpack(b'<f', fp.read(4))[0]
        return cls(value)


class DoubleTextRecord(FloatTextRecord):
    type = 0x92

    def __init__(self, value):
        self.value = value

    def to_bytes(self):
        r"""
        >>> DoubleTextRecord(1.337).to_bytes()
        b'\x921\x08\xac\x1cZd\xf5?'
        """
        bt = super(FloatTextRecord, self).to_bytes()
        bt += struct.pack(b'<d', self.value)
        return bytes(bt)

    def __str__(self):
        """
        >>> str(DoubleTextRecord(float('-inf')))
        '-INF'
        >>> str(DoubleTextRecord(-0.0))
        '-0'
        >>> str(DoubleTextRecord(1.337))
        '1.337'
        """
        super_self = super(DoubleTextRecord, self)
        if hasattr(super_self, '__unicode__'):
            # PY3
            return super_self.__unicode__()
        else:
            # PY2
            return super_self.__str__()

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'1\x08\xac\x1cZd\xf5?')
        >>> DoubleTextRecord.parse(fp).value
        1.337
        """
        value = struct.unpack(b'<d', fp.read(8))[0]
        return cls(value)


class DecimalTextRecord(Text):
    type = 0x94

    def __init__(self, value):
        self.value = value

    def __str__(self):
        r"""
        >>> str(DecimalTextRecord(Decimal(False, 0, 1337, 3)))
        '1.337'
        """
        return str(self.value)

    def to_bytes(self):
        r"""
        >>> DecimalTextRecord(Decimal(False, 0, 1337, 3)).to_bytes()
        b'\x94\x00\x00\x03\x00\x00\x00\x00\x009\x05\x00\x00\x00\x00\x00\x00'
        """
        return bytes(super(DecimalTextRecord, self).to_bytes() +
                     self.value.to_bytes())

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x00\x00\x03\x00\x00\x00\x00\x009\x05\x00\x00\x00\x00\x00\x00')
        >>> str(DecimalTextRecord.parse(fp))
        '1.337'
        """
        value = Decimal.parse(fp)
        return cls(value)


class DatetimeTextRecord(Text):
    type = 0x96

    def __init__(self, value, tz):
        self.value = value
        self.tz = tz

    def __str__(self):
        """
        >>> str(DatetimeTextRecord(621355968000000000,0))
        '1970-01-01T00:00:00'
        >>> str(DatetimeTextRecord(0,0))
        '0001-01-01T00:00:00'
        """
        ticks = self.value
        dt = (datetime.datetime(1, 1, 1) +
              datetime.timedelta(microseconds=ticks // 10))
        return dt.isoformat()

    def to_bytes(self):
        """
        >>> str(''.join('%02X' % i for i in DatetimeTextRecord(632834208000000000, 0).to_bytes()))
        '9600408EF95B47C808'
        >>> str(''.join('%02X' % i for i in DatetimeTextRecord(632834208000000000, 2).to_bytes()))
        '9600408EF95B47C888'
        """
        bt = super(DatetimeTextRecord, self).to_bytes()
        bt += struct.pack(
            '<Q',
            ((self.tz & 3) << 62) | (self.value & 0x3FFFFFFFFFFFFFFF))

        return bytes(bt)

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\xFF\\x3F\\x37\\xF4\\x75\\x28\\xCA\\x2B')
        >>> str(DatetimeTextRecord.parse(fp))
        '9999-12-31T23:59:59.999999'
        >>> fp = BytesIO(b'\\x00\\x40\\x8E\\xF9\\x5B\\x47\\xC8\\x08')
        >>> str(DatetimeTextRecord.parse(fp))
        '2006-05-17T00:00:00'
        """
        data = struct.unpack(b'<Q', fp.read(8))[0]
        tz = data >> 62
        value = data & 0x3FFFFFFFFFFFFFFF

        return DatetimeTextRecord(value, tz)


class Chars8TextRecord(Text):
    type = 0x98

    def __init__(self, value):
        if isinstance(value, str):
            self.value = value
        else:
            self.value = str(value)

    def __str__(self):
        r"""
        >>> str(Chars8TextRecord("abc"))
        'abc'
        >>> str(Chars8TextRecord("a<b>c>>&'\""))
        "a&lt;b&gt;c&gt;&gt;&amp;'&quot;"
        """
        return self.value

    def escaped(self):
        return xmlesc(self.value)

    def to_bytes(self):
        r"""
        >>> Chars8TextRecord('abc').to_bytes()
        b'\x98\x03abc'
        """
        data = self.value.encode('utf-8')
        bt = struct.pack(b'<B', self.type)
        bt += struct.pack(b'<B', len(data))
        bt += data

        return bytes(bt)

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x04test')
        >>> str(Chars8TextRecord.parse(fp))
        'test'
        """
        ln = struct.unpack(b'<B', fp.read(1))[0]
        value = fp.read(ln).decode('utf-8')
        return cls(value)


class Chars16TextRecord(Chars8TextRecord):
    type = 0x9A

    def to_bytes(self):
        r"""
        >>> Chars16TextRecord('abc').to_bytes()
        b'\x9a\x03\x00abc'
        """
        data = self.value.encode('utf-8')
        bt = struct.pack(b'<B', self.type)
        bt += struct.pack(b'<H', len(data))
        bt += data

        return bytes(bt)

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x04\x00test')
        >>> str(Chars16TextRecord.parse(fp))
        'test'
        """
        ln = struct.unpack(b'<H', fp.read(2))[0]
        value = fp.read(ln).decode('utf-8')
        return cls(value)


class Chars32TextRecord(Chars8TextRecord):
    type = 0x9C

    def to_bytes(self):
        r"""
        >>> Chars32TextRecord('abc').to_bytes()
        b'\x9c\x03\x00\x00\x00abc'
        """
        data = self.value.encode('utf-8')
        bt = struct.pack(b'<B', self.type)
        bt += struct.pack(b'<I', len(data))
        bt += data

        return bytes(bt)

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x04\x00\x00\x00test')
        >>> str(Chars32TextRecord.parse(fp))
        'test'
        """
        ln = struct.unpack(b'<I', fp.read(4))[0]
        value = fp.read(ln).decode('utf-8')
        return cls(value)


class UniqueIdTextRecord(Text):
    type = 0xAC

    def __init__(self, *args, **kwargs):
        self.uuid = uuid.UUID(*args, **kwargs)

    def to_bytes(self):
        """
        >>> UniqueIdTextRecord('urn:uuid:33221100-5544-7766-8899-aabbccddeeff').to_bytes()
        b'\\xac\\x00\\x11"3DUfw\\x88\\x99\\xaa\\xbb\\xcc\\xdd\\xee\\xff'
        """
        bt = super(UniqueIdTextRecord, self).to_bytes()
        bt += self.uuid.bytes_le

        return bytes(bt)

    def __str__(self):
        r"""
        >>> str(UniqueIdTextRecord('urn:uuid:33221100-5544-7766-8899-aabbccddeeff'))
        'urn:uuid:33221100-5544-7766-8899-aabbccddeeff'
        """
        return self.uuid.urn

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x00\x11"3DUfw\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        >>> str(UniqueIdTextRecord.parse(fp))
        'urn:uuid:33221100-5544-7766-8899-aabbccddeeff'
        """
        u = fp.read(16)

        return cls(bytes_le=u)


class UuidTextRecord(UniqueIdTextRecord):
    type = 0xB0

    def __str__(self):
        """
        >>> str(UuidTextRecord('urn:uuid:33221100-5544-7766-8899-aabbccddeeff'))
        '33221100-5544-7766-8899-aabbccddeeff'
        """
        return str(self.uuid)


class Bytes8TextRecord(Text):
    type = 0x9E

    def __init__(self, data):
        self.value = data

    def to_bytes(self):
        r"""
        >>> Bytes8TextRecord(b'abc').to_bytes()
        b'\x9e\x03abc'
        """
        bt = struct.pack(b'<B', self.type)
        bt += struct.pack(b'<B', len(self.value))
        bt += self.value

        return bytes(bt)

    def __str__(self):
        r"""
        >>> str(Bytes8TextRecord(b'abc'))
        'YWJj'
        """
        return base64.b64encode(self.value).decode()

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x03abc')
        >>> bytes(Bytes8TextRecord.parse(fp).value)
        b'abc'
        """
        ln = struct.unpack(b'<B', fp.read(1))[0]
        data = struct.unpack(('%ds' % ln).encode(), fp.read(ln))[0]
        return cls(data)


class Bytes16TextRecord(Bytes8TextRecord):
    type = 0xA0

    def __init__(self, data):
        super(Bytes16TextRecord, self).__init__(data)

    def to_bytes(self):
        r"""
        >>> Bytes16TextRecord(b'abc').to_bytes()
        b'\xa0\x03\x00abc'
        """
        bt = struct.pack(b'<B', self.type)
        bt += struct.pack(b'<H', len(self.value))
        bt += self.value

        return bytes(bt)

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x03\x00abc')
        >>> bytes(Bytes16TextRecord.parse(fp).value)
        b'abc'
        """
        ln = struct.unpack(b'<H', fp.read(2))[0]
        data = struct.unpack(('%ds' % ln).encode(), fp.read(ln))[0]
        return cls(data)


class Bytes32TextRecord(Bytes8TextRecord):
    type = 0xA2

    def __init__(self, data):
        super(Bytes32TextRecord, self).__init__(data)

    def to_bytes(self):
        r"""
        >>> Bytes32TextRecord(b'abc').to_bytes()
        b'\xa2\x03\x00\x00\x00abc'
        """
        bt = struct.pack(b'<B', self.type)
        bt += struct.pack(b'<I', len(self.value))
        bt += self.value

        return bytes(bt)

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x03\x00\x00\x00abc')
        >>> bytes(Bytes32TextRecord.parse(fp).value)
        b'abc'
        """
        ln = struct.unpack(b'<I', fp.read(4))[0]
        data = struct.unpack(('%ds' % ln).encode(), fp.read(ln))[0]
        return cls(data)


class StartListTextRecord(Text):
    type = 0xA4


class EndListTextRecord(Text):
    type = 0xA6


class EmptyTextRecord(Text):
    type = 0xA8


class TimeSpanTextRecord(Text):
    type = 0xAE

    def __init__(self, value):
        self.value = value

    def to_bytes(self):
        r"""
        >>> TimeSpanTextRecord(36000000).to_bytes()
        b'\xae\x00Q%\x02\x00\x00\x00\x00'
        """
        return bytes(super(TimeSpanTextRecord, self).to_bytes() +
                     struct.pack(b'<q', self.value))

    def __str__(self):
        return str(datetime.timedelta(milliseconds=self.value/10))

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x00Q%\x02\x00\x00\x00\x00')
        >>> str(TimeSpanTextRecord.parse(fp))
        '1:00:00'
        """
        value = struct.unpack(b'<q', fp.read(8))[0]
        return cls(value)


class DictionaryTextRecord(Text):
    type = 0xAA

    def __init__(self, index):
        self.index = index

    def to_bytes(self):
        r"""
        >>> DictionaryTextRecord(2).to_bytes()
        b'\xaa\x02'
        """
        return bytes(super(DictionaryTextRecord, self).to_bytes() +
                     MultiByteInt31(self.index).to_bytes())

    def __str__(self):
        r"""
        >>> str(DictionaryTextRecord(2))
        'Envelope'
        """
        return dictionary[self.index]

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x02')
        >>> str(DictionaryTextRecord.parse(fp))
        'Envelope'
        """
        index = MultiByteInt31.parse(fp).value
        return cls(index)

Record.add_records((ZeroTextRecord,
                    OneTextRecord,
                    FalseTextRecord,
                    TrueTextRecord,
                    Int8TextRecord,
                    Int16TextRecord,
                    Int32TextRecord,
                    Int64TextRecord,
                    UInt64TextRecord,
                    BoolTextRecord,
                    UnicodeChars8TextRecord,
                    UnicodeChars16TextRecord,
                    UnicodeChars32TextRecord,
                    QNameDictionaryTextRecord,
                    FloatTextRecord,
                    DoubleTextRecord,
                    DecimalTextRecord,
                    DatetimeTextRecord,
                    Chars8TextRecord,
                    Chars16TextRecord,
                    Chars32TextRecord,
                    UniqueIdTextRecord,
                    UuidTextRecord,
                    Bytes8TextRecord,
                    Bytes16TextRecord,
                    Bytes32TextRecord,
                    StartListTextRecord,
                    EndListTextRecord,
                    EmptyTextRecord,
                    TimeSpanTextRecord,
                    DictionaryTextRecord,))
