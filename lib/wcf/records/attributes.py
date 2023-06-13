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
from __future__ import absolute_import
from __future__ import unicode_literals

try:
    import __builtin__  # noqa
    is_py2 = True
except ImportError:
    is_py2 = False
from builtins import str, chr, bytes

import struct
import logging
import sys

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

from lib.wcf.datatypes import *
from lib.wcf.records.base import *
from lib.wcf.records.text import *
from lib.wcf.dictionary import dictionary


class ShortAttributeRecord(Attribute):
    type = 0x04

    def __init__(self, name, value):
        self.name = name
        self.value = value

    def to_bytes(self):
        """
        >>> ShortAttributeRecord('test', TrueTextRecord()).to_bytes()
        b'\\x04\\x04test\\x86'
        """
        bt = super(ShortAttributeRecord, self).to_bytes()
        bt += Utf8String(self.name).to_bytes()
        bt += self.value.to_bytes()

        return bytes(bt)

    def __str__(self):
        return '%s="%s"' % (self.name, str(self.value))

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x04test\\x86')
        >>> sar = ShortAttributeRecord.parse(fp)
        >>> str(sar.name)
        'test'
        >>> sar.value
        <TrueTextRecord(type=0x86)>
        """
        name = Utf8String.parse(fp).value
        type = struct.unpack(b'<B', fp.read(1))[0]
        value = Record.records[type].parse(fp)

        return cls(name, value)


class AttributeRecord(Attribute):
    type = 0x05

    def __init__(self, prefix, name, value):
        self.prefix = prefix
        self.name = name
        self.value = value

    def to_bytes(self):
        """
        >>> AttributeRecord('x', 'test', TrueTextRecord()).to_bytes()
        b'\\x05\\x01x\\x04test\\x86'
        """
        bt = super(AttributeRecord, self).to_bytes()
        bt += Utf8String(self.prefix).to_bytes()
        bt += Utf8String(self.name).to_bytes()
        bt += self.value.to_bytes()

        return bytes(bt)

    def __str__(self):
        return '%s:%s="%s"' % (self.prefix, self.name, str(self.value))

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x01x\\x04test\\x86')
        >>> ar = AttributeRecord.parse(fp)
        >>> str(ar.prefix)
        'x'
        >>> str(ar.name)
        'test'
        >>> ar.value
        <TrueTextRecord(type=0x86)>
        """
        prefix = Utf8String.parse(fp).value
        name   = Utf8String.parse(fp).value
        type   = struct.unpack(b'<B', fp.read(1))[0]
        value  = Record.records[type].parse(fp)

        return cls(prefix, name, value)


class ShortDictionaryAttributeRecord(Attribute):
    type = 0x06

    def __init__(self, index, value):
        self.index = index
        self.value = value

    def to_bytes(self):
        """
        >>> ShortDictionaryAttributeRecord(3, TrueTextRecord()).to_bytes()
        b'\\x06\\x03\\x86'
        """
        bt = super(ShortDictionaryAttributeRecord, self).to_bytes()
        bt += MultiByteInt31(self.index).to_bytes()
        bt += self.value.to_bytes()

        return bytes(bt)

    def __str__(self):
        return '%s="%s"' % (dictionary[self.index], str(self.value))

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x0c\\x86')
        >>> sdar = ShortDictionaryAttributeRecord.parse(fp)
        >>> sdar.index
        12
        >>> sdar.value
        <TrueTextRecord(type=0x86)>
        >>> str(sdar)
        'To="true"'
        """
        index = MultiByteInt31.parse(fp).value
        type  = struct.unpack(b'<B', fp.read(1))[0]
        value = Record.records[type].parse(fp)

        return cls(index, value)


class DictionaryAttributeRecord(Attribute):
    type = 0x07

    def __init__(self, prefix, index, value):
        self.prefix = prefix
        self.index = index
        self.value = value

    def to_bytes(self):
        """
        >>> DictionaryAttributeRecord('x', 2, TrueTextRecord()).to_bytes()
        b'\\x07\\x01x\\x02\\x86'
        """
        bt = super(DictionaryAttributeRecord, self).to_bytes()
        bt += Utf8String(self.prefix).to_bytes()
        bt += MultiByteInt31(self.index).to_bytes()
        bt += self.value.to_bytes()

        return bytes(bt)

    def __str__(self):
        return '%s:%s="%s"' % (self.prefix, dictionary[self.index],
                str(self.value))

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x01x\\x02\\x86')
        >>> dar = DictionaryAttributeRecord.parse(fp)
        >>> str(dar.prefix)
        'x'
        >>> dar.index
        2
        >>> str(dar.value)
        'true'
        """
        prefix = Utf8String.parse(fp).value
        index = MultiByteInt31.parse(fp).value
        type  = struct.unpack(b'<B', fp.read(1))[0]
        value = Record.records[type].parse(fp)

        return cls(prefix, index, value)


class ShortDictionaryXmlnsAttributeRecord(Attribute):
    type = 0x0A

    def __init__(self, index):
        self.index = index

    def __str__(self):
        return 'xmlns="%s"' % (dictionary[self.index],)

    def to_bytes(self):
        """
        >>> ShortDictionaryXmlnsAttributeRecord(6).to_bytes()
        b'\\n\\x06'
        """
        bt = struct.pack(b'<B', self.type)
        bt += MultiByteInt31(self.index).to_bytes()

        return bytes(bt)

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x06')
        >>> sdxar = ShortDictionaryXmlnsAttributeRecord.parse(fp)
        >>> sdxar.index
        6
        >>> str(sdxar)
        'xmlns="http://www.w3.org/2005/08/addressing"'
        """
        index = MultiByteInt31.parse(fp).value
        return cls(index)


class DictionaryXmlnsAttributeRecord(Attribute):
    type = 0x0B

    def __init__(self, prefix, index):
        self.prefix = prefix
        self.index = index

    def __str__(self):
        return 'xmlns:%s="%s"' % (self.prefix, dictionary[self.index])

    def to_bytes(self):
        """
        >>> DictionaryXmlnsAttributeRecord('a', 6).to_bytes()
        b'\\x0b\\x01\x61\\x06'
        """
        bt = struct.pack(b'<B', self.type)
        bt += Utf8String(self.prefix).to_bytes()
        bt += MultiByteInt31(self.index).to_bytes()

        return bytes(bt)

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x01a\\x06')
        >>> dxar = DictionaryXmlnsAttributeRecord.parse(fp)
        >>> str(dxar.prefix)
        'a'
        >>> dxar.index
        6
        >>> str(dxar)
        'xmlns:a="http://www.w3.org/2005/08/addressing"'
        """
        prefix = Utf8String.parse(fp).value
        index = MultiByteInt31.parse(fp).value
        return cls(prefix, index)


class ShortXmlnsAttributeRecord(Attribute):
    type = 0x08

    def __init__(self, value, *args, **kwargs):
        super(ShortXmlnsAttributeRecord, self).__init__(*args, **kwargs)
        self.value = value

    def to_bytes(self):
        """
        >>> ShortXmlnsAttributeRecord('test').to_bytes()
        b'\\x08\\x04test'
        """
        bt = struct.pack(b'<B', self.type)
        bt += Utf8String(self.value).to_bytes()
        return bytes(bt)

    def __str__(self):
        return 'xmlns="%s"' % (self.value,)

    @classmethod
    def parse(cls, fp):
        """
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\\x04test')
        >>> sxar = ShortXmlnsAttributeRecord.parse(fp)
        >>> str(sxar)
        'xmlns="test"'
        """
        value = Utf8String.parse(fp).value
        return cls(value)


class XmlnsAttributeRecord(Attribute):
    type = 0x09

    def __init__(self, name, value, *args, **kwargs):
        super(XmlnsAttributeRecord, self).__init__(*args, **kwargs)
        self.name = name
        self.value = value

    def to_bytes(self):
        """
        >>> XmlnsAttributeRecord('name', 'value').to_bytes()
        b'\\t\\x04name\\x05value'
        """
        bt = struct.pack(b'<B', self.type)
        bt += Utf8String(self.name).to_bytes()
        bt += Utf8String(self.value).to_bytes()
        return bytes(bt)

    def __str__(self):
        return 'xmlns:%s="%s"' % (self.name, self.value)

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x04name\x05value')
        >>> str(XmlnsAttributeRecord.parse(fp))
        'xmlns:name="value"'
        """
        name = Utf8String.parse(fp).value
        value = Utf8String.parse(fp).value
        return cls(name, value)


class PrefixAttributeRecord(AttributeRecord):
    def __init__(self, name, value):
        super(PrefixAttributeRecord, self).__init__(self.char, name, value)

    def to_bytes(self):
        r"""
        >>> PrefixAttributeARecord('name', TrueTextRecord()).to_bytes()
        b'&\x04name\x86'
        """
        string = Utf8String(self.name)
        return bytes(struct.pack(b'<B', self.type) + string.to_bytes() +
                     self.value.to_bytes())

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\x04name\x86')
        >>> paar = PrefixAttributeARecord.parse(fp)
        >>> str(paar)
        'a:name="true"'
        """
        name = Utf8String.parse(fp).value
        type = struct.unpack(b'<B', fp.read(1))[0]
        value= Record.records[type].parse(fp)
        return cls(name, value)


class PrefixDictionaryAttributeRecord(DictionaryAttributeRecord):
    def __init__(self, index, value):
        super(PrefixDictionaryAttributeRecord, self).__init__(self.char,
                                                              index, value)

    def to_bytes(self):
        r"""
        >>> PrefixDictionaryAttributeBRecord(2, TrueTextRecord()).to_bytes()
        b'\r\x02\x86'
        """
        idx = MultiByteInt31(self.index)
        return bytes(struct.pack(b'<B', self.type) + idx.to_bytes() +
                     self.value.to_bytes())

    @classmethod
    def parse(cls, fp):
        r"""
        >>> from io import BytesIO
        >>> fp = BytesIO(b'\02\x86')
        >>> pdabr = PrefixDictionaryAttributeBRecord.parse(fp)
        >>> str(pdabr)
        'b:Envelope="true"'
        """
        index = MultiByteInt31.parse(fp).value
        type = struct.unpack(b'<B', fp.read(1))[0]
        value = Record.records[type].parse(fp)
        return cls(index, value)


Record.add_records((
        ShortAttributeRecord,
        AttributeRecord,
        ShortDictionaryAttributeRecord,
        DictionaryAttributeRecord,
        ShortDictionaryXmlnsAttributeRecord,
        DictionaryXmlnsAttributeRecord,
        ShortXmlnsAttributeRecord,
        XmlnsAttributeRecord,
        ))


__module__ = sys.modules[__name__]
__records__ = []
for c in range(0x0C, 0x25 + 1):
    char = chr(c - 0x0C + ord('a'))
    clsname = 'PrefixDictionaryAttribute' + char.upper() + 'Record'
    if is_py2:
        clsname = clsname.encode('latin1')
    cls = type(
           clsname,
           (PrefixDictionaryAttributeRecord,),
           dict(
                type=c,
                char=char,
            )
           )
    setattr(__module__, clsname, cls)
    __records__.append(cls)

for c in range(0x26, 0x3F + 1):
    char = chr(c - 0x26 + ord('a'))
    clsname = 'PrefixAttribute' + char.upper() + 'Record'
    if is_py2:
        clsname = clsname.encode('latin1')
    cls = type(
           clsname,
           (PrefixAttributeRecord,),
           dict(
                type=c,
                char=char,
            )
           )
    setattr(__module__, clsname, cls)
    __records__.append(cls)

Record.add_records(__records__)
del __records__
