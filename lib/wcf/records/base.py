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

from builtins import str, bytes

import struct
import logging

from lib.wcf.datatypes import *

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class Record(object):
    records = dict()

    @classmethod
    def add_records(cls, records):
        """adds records to the lookup table

        :param records: list of Record subclasses
        :type records: list(Record)
        """
        for r in records:
            Record.records[r.type] = r

    def __init__(self, type=None):
        if type:
            self.type = type

    def to_bytes(self):
        """
        Generates the representing bytes of the record

        >>> from lib.wcf.records import *
        >>> Record(0xff).to_bytes()
        b'\\xff'
        >>> ElementRecord('a', 'test').to_bytes()
        b'A\\x01a\\x04test'
        """
        return bytes(struct.pack(b'<B', self.type))

    def __repr__(self):
        args = ['type=0x%X' % self.type]
        return '<%s(%s)>' % (type(self).__name__, ','.join(args))

    @classmethod
    def parse(cls, fp):
        """
        Parses the binary data from fp into Record objects

        :param fp: file like object to read from
        :returns: a root Record object with its child Records
        :rtype: Record

        >>> from lib.wcf.records import *
        >>> from io import BytesIO
        >>> buf = BytesIO(b'A\\x01a\\x04test\\x01')
        >>> r = Record.parse(buf)
        >>> r
        [<ElementRecord(type=0x41)>]
        >>> str(r[0])
        '<a:test>'
        >>> dump_records(r)
        b'A\\x01a\\x04test\\x01'
        >>> _ = print_records(r)
        <a:test></a:test>
        """
        if cls != Record:
            return cls()
        root = []
        records = root
        parents = []
        last_el = None
        type = True
        while type:
            type = fp.read(1)
            if type:
                type = struct.unpack(b'<B', type)[0]
                if type in Record.records:
                    log.debug('%s found' % Record.records[type].__name__)
                    obj = Record.records[type].parse(fp)
                    if isinstance(obj, EndElementRecord):
                        if len(parents) > 0:
                            records = parents.pop()
                        #records.append(obj)
                    elif isinstance(obj, Element):
                        last_el = obj
                        records.append(obj)
                        parents.append(records)
                        obj.childs = []
                        records = obj.childs
                    elif isinstance(obj, Attribute) and last_el:
                        last_el.attributes.append(obj)
                    else:
                        records.append(obj)
                    log.debug('Value: %s' % str(obj))
                elif type-1 in Record.records:
                    log.debug('%s with end element found (0x%x)' %
                            (Record.records[type-1].__name__, type))
                    records.append(Record.records[type-1].parse(fp))
                    #records.append(EndElementRecord())
                    last_el = None
                    if len(parents) > 0:
                        records = parents.pop()
                else:
                    log.warn('type 0x%x not found' % type)

        return root


class Element(Record):
    pass


class Attribute(Record):
    pass


class Text(Record):
    pass


class EndElementRecord(Element):
    type = 0x01


class CommentRecord(Record):
    type = 0x02

    def __init__(self, comment, *args, **kwargs):
        self.comment = comment

    def to_bytes(self):
        """
        >>> CommentRecord('test').to_bytes()
        b'\\x02\\x04test'
        """
        string = Utf8String(self.comment)

        return bytes(super(CommentRecord, self).to_bytes() +
                     string.to_bytes())

    def __str__(self):
        """
        >>> str(CommentRecord('test'))
        '<!-- test -->'
        """
        return '<!-- %s -->' % self.comment

    @classmethod
    def parse(cls, fp):
        data = Utf8String.parse(fp).value
        return cls(data)


class ArrayRecord(Record):
    type = 0x03

    datatypes = {
        0xB5: ('BoolTextWithEndElement', 1, '?'),
        0x8B: ('Int16TextWithEndElement', 2, 'h'),
        0x8D: ('Int32TextWithEndElement', 4, 'i'),
        0x8F: ('Int64TextWithEndElement', 8, 'q'),
        0x91: ('FloatTextWithEndElement', 4, 'f'),
        0x93: ('DoubleTextWithEndElement', 8, 'd'),
        0x95: ('DecimalTextWithEndElement', 16, ''),
        0x97: ('DateTimeTextWithEndElement', 8, ''),
        0xAF: ('TimeSpanTextWithEndElement', 8, ''),
        0xB1: ('UuidTextWithEndElement', 16, ''),
    }

    def __init__(self, element, data, attributes):
        self.element = element
        self.count = len(data)
        self.data = data
        recordtype = None
        for data in self.data:
            if recordtype is None:
                recordtype = data.type + 1
            else:
                assert recordtype == data.type + 1
        self.recordtype = recordtype
        self.attributes = []

    def to_bytes(self):
        """
        >>> from lib.wcf.records.text import Int32TextRecord
        >>> from lib.wcf.records.elements import ShortElementRecord
        >>> ArrayRecord(ShortElementRecord('item'), [Int32TextRecord(1), Int32TextRecord(2), Int32TextRecord(3)], []).to_bytes()
        b'\\x03@\\x04item\\x01\\x8d\\x03\\x01\\x00\\x00\\x00\\x02\\x00\\x00\\x00\\x03\\x00\\x00\\x00'
        """
        bt = super(ArrayRecord, self).to_bytes()
        bt += self.element.to_bytes()
        for attrib in self.attributes:
            bt += attrib.to_bytes()
        bt += EndElementRecord().to_bytes()
        bt += bytes(struct.pack(b'<B', self.recordtype))
        bt += MultiByteInt31(self.count).to_bytes()
        for data in self.data:
            bt += data.to_bytes()[1:]
        return bytes(bt)

    @classmethod
    def parse(cls, fp):
        """
        >>> from lib.wcf.records import *
        >>> from io import BytesIO
        >>> buf = BytesIO(b'@\\x04item\\x01\\x8d\\x03\\x01\\x00\\x00\\x00\\x02\\x00\\x00\\x00\\x03\\x00\\x00\\x00')
        >>> r = ArrayRecord.parse(buf)
        >>> r
        <ArrayRecord(type=0x3)>
        >>> r.to_bytes()
        b'\\x03@\\x04item\\x01\\x8d\\x03\\x01\\x00\\x00\\x00\\x02\\x00\\x00\\x00\\x03\\x00\\x00\\x00'
        """
        element = struct.unpack(b'<B', fp.read(1))[0]
        element = Record.records[element].parse(fp)
        attributes = []
        while True:
            type = struct.unpack(b'<B', fp.read(1))[0]
            obj = Record.records[type].parse(fp)
            if isinstance(obj, EndElementRecord):
                break
            elif isinstance(obj, Attribute):
                attributes.append(obj)
            else:
                raise ValueError('unknown type: %s' % hex(type))
        recordtype = struct.unpack(b'<B', fp.read(1))[0]
        count = MultiByteInt31.parse(fp).value
        data = []
        for i in range(count):
            data.append(Record.records[recordtype-1].parse(fp))
        return cls(element, data, attributes)

    def __str__(self):
        """
        >>> from lib.wcf.records.elements import ShortElementRecord
        >>> from lib.wcf.records.text import Int32TextRecord
        >>> str(ArrayRecord(ShortElementRecord('item'), [Int32TextRecord(1), Int32TextRecord(2), Int32TextRecord(3)], []))
        '<item>1</item><item>2</item><item>3</item>'
        """
        string = ''
        for data in self.data:
            string += str(self.element)
            string += str(data)
            string += '</%s>' % self.element.name

        return string

Record.add_records((EndElementRecord,
        CommentRecord,
        ArrayRecord,))
