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
from __future__ import absolute_import, print_function, unicode_literals

from builtins import str
import sys
import logging

log = logging.getLogger(__name__)

from lib.wcf.records.base import *
from lib.wcf.records.text import *
from lib.wcf.records.attributes import *
from lib.wcf.records.elements import *

def print_records(records, skip=0, fp=None, first_call=True):
    """prints the given record tree into a file like object
    
    :param records: a tree of record objects
    :type records: wcf.records.Record
    :param skip: start value for intending (Default: 0)
    :type skip: int
    :param fp: file like object to print to (Default: sys.stdout)
    
    """
    if records == None:
        return
    if fp == None:
        fp = sys.stdout

    was_el = False
    for r in records:
        if isinstance(r, EndElementRecord):
            continue
        if isinstance(r, Element):
            fp.write(('\n' if not first_call else '') + ' ' * skip + str(r))
        else:
            # Try escaped variant for text first
            try:
                fp.write(r.escaped())
            except AttributeError:
                fp.write(str(r))
       
        new_line = False
        if hasattr(r, 'childs'):
            new_line = print_records(r.childs, skip+1, fp, False)
        if isinstance(r, Element):
            if new_line:
                fp.write('\n' + ' ' * skip)
            if hasattr(r, 'prefix'):
                fp.write('</%s:%s>' % (r.prefix, r.name))
            else:
                fp.write('</%s>' % r.name)
            was_el = True
        else:
            was_el = False
    return was_el

def repr_records(records, skip=0):
    if records == None:
        return

    for r in records:
        print(' '*skip + str(r))
        if hasattr(r, 'childs'):
            repr_records(r.childs, skip+1)

def dump_records(records):
    """
    returns the byte representation of a given record tree

    :param records: the record tree
    :type records: wcf.records.Record
    :returns: a bytestring
    :rtype: str|bytes
    """
    out = b''

    for r in records:
        msg = 'Write %s' % type(r).__name__
        if r == records[-1]:
            if isinstance(r, Text):
                r.type = r.type + 1
                msg += ' with EndElement (0x%X)' % r.type
        log.debug(msg)
        log.debug('Value %s' % str(r))
        if isinstance(r, Element) and not isinstance(r, EndElementRecord) and len(r.attributes):
            log.debug(' Attributes:')
            for a in r.attributes:
                log.debug(' %s: %s' % (type(a).__name__, str(a)))
        out += r.to_bytes()
        
        if hasattr(r, 'childs'):
            out += dump_records(r.childs)
            if len(r.childs) == 0 or not isinstance(r.childs[-1], Text):
                log.debug('Write EndElement for %s' % r.name)
                out += EndElementRecord().to_bytes()
        elif isinstance(r, Element) and not isinstance(r, EndElementRecord):
            log.debug('Write EndElement for %s' % (r.name,))
            out += EndElementRecord().to_bytes()

    return out
