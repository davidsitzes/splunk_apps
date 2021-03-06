# -*- coding: utf-8 -*-
"""
    markupsafe._compat
    ~~~~~~~~~~~~~~~~~~

    Compatibility module for different Python versions.

    :copyright: (c) 2013 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import sys
import six

PY2 = sys.version_info[0] == 2

if not PY2:
    text_type = str
    string_types = (str,)
    unichr = chr
    int_types = (int,)
    iteritems = lambda x: iter(list(x.items()))
else:
    text_type = six.text_type
    string_types = (str, six.text_type)
    unichr = unichr
    int_types = six.integer_types
    iteritems = lambda x: iter(list(x.items()))
    #iteritems = lambda x: iter(x.items())
#else:
#    text_type = unicode
#    string_types = (str, unicode)
#    unichr = unichr
#    int_types = (int, long)
#    iteritems = lambda x: x.iteritems()
