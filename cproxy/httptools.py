#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
"""
a set of tools related to HTTP
"""
import email
import email.policy
import io
import chardet
import logging
from sys import maxsize as MAX_INT
_MAXLINE = 65536

policy = email.policy.HTTP.clone(linesep='\r\n')

class HTTPMSG:
    """easily deal with request/response/cache headers

    HTTP Message is identical to email Message except for
    an additional initial line
     - status, reason, response_version for response
     - command, path, requestion for request

    Many methods are wrapppers on email.message.Message's methods
    https://docs.python.org/3.7/library/email.message.html#email.message.EmailMessage
    """
    version_dict = {9: 'HTTP/0.9', 10: 'HTTP/1.0', 11: 'HTTP/1.1'}

    def __init__(self, msg, initial_line):
        self.eheaders = msg
        self._headers = b''
        self._body = b''
        self._body_str = ''
        self.headers_updated = False
        self._initial_line = initial_line

    def build_headers_bytes(self):
        # By default, email Message use the '\n' line separators.
        # we should use the RFC-correct '\r\n' for http headers
        # as_bytes is not reliable as it will generate
        # "User-Agent: Mozilla/5.0 (X11;\r\n Linux x86_64) AppleWebKit/537.36
        # (KHTML,\r\n like Gecko) Chrome/72.0.3626.121 Safari/537.36\r\n"
        # One thing that is hard to understand is:
        # if policy=email.polciy.HTTP is used and there's If-None-Modified header
        # as_string will replace If-None-Modified header with ETag!!!
        self._headers = self._initial_line.encode(
            "iso-8859-1") + self.eheaders.as_string(
                policy=self.eheaders.policy.clone(linesep='\r\n')).encode("iso-8859-1")

    def to_bytes(self):
        return self.get_headers_bytes() + self.get_body_bytes()

    def get_content_charset(self, failobj=None):
        return self.eheaders.get_content_charset(failobj)

    def get_headers_bytes(self):
        '''
        HTTPMessage to  the RFC-correct headers
        :return:
        '''
        if not self._headers or self.headers_updated:
            self.build_headers_bytes()

        return self._headers

    def del_header(self, key):
        del self.eheaders[key]
        self.headers_updated = True

    def get_header(self, key):
        if isinstance(key, str):
            return self.eheaders.get(key.lower(), None)
        raise Exception("parameter should be str")

    def set_header(self, key, value):
        if isinstance(key, str) and isinstance(value, str):
            # TODO should I use self._headers.replace_header() instead
            # see [email.message.Message: Representing an email message using the compat32 API — Python 3.7.2 documentation] # noqa
            # (https://docs.python.org/3/library/email.compat32-message.html#email.message.Message.replace_header)  # noqa
            self.del_header(key)
            self.eheaders[key] = value
            return
        raise Exception("parameter should be str")

    text_format_list = ['text', 'json', 'xml', 'html', 'x-www-form-urlencoded']
    def text_support(self, ctype):
        for fmt in self.text_format_list:
            if fmt in ctype:
                return True
        return False

    def _text(self):
        """convert body to plain text

        should be called after body_bytes is set up
        """
        body_data = self.get_body_bytes()
        if not body_data:
            return
        self.charset = self.get_content_charset()
        if self.charset:
            self._body_str = body_data.decode(self.charset)
        elif len(body_data) > 0 and self.get_header(
                'Content-Type') and self.text_support(
                    self.get_header('Content-Type')):
            # get charset using chardet
            self.charset = chardet.detect(body_data)['encoding']
            if self.charset:
                try:
                    self._body_str = body_data.decode(self.charset)
                except Exception as e:
                    logging.warning('No charset found, '.format(e))
                    self._body_str = body_data
                    self.charset = None
            else:
                self._body_str = body_data
        else:
            self._body_str = body_data
            self.charset = None

    def get_body_str(self):
        if not self._body_str:
            self._text()
        return self._body_str

    def get_body_bytes(self):
        '''
        return http body in bytes
        :return:
        '''
        content_length = self.get_header('Content-Length')
        if content_length and int(content_length) > 0 and not self._body:
            logging.warning("body data hasn't been read from socket or file")
        return self._body


def req_range_parser(range_string):
    """parse request range header
    (all inclusive)
          bytes=0-499
          bytes=500-999
          bytes=9500-

          bytes=-500 (the final 500 bytes)

        return: start, end
    """
    assert ('bytes' in range_string)
    valid_str = range_string.split('=')[1]
    if valid_str[0] == '-':
        start = 0
        end = valid_str
    else:
        parts = valid_str.split('-')
        start = parts[0]
        if parts[1]:
            end = parts[1]
        else:
            end = MAX_INT

        return (int(start), int(end))


def headers_to_http_msg(headers, line=b''):
    return line + headers.as_string().encode("iso-8859-1")


def http_msg_to_headers(f):
    line = f.readline(_MAXLINE + 1)
    msg = email.parser.BytesParser(policy=policy).parse(
        f, headersonly=True)
    return msg, line


def http_msg_bytes_to_headers(msg_bytes):
    f = io.BytesIO(msg_bytes)
    return http_msg_to_headers(f)


def replace_headers(msg, items):
    """replace headers
    require all fileds of items member of str type
    """
    for header in items:
        del msg[header[0]]
        msg[header[0]] = header[1]
