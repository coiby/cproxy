#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
import logging
import os
import select
import zlib

import brotli

import time
from http.client import HTTPResponse, _UNKNOWN, MAXAMOUNT, IncompleteRead
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, ParseResult, urlunparse, parse_qsl
from tempfile import gettempdir
import json

import ssl
import socket
from OpenSSL.crypto import load_certificate, FILETYPE_PEM, TYPE_RSA, \
    PKey, X509, X509Extension, dump_privatekey, \
    dump_certificate, load_privatekey, X509Req

import hashlib

from .cache import CacheManager
from .httptools import HTTPMSG

__all__ = ['CAAuth', 'ProxyHandle', 'Request', 'Response']

# compatible with python 3.4
try:
    ssl_protocal = ssl.PROTOCOL_TLS
except AttributeError:
    ssl_protocal = ssl.PROTOCOL_TLSv1_2

# For unstable network, TIMEOUT should be set to be larger value
TIMEOUT = 10
CACHE_DIR = "/data/coiby/other/cache_py/"
database = CACHE_DIR + "sites.db"


class Request(HTTPMSG):
    def __init__(self, req):
        self.query = dict(parse_qsl(req.url_parsed.query))
        # post_text used to construct unique resource id,
        # maybe used to extract resource identifiers later
        self.post_text = ""
        initial_line = '%s %s %s\r\n' % (req.command, req.path,
                                         req.request_version)
        self.command = req.command
        super().__init__(req.headers, initial_line)
        self.parse_req_body(req.rfile)
        self.check_freshness_header_from_cm = False

    def parse_req_body(self, rfile):
        # don't have content-type, e.g.
        # http://www.xuetangx.com/courses/course-v1:TsinghuaX+30240243X+sp/courseware/be5b8d4fec0c4c329d19845020bc67b2/ea4e11202a30484195b82c05bcb6b704/ # noqa
        # check post data
        content_length = self.get_header('Content-Length')
        if content_length:
            self._body = rfile.read(int(content_length))
            self.get_post_text()

    def get_post_text(self):
        """return posted data in structured format, e.g. dict"""
        if self.post_text:
            return self.post_text

        ctype = self.get_header('content-type')
        # POST request has the following content types:
        #  - 'application/x-www-form-urlencoded'
        #  - 'application/json'
        #  - 'text/plain'
        #  - 'application/xml'
        #  - 'multipart/form-data' (could have binary data)
        # for now  only the first 3 types are supported
        #

        if ctype == 'text/plain':
            self.post_text = self.get_body_str()
        elif ctype == 'application/json':
            self.post_text = json.loads(self.get_body_str())
        elif ctype == 'application/x-www-form-urlencoded':
            # don't use parse_qs, because
            # "field1=value1&field2=value2"
            #  will be parsd as
            # {'field1': ['value1'], 'field2': ['value2']}
            self.post_text = dict(parse_qsl(self.get_body_str()))
        else:
            self.post_text = hashlib.sha256(self.get_body_bytes()).hexdigest()


class SyncHTTPResponse(HTTPResponse):
    """
    Receive data from one side and send it to the other side
    simultaneously if possible by overwriting some methods of HTTPResponse


    TODO Unlike Firefox, chromium-based browsers ususally don't buffer
         full video. It will drop the connection after receiving the first 4MB
         if users don't play the video immeditatly.
         Generally they will connect/disconnect with the video server multiples
         times to ask for different parts of video. We may continue receiving
         the data even when chromimum disconnects.
    """

    def __init__(self, sock, debuglevel=0, method=None, url=None):
        super().__init__(sock, debuglevel, method, url)
        self.send_socket = None
        self.url = url

    def chunkize(self, data):
        print(len(data))
        return hex(len(data)).encode('latin1') + b"\r\n" + data + b"\r\n"

    def sync_send_to(self, send_socket):
        self.send_socket = send_socket

    def _safe_read(self, amt):
        s = []
        while amt > 0:
            chunk = self.fp.read(min(amt, MAXAMOUNT))
            if not chunk:
                raise IncompleteRead(b''.join(s), amt)
            s.append(chunk)
            amt -= len(chunk)
            if self.send_socket:
                try:
                    self.send_socket.sendall(chunk)
                # even when the client drops the connection, we will continue
                # receive data from remote server
                # e.g. chromium-based browser will disconnect before buffering
                # the whole video
                except ConnectionResetError:
                    logging.debug('Client drop the connection')
                    self.send_socket = None
        return b"".join(s)

    def _readall_chunked(self):
        assert self.chunked != _UNKNOWN
        value = []
        try:
            while True:
                chunk_left = self._get_chunk_left()
                if chunk_left is None:
                    break
                value.append(self._safe_read(chunk_left))
                if self.send_socket:
                    self.send_socket.sendall(self.chunkize(value[-1]))
                self.chunk_left = 0
            if self.send_socket:
                self.send_socket.sendall(b"0\r\n\r\n")
            return b''.join(value)
        except IncompleteRead:
            raise IncompleteRead(b''.join(value))


class Response(HTTPMSG):
    def __init__(self, proxy_socket, send_socket, opts):
        self.send_socket = send_socket
        debug_level = 1 if opts.debug else 0
        self.h = SyncHTTPResponse(proxy_socket, debug_level)
        h = self.h
        h.begin()  # get headers

        initial_line = '%s %s %s\r\n' % (self.version_dict[h.version],
                                         h.status, h.reason)
        self.send_data = True
        self.body_received = False

        super().__init__(h.msg, initial_line)
        if not self.get_header('Content-length'):
            #  del self.msg['Tranfer-Encoding']
            self.send_data = False
        self.status = h.status
        self.headers_updated = True
        #  self._text()  # decode plain text

    def read(self):

        #  print(self.get_headers_bytes().decode('latin1'))
        if self.send_data:
            self.send_socket.sendall(self.get_headers_bytes())
            self.h.sync_send_to(self.send_socket)
        try:
            body_data = self._decompress_content_body(
                self.h.read(), self.get_header('Content-Encoding'))
            self.body_received = True
        except socket.error as e:
            logging.debug("When receiving data from remote, \
                        there's an error: {}".format(e))
            return

        self.set_body_bytes(body_data)
        # HTTPResponse will gather all chunks, no need to put Tranfer-Encoding
        if self.get_header('Transfer-Encoding'):
            self.del_header('Transfer-Encoding')

        # don't close proxy_socket
        #  proxy_socket.close()
        #  h.close()

    def _compress_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            gzip_compress = zlib.compressobj(9, zlib.DEFLATED,
                                             zlib.MAX_WBITS | 16)
            data = gzip_compress.compress(text) + gzip_compress.flush()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            data = text
        return data

    def set_body_bytes(self, body):
        if isinstance(body, bytes):
            self._body = body
            self.set_header("Content-length", str(len(body)))
            return
        raise Exception("parameter should be bytes")

    def _decompress_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data

        elif encoding in ('gzip', 'x-gzip'):
            text = zlib.decompress(data, 16 + zlib.MAX_WBITS)
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        elif encoding == 'br':
            text = brotli.decompress(data)
        else:
            text = data
        self.set_header('Content-Encoding', 'identity')
        return text


class CAAuth(object):
    """Generate CA and self-signed certificates

    this part of code is borrowed from https://github.com/qiyeboy/BaseProxy
    except for the comment
    """

    def __init__(self, opts, ca_file="ca.pem", cert_file='ca.crt'):
        self.ca_file_path = os.path.join(opts.config_dir, ca_file)
        self.cert_file_path = os.path.join(opts.config_dir, cert_file)
        self._gen_ca()

    def _gen_ca(self, again=False):
        # Generate key
        if os.path.exists(self.ca_file_path) and os.path.exists(
                self.cert_file_path) and not again:
            self._read_ca(self.ca_file_path)
            return
        self.key = PKey()
        self.key.generate_key(TYPE_RSA, 2048)
        # Generate certificate
        self.cert = X509()
        self.cert.set_version(2)
        self.cert.set_serial_number(1)
        self.cert.get_subject().CN = 'CachingProxy'
        self.cert.gmtime_adj_notBefore(0)
        self.cert.gmtime_adj_notAfter(315360000)
        self.cert.set_issuer(self.cert.get_subject())
        self.cert.set_pubkey(self.key)
        self.cert.add_extensions([
            X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
            X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            X509Extension(
                b"subjectKeyIdentifier", False, b"hash", subject=self.cert),
        ])
        self.cert.sign(self.key, "sha256")
        with open(self.ca_file_path, 'wb+') as f:
            f.write(dump_privatekey(FILETYPE_PEM, self.key))
            f.write(dump_certificate(FILETYPE_PEM, self.cert))

        with open(self.cert_file_path, 'wb+') as f:
            f.write(dump_certificate(FILETYPE_PEM, self.cert))

    def _read_ca(self, file):
        self.cert = load_certificate(FILETYPE_PEM, open(file, 'rb').read())
        self.key = load_privatekey(FILETYPE_PEM, open(file, 'rb').read())

    def __getitem__(self, cn):
        # self-signed certificates in tmp direcotry
        #
        cache_dir = gettempdir()
        root_dir = os.path.join(cache_dir, 'CP')
        if not os.path.exists(root_dir):
            os.makedirs(root_dir)

        cnp = os.path.join(root_dir, "CP_{}.pem".format(cn))

        if not os.path.exists(cnp):
            self._sign_ca(cn, cnp)
        return cnp

    def _sign_ca(self, cn, cnp):
        # create certificate
        try:

            key = PKey()
            key.generate_key(TYPE_RSA, 2048)

            # Generate CSR
            req = X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha256')

            # Sign CSR
            cert = X509()
            cert.set_version(2)
            cert.set_subject(req.get_subject())
            cert.set_serial_number(self.serial)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(31536000)
            cert.set_issuer(self.cert.get_subject())
            ss = ("DNS:%s" % cn).encode(encoding="utf-8")

            cert.add_extensions([X509Extension(b"subjectAltName", False, ss)])

            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.key, 'sha256')

            with open(cnp, 'wb+') as f:
                f.write(dump_privatekey(FILETYPE_PEM, key))
                f.write(dump_certificate(FILETYPE_PEM, cert))
        except Exception as e:
            raise Exception("generate CA fail:{}".format(str(e)))

    @property
    def serial(self):
        return int("%d" % (time.time() * 1000))


class ProxyHandle(BaseHTTPRequestHandler):
    # set to 'HTTP/1.1', the server will permit HTTP persistent connections
    protocol_version = 'HTTP/1.1'

    def __init__(self, request, client_addr, server):
        self.cm = server.cm
        self.opts = server.opts
        # makr if connection with remote server has been established
        self.is_connected = False
        self.port = None
        self.ssl_host = ''
        self._proxy_sock = None
        # also valid for PUT method, i.e. for non-GET methods
        self.post_body_data = b''
        BaseHTTPRequestHandler.__init__(self, request, client_addr, server)

    def log_message(self, format, *args):
        """not needed"""
        pass

    def do_CONNECT(self):
        """HTTP tunneling"""
        logging.info("CONNECT " + self.path)
        if self.server.https:
            self.connect_intercept()

        else:
            self.connect_relay()

    def get_reponse(self, request):
        logging.debug("Sent request {} to {}".format(request.to_bytes(),
                                                     self.url))
        self._proxy_sock.sendall(request.to_bytes())
        response = Response(self._proxy_sock, self.request,
                            self.opts)
        return response

    def make_request(self, cache, request):
        response = None
        if not self.is_connected:
            # establish connection with remote server
            try:
                self._connect_to_remote()
                self.is_connected = True
                logging.debug("[CP] Connection established")
            except socket.error as e:
                logging.debug("[CP] Connection establishing error".format(e))
                return response
        retry = False
        if request:
            if self._proxy_sock.fileno() == -1:  # remote close the connection
                self. _connect_to_remote()
            # TODO re-establishing SSL connection is slow,
            # is there a way to tell if remote server maintains the connection?
            try:
                response = self.get_reponse(request)
            except socket.error as e:
                logging.info("Getting response error: {} {}".format(
                    e, self.url))
                retry = True

        if retry:
            try:
                self. _connect_to_remote()
                response = self.get_reponse(request)
            except socket.error as e:
                logging.info("reqeust response error: {} {}".format(
                    e, self.url))

        return response

    def path_process(self):
        """process path
        For http sites, the browser will send absolute path to proxy server,
        e.g. the http reqeust header will be like
          `GET http://tools.ietf.org/html/rfc3986 HTTP/1.1`
        Thus, we need to strip off some parts so the request will becomes
          `GET html/rfc3986 HTTP/1.1`
        """
        if self.ssl_host:  # been dealt with by do_CONNECT
            self.url_parsed = urlparse('https://' + self.hostname + ':443' +
                                       self.path)
            self.url = self.hostname + self.path
            return
        self.url_parsed = urlparse(self.path)
        u = self.url_parsed
        if u.scheme != 'http':
            raise Exception('Unknown scheme %s' % repr(u.scheme))
        self.hostname = u.hostname
        self.port = u.port or 80
        self.url = self.path
        self.path = urlunparse(
            ParseResult(
                scheme='',
                netloc='',
                params=u.params,
                path=u.path or '/',
                query=u.query,
                fragment=u.fragment))

    def process_request(self):
        if self.path == 'http://cp.ca/':
            self._send_ca()
            return
        # For https, self.path doesn't have hostname because the browser thinks
        # it's communicating with the server directly through the tunnel
        #
        # For http, the browser will automally add hostname as prefix
        # Notice path here has different meaning from the <path> in
        # <scheme>://<net_loc>/<path>;<params>?<query>#<fragment> specified in
        # [RFC 1808 - Relative Uniform Resource
        # Locators](https://tools.ietf.org/html/rfc1808.html)
        self.path_process()

        logging.info("URL to serve: %s", self.url)
        # disable youtube for edx
        referer = self.headers.get('referer', '')
        # youtube is disabled on courses.edx.org
        if 'youtube.com' in self.hostname and (
                'courses.edx.org' in referer
                or 'lagunita.stanford.edu' in referer):
            self.send_error(404, 'Youtube forbidden for courses.edx.org')
            return

        request = Request(self)

        cache = self.cm.find(self.url_parsed, request)
        #  logging.debug(repr(str(self.headers)))
        if self.opts.OFFLINE:
            if cache.exist():
                logging.info("Cache hit {}: {}".format(self.url, cache.path))
                self.request.sendall(cache.to_bytes())
                return False
            logging.info("Cache miss {}".format(self.url))
            self.send_error(404, 'No cache')
            return False

        response = self.make_request(cache, request)
        status = 1000
        if response:
            status = response.status

        # decide:
        #  - what will be sent to the client
        #    1. cache
        #    2. response, if yes, when will we send it
        #      - sent after receiving all data from server
        #      - sent while receving all the data
        #    3. 404

        NOT_MODIFIED = 304
        sending_cache = False
        if response:
            if status >= 400 or (request.check_freshness_header_from_cm
                                 and status == NOT_MODIFIED):
                response.send_data = False
                sending_cache = True

            response.read()  # receive body regardless of the status
            if not sending_cache:
                if not response.body_received:
                    # even though send_data = True
                    # exception may happens when receiving data from remote
                    # in this case, we still rely on cache
                    sending_cache = True
                    logging.debug("body not recevied")
                elif not response.send_data:
                    # this situtation happens when response has
                    # transfer-encode header
                    # TODO will be resolved later
                    try:
                        self.request.sendall(response.to_bytes())
                    except socket.error as e:
                        logging.info(
                            'Error occurs when sending response from {}: {}'.
                            format(self.url, e))
        else:
            sending_cache = True

        if sending_cache:
            if cache.exist():
                logging.info("Cache hit {}".format(self.url))
                self.request.sendall(cache.to_bytes())
            else:
                if response:
                    try:
                        self.request.sendall(response.to_bytes())
                    except socket.error as e:
                        # TODO Connection to client broken? Close it?
                        logging.info("Error sending response {}, {}".format(
                            self.url, str(e)))
                else:
                    logging.debug('404 for {}'.format(
                        self.hostname + self.path))
                    self.send_error(404, 'Not found')

        # TODO don't store 304 response
        # CacheManager will decide whether to store/update or not
        self.cm.store(response, self.command, cache)

    def do_GET(self):
        logging.debug("GET " + self.path)
        self.process_request()

    do_HEAD = do_GET
    do_PUT = do_GET
    do_POST = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    context = ssl.create_default_context()

    def _connect_to_remote(self):
        """Establish connection with remote server

        Support IPv6 by using socket.create_connection

        SSL session will be re-used to do abbreviated handshake, thus quicker
        response.
        See [Speeding up TLS: enabling session reuse | Vincent Bernat]
        (https://vincent.bernat.ch/en/blog/2011-ssl-session-reuse-rfc5077)
        """

        session = self._proxy_sock.session if isinstance(
            self._proxy_sock, ssl.SSLSocket) else None
        session = None
        # use create_connection which prefers IPv6
        self._proxy_sock = socket.create_connection((self.hostname, self.port),
                                                    TIMEOUT)
        if self.ssl_host:
            # re-use session
            self._proxy_sock = self.context.wrap_socket(
                self._proxy_sock,
                server_hostname=self.hostname,
                session=session)

    def connect_intercept(self):
        """intercept CONNECT request, play as man in the middle"""
        self.hostname, self.port = self.path.split(':')

        try:
            # what if we connect without using SNI as shown in
            # [How mitmproxy works]
            # (https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/#complication-3-server-name-indication) # noqa
            self.send_response(200, "Connection established")
            self.end_headers()
            context = ssl.SSLContext(ssl_protocal)
            #  context.set_ciphers('AESGCM:!DH:!DHE:!ECDHE:!PSK')
            context.load_cert_chain(self.server.ca[self.hostname])
            self.request = context.wrap_socket(self.request, server_side=True)
        except socket.error as e:
            self.send_error(500, str(e))
            return

        self.setup()
        self.ssl_host = 'https://%s' % self.path
        self.handle_one_request()

    def connect_relay(self):
        '''
        relay packets through tunnel,
        '''

        self.hostname, self.port = self.path.split(':')
        self.url = self.hostname + self.path
        try:
            self._proxy_sock = socket.socket()
            self._proxy_sock.settimeout(TIMEOUT)
            self._proxy_sock.connect((self.hostname, int(self.port)))
        except socket.error as e:
            logging.debug("Error when establishing connection with remote \
                          server, {}".format(e))
            self.send_error(500)
            return

        self.send_response(200, 'Connection Established')
        self.end_headers()

        inputs = [self.request, self._proxy_sock]

        while True:
            readable, writeable, errs = select.select(inputs, [], inputs, 10)
            if errs:
                break
            for r in readable:
                data = r.recv(8092)
                if data:
                    if r is self.request:
                        self._proxy_sock.sendall(data)
                    elif r is self._proxy_sock:
                        self.request.sendall(data)
                else:
                    break
        self.request.close()
        self._proxy_sock.close()

    def _send_ca(self):
        # send CA to browser to be installed&trusted
        cert_path = self.server.ca.cert_file_path
        with open(cert_path, 'rb') as f:
            data = f.read()

        self.send_response(200)
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)


class CachingProxy(ThreadingMixIn, HTTPServer):
    # we can inherit from ThreadingHTTPServer for Python > 3.4
    daemon_threads = True

    def __init__(self,
                 opts,
                 server_addr=('locahost', 8080),
                 RequestHandlerClass=ProxyHandle,
                 bind_and_activate=True,
                 https=True):
        self.opts = opts
        self.cm = CacheManager(opts)
        HTTPServer.__init__(self, server_addr, RequestHandlerClass,
                            bind_and_activate)
        logging.info("CP is listening on http://{}:{}".format(*server_addr))
        self.ca = CAAuth(opts, ca_file="ca.pem", cert_file='ca.crt')
        self.https = https

    def shutdown(self):
        """if program exits abruptly, notify cache manager"""
        self.cm.shutdown()
