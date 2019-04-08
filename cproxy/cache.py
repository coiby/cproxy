#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
"""

"""
import errno
import fnmatch
import gzip
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import re
import shutil
from . import httptools

CACHE_DIR_NAMESPACE = "CachingProxy"
CACHE_COMPRESS = False
fopen = gzip.open if CACHE_COMPRESS else open

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))


class Rules:
    """
    identify resource based on manually defined rules

    To achive fast query O(1), the rules are represented by
    a dict-based/hashed tree, e.g.,

    {'com': {'googleapis': {'www': {'/youtube/v3/videos': ['video_id']}},
             'googlevideo': {'*': {'/videoplayback': ['id','range',
                                                      'clen','mime']}},
             'youtube': {'www': {'/get_video_info': ['video_id'],
                             '/watch': ['v', 'el']}}},
     'org': {'coursera': {'www': {'/api/subtitleAssetProxy.v1/*': ''}}}}
    """

    def __init__(self, path='./rules'):
        self.rules = {}
        path = os.path.join(__location__, path)
        self.build_rules_tree(path)

    def build_rules_tree(self, path):
        if not os.path.exists(path):
            logging.warning(
                "{} doesn't exist, finding cache by rules will not work".
                format(path))
            return

        with open(path, 'r') as f:
            for line in f.readlines():
                if not line.startswith('!'):
                    self.rule_to_tree(line)

    def split_url(self, url):
        parts = url.split('/')
        # assume there is a path
        assert (len(parts) >= 2)
        path = '/' + '/'.join(parts[1:])
        domain_parts = parts[0].split('.')
        return domain_parts, path

    def rule_to_tree(self, rule, ids=''):
        parts = rule.split()
        if len(parts) > 1:
            ids = parts[1].split(',')

        domain_parts, path = self.split_url(parts[0])

        dic1_prev = {path: ids}
        # return nested_keys(rules, parts[0].split('.')[::-1], path)
        for part in domain_parts:
            dic1 = {}
            dic1[part] = dic1_prev
            dic1_prev = dic1

        self.merge_rule(dic1)

    def merge_rule(self, rule):
        root = self.rules
        loop = True
        while loop:
            for key in rule:
                if key in root:
                    root = root[key]
                    rule = rule[key]
                else:
                    root[key] = rule[key]
                    loop = False

    def find(self, url):
        """Given an url, find if there is any rule matching it
        e.g. www.coursera.org/api/subtitleAssetProxy.v1/A8NI4jtrEem4egrIUlgmqg"
        """
        domain_parts, path = self.split_url(url)
        parts = domain_parts[::-1]
        parts.append(path)
        root = self.rules
        for key_ in parts:
            found = False
            for key in root:
                if fnmatch.fnmatch(key_, key):
                    root = root[key]
                    found = True
                    break

            if not found:
                break

        if found:
            return root  # the leaf node will contain the ids

        return False


rules = Rules()


def split_path(path):
    split_path = path.split('/')
    dirname = None
    filename = None
    assert (len(split_path) > 1)
    if len(split_path) > 1:
        last_fragment = split_path[-1]
        if '.' not in last_fragment:
            if last_fragment:
                filename = last_fragment + '.html'
                dirname = '/'.join(split_path[:-1])
            else:
                filename = ''
                dirname = path
        else:
            filename = last_fragment
            dirname = '/'.join(split_path[:-1])
    else:
        filename = ''
        dirname = path
    return (dirname, filename)


def make_dirs(path):
    # Helper to make dirs recursively
    # http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def valid_filename(query_string):
    """remove invliad characters
    a-z 0-9 _ - .
    """
    valid_chars = re.compile(r"[^a-z0-9+\_\-.=#$(){} \[\]^']", re.IGNORECASE)
    return valid_chars.sub('', query_string)


# compatible with Windows
MAX_PATH = 257


def get_hashed_filepath(stub, method, query='', body_bytes=b''):
    hash_template = '{method}-{sha}_{stub}'
    if not stub:
        stub = 'index.html'

    #  suffix = valid_filename(params_str)

    #  if prefix_len + len(method) + len(stub) + len(suffix) > MAX_PATH:
    sha = ''
    hashed_bytes = query.encode('iso-8859-1') + body_bytes
    if hashed_bytes:
        sha = hashlib.sha256(hashed_bytes).hexdigest()

    hash_t = hash_template.format(method=method, stub=stub, sha=sha)
    return hash_t


def has_extension(path):
    """check whether path has extension
    maybe also validify the extention accroding to the list
    [Common File Extensions](https://fileinfo.com/filetypes/common)
    """
    last_part = path.split('/')[-1]
    splits = last_part.split('.')
    return len(splits) >= 2 and splits[-1]


class Cache(httptools.HTTPMSG):
    """Cache object

    A cache's header and content are stored seperatedly

    If the cache file doesn't exist on the disk, the Cache object will be used
    as a container to re-populating HTTP Response
    """

    def __init__(self, path, req, url):
        self.req = req
        self.url_ful = url
        super().__init__(None, '')
        self.set_path(path)

    def set_path(self, path):
        self.path = path
        self.headers_path = self.path + '.header'
        if self.exist():
            self.build_eheaders_from_file()
            self.range_check()

    def range_check(self):
        """ modify cache response headers if req use range header
        also modify req's header if necessary

        If req asks for partial data and cache exists,
         we will need to modify the response's header
        """
        self.partial = False
        range_header = self.req.get_header('range')
        if range_header:
            start, end = httptools.req_range_parser(range_header)
            body_len = int(self.get_header('content-length'))
            if not (start == 0 and end == httptools.MAX_INT):
                if end == httptools.MAX_INT:
                    end = body_len
                elif end < 0:
                    self.start = body_len + end
                    end = body_len
                elif end > 0:
                    end = end + 1  # python exclusive end

                self.partial = True
                self.body_start, self.body_end = start, end
                val = 'bytes {}-{}/{}'.format(start, end - 1, body_len)
                key = 'Content-range'
                self.set_header(key, val)
                self.set_header('content-length', str(end - start))
                logging.debug("partial data: {}".format(val))

        # if there is range_header and the cache's response contains etag, we
        # need to ask the remote server if it's stale or not
        # when req aks for parital data, we can also put etag header
        # since etag is calculated based on whole data instead of
        # on partial data
        self.modify_req_headers()

    def build_eheaders_from_file(self):
        with fopen(self.headers_path, 'rb') as f:
            eheaders, initial_line = httptools.http_msg_to_headers(f)
            initial_line = initial_line.decode("iso-8859-1")
            super().__init__(eheaders, initial_line)

    def modify_req_headers(self):
        """add If-None-Match header to req
        if
         - cache file exists,
         - req doesn't have If-None-Match header
         - cache has etag header
        """
        etag = self.get_header('etag')
        if etag and not self.req.get_header('If-None-Match'):
            self.req.check_freshness_header_from_cm = True
            self.req.set_header("If-None-Match", etag)

    def get_body_bytes(self):
        """read from file"""
        if not self._body:
            with fopen(self.path, 'rb') as f:
                body = f.read()
                # req asking a range
                if self.partial:
                    body = body[self.body_start:self.body_end]
                self._body = body
        return self._body

    def check_fresh(self):
        """whether to check the freshness"""
        return True

    def exist(self):
        return os.path.isfile(
            self.path) and os.path.isfile(self.path + '.header')


class CacheManager(object):
    """find/store/update caches

    When searching for local cache, it will try the following methods in sequence
    until one is found
     1. local cache that fully match the request (url + post_data)

     2. For GET method, find one that
       - has extension
       - match URL.PATH
       e.g. `?1553773236628`, `?Expires=1553904000` would be ignored for
        1. edx-video.net/MIT600512016-V006400_DTH.mp4?1553773236628
        2. d3c33hcgiwev3.cloudfront.net/1-1_Intro_to_the_focused_and_diffuse_modes/full/540p/index.mp4?Expires=1553904000 # noqa

     3. match cache based on manually defined rules
    """

    def __init__(self, opts):
        database = os.path.join(opts.cache_dir, 'sites.db')
        self.opts = opts
        if not os.path.isfile(database):
            shutil.copyfile(os.path.join(
                __location__, 'sites_template.db'), database)
        self.conn = sqlite3.connect(database, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.lock = threading.Lock()
        self.cache_dir = os.path.join(self.opts.cache_dir, CACHE_DIR_NAMESPACE)
        logging.info("Caches saved to {}".format(self.cache_dir))

    def safe_query(self, query):
        "thread-safe query"
        logging.debug(query)
        with self.lock:
            return self.cursor.execute(query).fetchall()

    def get_cache_dir(self):
        return self.cache_dir

    def url_to_path(self, url_parsed, req):
        """url to file path
        a.com/b/c/d;p?q  -> a.com/b/c/, d;p.html?q
        """
        url = url_parsed.netloc.split(':')[0] + url_parsed.path
        if url_parsed.params:
            url += ";{}".format(url_parsed.params)

        directory, stub = split_path(url)
        name = get_hashed_filepath(
            stub=stub,
            method=req.command,
            query=url_parsed.query,
            body_bytes=req.get_body_bytes())
        return directory, name

        if url_parsed.query:
            url += "?{}".format(url_parsed.query)

    def find(self, url_parsed, req):
        """find the cache for a request also modify the headers if necessary

        TODO: another approach is to construct a key which will uniquely
              determine a resrouce first, then use this
              key to query the database
        """
        method = req.command
        # url's path always has the suffix '?' . This suffix will help
        # distinguish between 'test.com/a.js' and 'test.com/a.js.map'
        url = "{}://{}{}?".format(url_parsed.scheme,
                                  url_parsed.netloc, url_parsed.path)
        url_no_query_post = url
        if url_parsed.query:
            url += "{}".format(url_parsed.query)

        # I plan to make post_text a dict and post_text can formatted as
        # similar to url.query, i.e. '?key1=val1&key2=val2'
        # But
        #   1. non-standard json like '[{"data":1}, {"new":2}]' will be posted,
        #   2. the structure may be nested
        # so json.dumps is adopted to deal wit these situtations

        if req.post_text:
            url += json.dumps(req.post_text)  # dict_to_str(params_post)

        query_req = req.query

        dirpath, name = self.url_to_path(url_parsed, req)

        cache = Cache(
            os.path.join(self.get_cache_dir(), dirpath, name), req, url)

        logging.debug("Going to retrieve cache {}".format(cache.path))
        # TODO check if cache is fresh
        # If there is no query or post, the resource can be uniquely determined
        # by url, but we still need to check 'test.com/a.mp4?232' for
        # 'test.com/a.mp4'
        if cache.exist():
            return cache

        cache, sites = self.find_by_extention(url_no_query_post,
                                              url_parsed.path, cache, method)

        if cache.exist():
            return cache

        if sites:
            logging.debug(
                "Trying to find cache for {} based on rules".format(url))
            url_no_port = "{}{}".format(
                url_parsed.netloc.split(':')[0], url_parsed.path)
            return self.find_by_rule(url_no_port, sites, cache, query_req)

        return cache

    def find_by_extention(self, url_no_query_post, path, cache, method):
        """find cache for GET req whose path has extenison

        e.g. GET a.b/1.mp4?, c.d/path/a/1.doc

        TODO also for POST?

        There is tricky situation for this way of find cache
          'r2-builds/ondemand/allStyles.96ee9191dfd6763e656d.js'
        shouldn't match
          'r2-builds/ondemand/allStyles.96ee9191dfd6763e656d.js.map'
        add suffix '?' to path will fix this issue
        """
        # order result by id, i.e. by freshness of resourse
        query = "select * from sites where url like '{}%' order by id desc".format(  # noqa
            url_no_query_post)
        sites = self.safe_query(query)

        if has_extension(path) and method == 'GET':
            if len(sites) > 0:
                cache.set_path(sites[0]['path'])

        return cache, sites

    def find_by_rule(self, url_no_port, sites, cache, query_req):
        # find cache based on manually defined rules
        ids = rules.find(url_no_port)

        if ids is not False:
            for row in sites:
                query = json.loads(row['query'])
                found = True
                for id in ids:
                    id_in_req = id in query_req
                    id_in_site = id in query
                    # require id in both query or not in either query
                    # useful for downloading a file via range parameter
                    # e.g. googlevideo.com/playback
                    if (id_in_req != id_in_site) or (
                            id_in_req and (query[id] != query_req[id])):
                        found = False
                        break

                if found:
                    cache.path = row['path']
                    cache.set_path(row['path'])
                    break

        return cache

    def validify_content_range(self, response, body_len):
        """check if whole content is returned
        e.g.
         valid: bytes 0-1761711/1761712
         invalid:  bytes 7000-7999/8000 (partial)
        """
        content_range = response.get_header('content-range')
        if content_range:
            assert ('bytes' in content_range)
            total_bytes = int(content_range.split('/')[-1])
            # TODO if 90% received, is it valid?
            if total_bytes != body_len:
                return False
        return True

    def store(self, response, method, cache):

        if not response or response.status >= 400 or response.status == 304:
            return
        header = response.get_headers_bytes()
        body = response.get_body_bytes()
        body_len = response.get_header('content-length')
        # TODO no content-length header
        # make sure redeived bytes == claimed size
        if not body_len:
            return
        body_len = int(body_len)
        if body_len != len(body):
            return
        # don't store partial content, i.e. 206 status code
        # TODO we may collect parital data until full data is collected
        if not self.validify_content_range(response, body_len):
            return
        folder = os.path.dirname(cache.path)
        make_dirs(folder)
        cache_file_header = cache.path + '.header'
        logging.debug("Going to store {}".format(cache.path))
        with fopen(cache_file_header, 'wb+') as f:
            f.write(header)

        with fopen(cache.path, 'wb+') as f:
            f.write(body)

        access_time = int(time.time())
        query = "INSERT or REPLACE INTO sites(url, query, post_text, method, \
            status, path, access_time) VALUES \
            ('{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(
            cache.url_ful, json.dumps(cache.req.query),
            json.dumps(cache.req.post_text), method, response.status,
            cache.path, access_time)
        self.safe_query(query)

    def shutdown(self):
        "called when the proxy server exits"
        self.conn.commit()
        self.conn.close()
