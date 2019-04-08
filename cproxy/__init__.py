#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""cproxy import Interface.

"""
import logging
import sys

from .proxy import CachingProxy
from .options import parseOpts

__author__ = "Coiby Xu"
__email__ = "coiby.xu@gmail.com"

__all__ = ['httptools', 'proxy', 'cache']


def main(argv=None):
    try:
        opts = parseOpts(sys.argv)
        debug_level = logging.DEBUG if opts.debug else logging.INFO
        logging.basicConfig(level=debug_level,
                            format='[%(asctime)s] %(levelname)s %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')

        port = opts.port if opts.port else 8080
        cp = CachingProxy(opts, server_addr=('localhost', port), https=True)
        cp.serve_forever()
    except KeyboardInterrupt:
        logging.info("Ctrl+c detected, gracefully exit")
        cp.shutdown()
