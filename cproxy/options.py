#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
"""

Under windows, %appdata%/cachingproxy will be used to store root CA

Search for configuration file among the following paths
 - ~/.config/cachingproxy.conf
 - ~/.config/cachingproxy/config

Also accept arguments from command line which will overwrite
the configuration file.


Code borrowed from youtube-dl
"""
import argparse
import os
import shlex

import platform

platform = platform.system()

config_dirs = {'Linux': '.config',
               'Darwin': 'Library/Preferences',
               'Windows': 'AppData/Roaming'}

config_files = {'Linux': 'config',
                'Darwin': 'config',
                'Windows': 'config.txt'}

config_dir = os.path.join(os.path.expanduser('~'),
                          config_dirs[platform], 'cachingproxy')


def parseOpts(argv):
    def _readOptions(filename_bytes, default=[]):
        try:
            optionf = open(filename_bytes)
        except IOError:
            return default  # silently skip if file is not present
        try:
            contents = optionf.read()
            res = shlex.split(contents, comments=True)
        finally:
            optionf.close()
        return res

    def _readUserConf():
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        userConfFile = os.path.join(config_dir, config_files[platform])
        return _readOptions(userConfFile)

    parser = argparse.ArgumentParser("CachingProxy arguments")

    parser.add_argument(
        '-c',
        '--config_dir',
        dest='config_dir',
        action='store',
        default=config_dir,
        help='where to store CA; you can put your config file here')

    parser.add_argument(
        '-cd',
        '--cache_dir',
        dest='cache_dir',
        action='store',
        default='',
        help='where to store caches')

    parser.add_argument(
        '-p',
        '--port',
        dest='port',
        type=int,
        action='store',
        default=None,
        help='server listening port')

    parser.add_argument(
        '-off',
        '--offline',
        dest='OFFLINE',
        action='store_true',
        default=False,
        help='Offline mode')

    parser.add_argument(
        '-d',
        '--debug',
        dest='debug',
        action='store_true',
        default=False,
        help='Enable debugging mode')

    user_conf = _readUserConf()
    command_line_conf = argv[1:]
    return parser.parse_args(user_conf + command_line_conf)
