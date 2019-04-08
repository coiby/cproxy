#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#

import sys
# code from youtube_dl
if __package__ is None and not hasattr(sys, 'frozen'):
    # direct call of __main__.py
    import os.path
    path = os.path.realpath(os.path.abspath(__file__))
    sys.path.insert(0, os.path.dirname(os.path.dirname(path)))

import cproxy

if __name__ == '__main__':
    cproxy.main()
