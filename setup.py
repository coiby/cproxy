#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="CProxy",
    version="0.1a1",
    author="Coiby",
    license="GPLv2",
    author_email="Coiby.Xu@gmail.com",
    description="A HTTP/HTTPS Caching Proxy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/coiby/CProxy",
    packages=setuptools.find_packages(),
    classifiers=[
        "Topic :: Internet",
        "Topic :: Internet :: WWW/HTTP",
        'Topic :: Internet :: Proxy Servers',
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        "Operating System :: OS Independent"
    ],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            "cproxy = cproxy:main"
        ]
    },
    install_requires=['pyOpenSSL', 'brotli', 'chardet']
)
