#! /usr/bin/env python

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information

"""
Setuptools setup file for Scapy RPC.
"""

import io
import os
import sys

if sys.version_info < (3, 9):
    raise OSError("Scapy RED needs Python 3.9+ !")

try:
    from setuptools import setup
except:
    raise ImportError("setuptools is required to install scapy-rpc !")


def get_long_description():
    """
    Extract description from README.md, for PyPI's usage
    """

    def process_ignore_tags(buffer):
        return "\n".join(
            x for x in buffer.split("\n") if "<!-- ignore_ppi -->" not in x
        )

    try:
        fpath = os.path.join(os.path.dirname(__file__), "README.md")
        with io.open(fpath, encoding="utf-8") as f:
            readme = f.read()
            desc = readme.partition("<!-- start_ppi_description -->")[2]
            desc = desc.partition("<!-- stop_ppi_description -->")[0]
            return process_ignore_tags(desc.strip())
    except IOError:
        return None


setup(
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
)
