# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information

"""
Scapy RPC definitions
"""

import importlib
import importlib.machinery
import pathlib

__version__ = "0.0.4"


def scapy_ext(plg):
    plg.config("Scapy RPC", __version__)
    for lay in pathlib.Path(__file__).parent.glob("*.py"):
        if lay.name == "__init__.py":
            continue
        plg.register(
            name="msrpce.raw." + lay.name[:-3],
            mode=plg.MODE.LAYERS,
            path=lay.absolute(),
        )
