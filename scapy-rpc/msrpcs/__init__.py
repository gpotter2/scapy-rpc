"""
Scapy RPC definitions
"""

import importlib
import importlib.machinery
import pathlib

__version__ = "0.0.1"


def scapy_ext(plg):
    plg.config("Scapy RPC", __version__)
    for lay in pathlib.Path(__file__).parent.glob('*.py'):
        if lay.name == "__init__.py":
            continue
        plg.register(
            name="msrpce.raw." + lay.name[:-3],
            mode=plg.MODE.LAYERS,
            path=lay.absolute(),
        )
