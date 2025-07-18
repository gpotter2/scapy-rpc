# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

# [ms-rdpesc] v17.0 (Tue, 23 Apr 2024)

"""
RPC definitions for the following interfaces:
- type_scard_pack (v1.0): A35AF600-9CF4-11CD-A076-08002B2BD711
This file is auto-generated by midl-to-scapy, do not modify.
"""

import uuid


from scapy.layers.dcerpc import NDRPacket, register_dcerpc_interface

TYPE_SCARD_PACK_OPNUMS = {}
register_dcerpc_interface(
    name="type_scard_pack",
    uuid=uuid.UUID("A35AF600-9CF4-11CD-A076-08002B2BD711"),
    version="1.0",
    opnums=TYPE_SCARD_PACK_OPNUMS,
)
