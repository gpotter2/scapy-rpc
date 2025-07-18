# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

# [ms-rsp] v12.0 (Tue, 23 Apr 2024)

"""
RPC definitions for the following interfaces:
- InitShutdown (v1.0): 894de0c0-0d55-11d3-a322-00c04fa321a1
This file is auto-generated by midl-to-scapy, do not modify.
"""

import uuid


from scapy.layers.dcerpc import (
    NDRPacket,
    DceRpcOp,
    NDRByteField,
    NDRConfVarStrLenField,
    NDRConfVarStrLenFieldUtf16,
    NDRFullEmbPointerField,
    NDRFullPointerField,
    NDRIntField,
    NDRPacketField,
    NDRShortField,
    register_dcerpc_interface,
)


class PREG_UNICODE_STRING(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRShortField("Length", None, size_of="Buffer", adjust=lambda _, x: (x * 2)),
        NDRShortField(
            "MaximumLength", None, size_of="Buffer", adjust=lambda _, x: (x * 2)
        ),
        NDRFullEmbPointerField(
            NDRConfVarStrLenFieldUtf16(
                "Buffer",
                "",
                size_is=lambda pkt: (pkt.MaximumLength // 2),
                length_is=lambda pkt: (pkt.Length // 2),
            )
        ),
    ]


class BaseInitiateShutdown_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRShortField("ServerName", 0)),
        NDRFullPointerField(
            NDRPacketField("lpMessage", PREG_UNICODE_STRING(), PREG_UNICODE_STRING)
        ),
        NDRIntField("dwTimeout", 0),
        NDRByteField("bForceAppsClosed", 0),
        NDRByteField("bRebootAfterShutdown", 0),
    ]


class BaseInitiateShutdown_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class BaseAbortShutdown_Request(NDRPacket):
    fields_desc = [NDRFullPointerField(NDRShortField("ServerName", 0))]


class BaseAbortShutdown_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class BaseInitiateShutdownEx_Request(NDRPacket):
    fields_desc = [
        NDRFullPointerField(NDRShortField("ServerName", 0)),
        NDRFullPointerField(
            NDRPacketField("lpMessage", PREG_UNICODE_STRING(), PREG_UNICODE_STRING)
        ),
        NDRIntField("dwTimeout", 0),
        NDRByteField("bForceAppsClosed", 0),
        NDRByteField("bRebootAfterShutdown", 0),
        NDRIntField("dwReason", 0),
    ]


class BaseInitiateShutdownEx_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


INITSHUTDOWN_OPNUMS = {
    0: DceRpcOp(BaseInitiateShutdown_Request, BaseInitiateShutdown_Response),
    1: DceRpcOp(BaseAbortShutdown_Request, BaseAbortShutdown_Response),
    2: DceRpcOp(BaseInitiateShutdownEx_Request, BaseInitiateShutdownEx_Response),
}
register_dcerpc_interface(
    name="InitShutdown",
    uuid=uuid.UUID("894de0c0-0d55-11d3-a322-00c04fa321a1"),
    version="1.0",
    opnums=INITSHUTDOWN_OPNUMS,
)
