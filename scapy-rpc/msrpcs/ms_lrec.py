# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

# [ms-lrec] v5.0 (Tue, 23 Apr 2024)

"""
RPC definitions for the following interfaces:
- NetEventForwarder (v1.0): 22e5386d-8b12-4bf0-b0ec-6a1ea419e366
This file is auto-generated by midl-to-scapy, do not modify.
"""

import uuid


from scapy.layers.dcerpc import (
    NDRPacket,
    DceRpcOp,
    NDRConfStrLenField,
    NDRConfVarStrNullField,
    NDRConfVarStrNullFieldUtf16,
    NDRContextHandle,
    NDRFullEmbPointerField,
    NDRIntField,
    NDRPacketField,
    register_dcerpc_interface,
)


class RpcNetEventOpenSession_Request(NDRPacket):
    fields_desc = [NDRConfVarStrNullFieldUtf16("LoggerName", "")]


class RpcNetEventOpenSession_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("SessionHandle", NDRContextHandle(), NDRContextHandle),
        NDRIntField("status", 0),
    ]


class EVENT_BUFFER(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("BufferLength", None, size_of="Buffer"),
        NDRFullEmbPointerField(
            NDRConfStrLenField("Buffer", "", size_is=lambda pkt: pkt.BufferLength)
        ),
    ]


class RpcNetEventReceiveData_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("SessionHandle", NDRContextHandle(), NDRContextHandle)
    ]


class RpcNetEventReceiveData_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("EventBuffer", EVENT_BUFFER(), EVENT_BUFFER),
        NDRIntField("status", 0),
    ]


class RpcNetEventCloseSession_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("SessionHandle", NDRContextHandle(), NDRContextHandle)
    ]


class RpcNetEventCloseSession_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("SessionHandle", NDRContextHandle(), NDRContextHandle),
        NDRIntField("status", 0),
    ]


NETEVENTFORWARDER_OPNUMS = {
    0: DceRpcOp(RpcNetEventOpenSession_Request, RpcNetEventOpenSession_Response),
    1: DceRpcOp(RpcNetEventReceiveData_Request, RpcNetEventReceiveData_Response),
    2: DceRpcOp(RpcNetEventCloseSession_Request, RpcNetEventCloseSession_Response),
}
register_dcerpc_interface(
    name="NetEventForwarder",
    uuid=uuid.UUID("22e5386d-8b12-4bf0-b0ec-6a1ea419e366"),
    version="1.0",
    opnums=NETEVENTFORWARDER_OPNUMS,
)
