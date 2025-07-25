# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

# [ms-swn] v14.0 (Tue, 19 Nov 2024)

"""
RPC definitions for the following interfaces:
- Witness (v1.1): ccd8c074-d0e5-4a40-92b4-d074faa6ba28
This file is auto-generated by midl-to-scapy, do not modify.
"""

import uuid

from scapy.fields import StrFixedLenFieldUtf16
from scapy.layers.dcerpc import (
    NDRPacket,
    DceRpcOp,
    NDRConfPacketListField,
    NDRConfStrLenField,
    NDRConfVarStrNullField,
    NDRConfVarStrNullFieldUtf16,
    NDRContextHandle,
    NDRFullEmbPointerField,
    NDRFullPointerField,
    NDRIntField,
    NDRPacketField,
    NDRShortField,
    register_dcerpc_interface,
)


class PWITNESS_INTERFACE_INFO(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        StrFixedLenFieldUtf16("InterfaceGroupName", "", length=260 * 2),
        NDRIntField("Version", 0),
        NDRShortField("State", 0),
        NDRIntField("IPV4", 0),
        StrFixedLenFieldUtf16("IPV6", "", length=8 * 2),
        NDRIntField("Flags", 0),
    ]


class PWITNESS_INTERFACE_LIST(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("NumberOfInterfaces", None, size_of="InterfaceInfo"),
        NDRFullEmbPointerField(
            NDRConfPacketListField(
                "InterfaceInfo",
                [PWITNESS_INTERFACE_INFO()],
                PWITNESS_INTERFACE_INFO,
                size_is=lambda pkt: pkt.NumberOfInterfaces,
            )
        ),
    ]


class WitnessrGetInterfaceList_Request(NDRPacket):
    fields_desc = []


class WitnessrGetInterfaceList_Response(NDRPacket):
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField(
                "InterfaceList", PWITNESS_INTERFACE_LIST(), PWITNESS_INTERFACE_LIST
            )
        ),
        NDRIntField("status", 0),
    ]


class WitnessrRegister_Request(NDRPacket):
    fields_desc = [
        NDRIntField("Version", 0),
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("NetName", "")),
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("IpAddress", "")),
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("ClientComputerName", "")),
    ]


class WitnessrRegister_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("ppContext", NDRContextHandle(), NDRContextHandle),
        NDRIntField("status", 0),
    ]


class WitnessrUnRegister_Request(NDRPacket):
    fields_desc = [NDRPacketField("pContext", NDRContextHandle(), NDRContextHandle)]


class WitnessrUnRegister_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class PRESP_ASYNC_NOTIFY(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("MessageType", 0),
        NDRIntField("Length", None, size_of="MessageBuffer"),
        NDRIntField("NumberOfMessages", 0),
        NDRFullEmbPointerField(
            NDRConfStrLenField("MessageBuffer", "", size_is=lambda pkt: pkt.Length)
        ),
    ]


class WitnessrAsyncNotify_Request(NDRPacket):
    fields_desc = [NDRPacketField("pContext", NDRContextHandle(), NDRContextHandle)]


class WitnessrAsyncNotify_Response(NDRPacket):
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField("pResp", PRESP_ASYNC_NOTIFY(), PRESP_ASYNC_NOTIFY)
        ),
        NDRIntField("status", 0),
    ]


class WitnessrRegisterEx_Request(NDRPacket):
    fields_desc = [
        NDRIntField("Version", 0),
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("NetName", "")),
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("ShareName", "")),
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("IpAddress", "")),
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("ClientComputerName", "")),
        NDRIntField("Flags", 0),
        NDRIntField("KeepAliveTimeout", 0),
    ]


class WitnessrRegisterEx_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("ppContext", NDRContextHandle(), NDRContextHandle),
        NDRIntField("status", 0),
    ]


class WitnessrUnRegisterEx_Request(NDRPacket):
    fields_desc = [NDRPacketField("ppContext", NDRContextHandle(), NDRContextHandle)]


class WitnessrUnRegisterEx_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("ppContext", NDRContextHandle(), NDRContextHandle),
        NDRIntField("status", 0),
    ]


WITNESS_OPNUMS = {
    0: DceRpcOp(WitnessrGetInterfaceList_Request, WitnessrGetInterfaceList_Response),
    1: DceRpcOp(WitnessrRegister_Request, WitnessrRegister_Response),
    2: DceRpcOp(WitnessrUnRegister_Request, WitnessrUnRegister_Response),
    3: DceRpcOp(WitnessrAsyncNotify_Request, WitnessrAsyncNotify_Response),
    4: DceRpcOp(WitnessrRegisterEx_Request, WitnessrRegisterEx_Response),
    5: DceRpcOp(WitnessrUnRegisterEx_Request, WitnessrUnRegisterEx_Response),
}
register_dcerpc_interface(
    name="Witness",
    uuid=uuid.UUID("ccd8c074-d0e5-4a40-92b4-d074faa6ba28"),
    version="1.1",
    opnums=WITNESS_OPNUMS,
)
