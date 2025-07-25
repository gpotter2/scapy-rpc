# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

# [ms-oxcrpc] v25.0 (Tue, 20 May 2025)

"""
RPC definitions for the following interfaces:
- emsmdb (v0.81): A4F1DB00-CA47-1067-B31F-00DD010662DA
- asyncemsmdb (v0.01): 5261574A-4572-206E-B268-6B199213B4E4
This file is auto-generated by midl-to-scapy, do not modify.
"""

import uuid

from scapy.fields import StrFixedLenFieldUtf16
from scapy.layers.dcerpc import (
    NDRPacket,
    DceRpcOp,
    NDRConfStrLenField,
    NDRConfVarStrLenField,
    NDRConfVarStrNullField,
    NDRContextHandle,
    NDRFullPointerField,
    NDRIntField,
    NDRPacketField,
    NDRShortField,
    register_dcerpc_interface,
)


class Opnum0Reserved_Request(NDRPacket):
    fields_desc = []


class Opnum0Reserved_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class EcDoDisconnect_Request(NDRPacket):
    fields_desc = [NDRPacketField("pcxh", NDRContextHandle(), NDRContextHandle)]


class EcDoDisconnect_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("pcxh", NDRContextHandle(), NDRContextHandle),
        NDRIntField("status", 0),
    ]


class Opnum2Reserved_Request(NDRPacket):
    fields_desc = []


class Opnum2Reserved_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class Opnum3Reserved_Request(NDRPacket):
    fields_desc = []


class Opnum3Reserved_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class EcRRegisterPushNotification_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("pcxh", NDRContextHandle(), NDRContextHandle),
        NDRIntField("iRpc", 0),
        NDRConfStrLenField("rgbContext", "", size_is=lambda pkt: pkt.cbContext),
        NDRShortField("cbContext", None, size_of="rgbContext"),
        NDRIntField("grbitAdviseBits", 0),
        NDRConfStrLenField(
            "rgbCallbackAddress", "", size_is=lambda pkt: pkt.cbCallbackAddress
        ),
        NDRShortField("cbCallbackAddress", None, size_of="rgbCallbackAddress"),
    ]


class EcRRegisterPushNotification_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("pcxh", NDRContextHandle(), NDRContextHandle),
        NDRIntField("hNotification", 0),
        NDRIntField("status", 0),
    ]


class Opnum5Reserved_Request(NDRPacket):
    fields_desc = []


class Opnum5Reserved_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class EcDummyRpc_Request(NDRPacket):
    fields_desc = []


class EcDummyRpc_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class Opnum7Reserved_Request(NDRPacket):
    fields_desc = []


class Opnum7Reserved_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class Opnum8Reserved_Request(NDRPacket):
    fields_desc = []


class Opnum8Reserved_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class Opnum9Reserved_Request(NDRPacket):
    fields_desc = []


class Opnum9Reserved_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class EcDoConnectEx_Request(NDRPacket):
    fields_desc = [
        NDRConfVarStrNullField("szUserDN", ""),
        NDRIntField("ulFlags", 0),
        NDRIntField("ulConMod", 0),
        NDRIntField("cbLimit", 0),
        NDRIntField("ulCpid", 0),
        NDRIntField("ulLcidString", 0),
        NDRIntField("ulLcidSort", 0),
        NDRIntField("ulIcxrLink", 0),
        NDRShortField("usFCanConvertCodePages", 0),
        StrFixedLenFieldUtf16("rgwClientVersion", "", length=3 * 2),
        NDRIntField("pulTimeStamp", 0),
        NDRConfStrLenField("rgbAuxIn", "", size_is=lambda pkt: pkt.cbAuxIn),
        NDRIntField("cbAuxIn", None, size_of="rgbAuxIn"),
        NDRIntField("pcbAuxOut", 0),
    ]


class EcDoConnectEx_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("pcxh", NDRContextHandle(), NDRContextHandle),
        NDRIntField("pcmsPollsMax", 0),
        NDRIntField("pcRetry", 0),
        NDRIntField("pcmsRetryDelay", 0),
        NDRShortField("picxr", 0),
        NDRFullPointerField(NDRConfVarStrNullField("szDNPrefix", "")),
        NDRFullPointerField(NDRConfVarStrNullField("szDisplayName", "")),
        StrFixedLenFieldUtf16("rgwServerVersion", "", length=3 * 2),
        StrFixedLenFieldUtf16("rgwBestVersion", "", length=3 * 2),
        NDRIntField("pulTimeStamp", 0),
        NDRConfVarStrLenField(
            "rgbAuxOut",
            "",
            size_is=lambda pkt: pkt.pcbAuxOut,
            length_is=lambda pkt: pkt.pcbAuxOut,
        ),
        NDRIntField("pcbAuxOut", None, size_of="rgbAuxOut"),
        NDRIntField("status", 0),
    ]


class EcDoRpcExt2_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("pcxh", NDRContextHandle(), NDRContextHandle),
        NDRIntField("pulFlags", 0),
        NDRConfStrLenField("rgbIn", "", size_is=lambda pkt: pkt.cbIn),
        NDRIntField("cbIn", None, size_of="rgbIn"),
        NDRIntField("pcbOut", 0),
        NDRConfStrLenField("rgbAuxIn", "", size_is=lambda pkt: pkt.cbAuxIn),
        NDRIntField("cbAuxIn", None, size_of="rgbAuxIn"),
        NDRIntField("pcbAuxOut", 0),
    ]


class EcDoRpcExt2_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("pcxh", NDRContextHandle(), NDRContextHandle),
        NDRIntField("pulFlags", 0),
        NDRConfVarStrLenField(
            "rgbOut",
            "",
            size_is=lambda pkt: pkt.pcbOut,
            length_is=lambda pkt: pkt.pcbOut,
        ),
        NDRIntField("pcbOut", None, size_of="rgbOut"),
        NDRConfVarStrLenField(
            "rgbAuxOut",
            "",
            size_is=lambda pkt: pkt.pcbAuxOut,
            length_is=lambda pkt: pkt.pcbAuxOut,
        ),
        NDRIntField("pcbAuxOut", None, size_of="rgbAuxOut"),
        NDRIntField("pulTransTime", 0),
        NDRIntField("status", 0),
    ]


class Opnum12Reserved_Request(NDRPacket):
    fields_desc = []


class Opnum12Reserved_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class Opnum13Reserved_Request(NDRPacket):
    fields_desc = []


class Opnum13Reserved_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class EcDoAsyncConnectEx_Request(NDRPacket):
    fields_desc = [NDRPacketField("cxh", NDRContextHandle(), NDRContextHandle)]


class EcDoAsyncConnectEx_Response(NDRPacket):
    fields_desc = [
        NDRPacketField("pacxh", NDRContextHandle(), NDRContextHandle),
        NDRIntField("status", 0),
    ]


EMSMDB_OPNUMS = {
    0: DceRpcOp(Opnum0Reserved_Request, Opnum0Reserved_Response),
    1: DceRpcOp(EcDoDisconnect_Request, EcDoDisconnect_Response),
    2: DceRpcOp(Opnum2Reserved_Request, Opnum2Reserved_Response),
    3: DceRpcOp(Opnum3Reserved_Request, Opnum3Reserved_Response),
    4: DceRpcOp(
        EcRRegisterPushNotification_Request, EcRRegisterPushNotification_Response
    ),
    5: DceRpcOp(Opnum5Reserved_Request, Opnum5Reserved_Response),
    6: DceRpcOp(EcDummyRpc_Request, EcDummyRpc_Response),
    7: DceRpcOp(Opnum7Reserved_Request, Opnum7Reserved_Response),
    8: DceRpcOp(Opnum8Reserved_Request, Opnum8Reserved_Response),
    9: DceRpcOp(Opnum9Reserved_Request, Opnum9Reserved_Response),
    10: DceRpcOp(EcDoConnectEx_Request, EcDoConnectEx_Response),
    11: DceRpcOp(EcDoRpcExt2_Request, EcDoRpcExt2_Response),
    12: DceRpcOp(Opnum12Reserved_Request, Opnum12Reserved_Response),
    13: DceRpcOp(Opnum13Reserved_Request, Opnum13Reserved_Response),
    14: DceRpcOp(EcDoAsyncConnectEx_Request, EcDoAsyncConnectEx_Response),
}
register_dcerpc_interface(
    name="emsmdb",
    uuid=uuid.UUID("A4F1DB00-CA47-1067-B31F-00DD010662DA"),
    version="0.81",
    opnums=EMSMDB_OPNUMS,
)


class EcDoAsyncWaitEx_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("acxh", NDRContextHandle(), NDRContextHandle),
        NDRIntField("ulFlagsIn", 0),
    ]


class EcDoAsyncWaitEx_Response(NDRPacket):
    fields_desc = [NDRIntField("pulFlagsOut", 0), NDRIntField("status", 0)]


ASYNCEMSMDB_OPNUMS = {0: DceRpcOp(EcDoAsyncWaitEx_Request, EcDoAsyncWaitEx_Response)}
register_dcerpc_interface(
    name="asyncemsmdb",
    uuid=uuid.UUID("5261574A-4572-206E-B268-6B199213B4E4"),
    version="0.01",
    opnums=ASYNCEMSMDB_OPNUMS,
)
