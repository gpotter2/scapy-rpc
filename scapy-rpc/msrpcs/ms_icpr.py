# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

# [ms-icpr] v24.0 (Tue, 23 Apr 2024)

"""
RPC definitions for the following interfaces:
- ICertPassage (v0.0): 91ae6020-9e3c-11cf-8d7c-00aa00c091be
This file is auto-generated by midl-to-scapy, do not modify.
"""

import uuid


from scapy.layers.dcerpc import (
    NDRPacket,
    DceRpcOp,
    NDRConfStrLenField,
    NDRConfVarStrNullField,
    NDRConfVarStrNullFieldUtf16,
    NDRFullEmbPointerField,
    NDRFullPointerField,
    NDRIntField,
    NDRPacketField,
    register_dcerpc_interface,
)


class CERTTRANSBLOB(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("cb", None, size_of="pb"),
        NDRFullEmbPointerField(
            NDRConfStrLenField("pb", "", size_is=lambda pkt: pkt.cb)
        ),
    ]


class CertServerRequest_Request(NDRPacket):
    fields_desc = [
        NDRIntField("dwFlags", 0),
        NDRFullPointerField(NDRConfVarStrNullFieldUtf16("pwszAuthority", "")),
        NDRIntField("pdwRequestId", 0),
        NDRPacketField("pctbAttribs", CERTTRANSBLOB(), CERTTRANSBLOB),
        NDRPacketField("pctbRequest", CERTTRANSBLOB(), CERTTRANSBLOB),
    ]


class CertServerRequest_Response(NDRPacket):
    fields_desc = [
        NDRIntField("pdwRequestId", 0),
        NDRIntField("pdwDisposition", 0),
        NDRPacketField("pctbCert", CERTTRANSBLOB(), CERTTRANSBLOB),
        NDRPacketField("pctbEncodedCert", CERTTRANSBLOB(), CERTTRANSBLOB),
        NDRPacketField("pctbDispositionMessage", CERTTRANSBLOB(), CERTTRANSBLOB),
        NDRIntField("status", 0),
    ]


ICERTPASSAGE_OPNUMS = {
    0: DceRpcOp(CertServerRequest_Request, CertServerRequest_Response)
}
register_dcerpc_interface(
    name="ICertPassage",
    uuid=uuid.UUID("91ae6020-9e3c-11cf-8d7c-00aa00c091be"),
    version="0.0",
    opnums=ICERTPASSAGE_OPNUMS,
)
