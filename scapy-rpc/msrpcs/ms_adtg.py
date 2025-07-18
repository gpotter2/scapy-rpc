# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

# [ms-adtg] v19.1 (Fri, 30 May 2025)

"""
RPC definitions for the following interfaces:
- IUnknown (v0.0): 00000000-0000-0000-C000-000000000046
- IDataFactory (v0.0): 0EAC4842-8763-11cf-A743-00AA00A3F00D
- IDataFactory2 (v0.0): 070669EB-B52F-11d1-9270-00C04FBBBFB3
- IDataFactory3 (v0.0): 4639DB2A-BFC5-11d2-9318-00C04FBBBFB3
This file is auto-generated by midl-to-scapy, do not modify.
"""

from enum import IntEnum
import uuid


from scapy.layers.dcerpc import (
    NDRPacket,
    DceRpcOp,
    NDRConfPacketListField,
    NDRConfStrLenField,
    NDRConfStrLenFieldUtf16,
    NDRFullPointerField,
    NDRIntField,
    NDRPacketField,
    NDRRecursiveField,
    NDRRefEmbPointerField,
    NDRShortField,
    NDRSignedIntField,
    NDRSignedLongField,
    register_com_interface,
    register_dcerpc_interface,
)

IUNKNOWN_OPNUMS = {  # 0: Opnum0NotUsedOnWire,
    # 1: Opnum1NotUsedOnWire,
    # 2: Opnum2NotUsedOnWire
}
register_com_interface(
    name="IUnknown",
    uuid=uuid.UUID("00000000-0000-0000-C000-000000000046"),
    opnums=IUNKNOWN_OPNUMS,
)


class FLAGGED_WORD_BLOB(NDRPacket):
    ALIGNMENT = (4, 8)
    DEPORTED_CONFORMANTS = ["asData"]
    fields_desc = [
        NDRIntField("cBytes", 0),
        NDRIntField("clSize", None, size_of="asData"),
        NDRConfStrLenFieldUtf16(
            "asData", "", size_is=lambda pkt: pkt.clSize, conformant_in_struct=True
        ),
    ]


class MInterfacePointer(NDRPacket):
    ALIGNMENT = (4, 8)
    DEPORTED_CONFORMANTS = ["abData"]
    fields_desc = [
        NDRIntField("ulCntData", None, size_of="abData"),
        NDRConfStrLenField(
            "abData", "", size_is=lambda pkt: pkt.ulCntData, conformant_in_struct=True
        ),
    ]


class Query_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("bstrConnection", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRPacketField("bstrQuery", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRSignedIntField("lMarshalOptions", 0),
    ]


class Query_Response(NDRPacket):
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField("ppRecordset", MInterfacePointer(), MInterfacePointer)
        ),
        NDRIntField("status", 0),
    ]


class SubmitChanges_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("bstrConnection", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRPacketField("pRecordset", MInterfacePointer(), MInterfacePointer),
    ]


class SubmitChanges_Response(NDRPacket):
    fields_desc = [NDRIntField("status", 0)]


class ConvertToString_Request(NDRPacket):
    fields_desc = [NDRPacketField("punkObject", MInterfacePointer(), MInterfacePointer)]


class ConvertToString_Response(NDRPacket):
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField("pbstrInline", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB)
        ),
        NDRIntField("status", 0),
    ]


class VARENUM(IntEnum):
    VT_EMPTY = 0
    VT_NULL = 1
    VT_I2 = 2
    VT_I4 = 3
    VT_R4 = 4
    VT_R8 = 5
    VT_CY = 6
    VT_DATE = 7
    VT_BSTR = 8
    VT_DISPATCH = 9
    VT_ERROR = 10
    VT_BOOL = 11
    VT_VARIANT = 12
    VT_UNKNOWN = 13
    VT_DECIMAL = 14
    VT_I1 = 16
    VT_UI1 = 17
    VT_UI2 = 18
    VT_UI4 = 19
    VT_I8 = 20
    VT_UI8 = 21
    VT_INT = 22
    VT_UINT = 23
    VT_VOID = 24
    VT_HRESULT = 25
    VT_PTR = 26
    VT_SAFEARRAY = 27
    VT_CARRAY = 28
    VT_USERDEFINED = 29
    VT_LPSTR = 30
    VT_LPWSTR = 31
    VT_RECORD = 36
    VT_INT_PTR = 37
    VT_UINT_PTR = 38
    VT_ARRAY = 8192
    VT_BYREF = 16384


class CURRENCY(NDRPacket):
    ALIGNMENT = (8, 8)
    fields_desc = [NDRSignedLongField("int64", 0)]


class SF_TYPE(IntEnum):
    SF_ERROR = VARENUM.VT_ERROR
    SF_I1 = VARENUM.VT_I1
    SF_I2 = VARENUM.VT_I2
    SF_I4 = VARENUM.VT_I4
    SF_I8 = VARENUM.VT_I8
    SF_BSTR = VARENUM.VT_BSTR
    SF_UNKNOWN = VARENUM.VT_UNKNOWN
    SF_DISPATCH = VARENUM.VT_DISPATCH
    SF_VARIANT = VARENUM.VT_VARIANT
    SF_RECORD = VARENUM.VT_RECORD
    SF_HAVEIID = VARENUM.VT_UNKNOWN | 32768


class SAFEARR_BSTR(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("Size", None, size_of="aBstr"),
        NDRRefEmbPointerField(
            NDRConfPacketListField(
                "aBstr", [], FLAGGED_WORD_BLOB, size_is=lambda pkt: pkt.Size
            )
        ),
    ]


class SAFEARR_UNKNOWN(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("Size", None, size_of="apUnknown"),
        NDRRefEmbPointerField(
            NDRConfPacketListField(
                "apUnknown", [], MInterfacePointer, size_is=lambda pkt: pkt.Size
            )
        ),
    ]


class SAFEARR_DISPATCH(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("Size", None, size_of="apDispatch"),
        NDRRefEmbPointerField(
            NDRConfPacketListField(
                "apDispatch", [], MInterfacePointer, size_is=lambda pkt: pkt.Size
            )
        ),
    ]


class wireVARIANTStr(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRIntField("clSize", 0),
        NDRIntField("rpcReserved", 0),
        NDRShortField("vt", 0),
        NDRShortField("wReserved1", 0),
        NDRShortField("wReserved2", 0),
        NDRShortField("wReserved3", 0),
        NDRRecursiveField("_varUnion"),
    ]


class CreateRecordSet_Request(NDRPacket):
    fields_desc = [NDRPacketField("varColumnInfos", wireVARIANTStr(), wireVARIANTStr)]


class CreateRecordSet_Response(NDRPacket):
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField("ppDispatch", MInterfacePointer(), MInterfacePointer)
        ),
        NDRIntField("status", 0),
    ]


IDATAFACTORY_OPNUMS = {  # 0: Opnum0NotUsedOnWire,
    # 1: Opnum1NotUsedOnWire,
    # 2: Opnum2NotUsedOnWire,
    3: DceRpcOp(Query_Request, Query_Response),
    4: DceRpcOp(SubmitChanges_Request, SubmitChanges_Response),
    5: DceRpcOp(ConvertToString_Request, ConvertToString_Response),
    6: DceRpcOp(CreateRecordSet_Request, CreateRecordSet_Response),
}
register_dcerpc_interface(
    name="IDataFactory",
    uuid=uuid.UUID("0EAC4842-8763-11cf-A743-00AA00A3F00D"),
    version="0.0",
    opnums=IDATAFACTORY_OPNUMS,
)


class Execute21_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("ConnectionString", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRPacketField("HandlerString", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRPacketField("QueryString", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRSignedIntField("lMarshalOptions", 0),
        NDRPacketField("Properties", wireVARIANTStr(), wireVARIANTStr),
        NDRPacketField("TableId", wireVARIANTStr(), wireVARIANTStr),
        NDRSignedIntField("lExecuteOptions", 0),
        NDRFullPointerField(
            NDRPacketField("pParameters", wireVARIANTStr(), wireVARIANTStr)
        ),
    ]


class Execute21_Response(NDRPacket):
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField("pParameters", wireVARIANTStr(), wireVARIANTStr)
        ),
        NDRFullPointerField(
            NDRPacketField("ppRecordset", MInterfacePointer(), MInterfacePointer)
        ),
        NDRIntField("status", 0),
    ]


class Synchronize21_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("ConnectionString", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRPacketField("HandlerString", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRSignedIntField("lSynchronizeOptions", 0),
        NDRFullPointerField(
            NDRPacketField("ppRecordset", MInterfacePointer(), MInterfacePointer)
        ),
        NDRFullPointerField(
            NDRPacketField("pStatusArray", wireVARIANTStr(), wireVARIANTStr)
        ),
    ]


class Synchronize21_Response(NDRPacket):
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField("ppRecordset", MInterfacePointer(), MInterfacePointer)
        ),
        NDRFullPointerField(
            NDRPacketField("pStatusArray", wireVARIANTStr(), wireVARIANTStr)
        ),
        NDRFullPointerField(
            NDRPacketField("pResult", wireVARIANTStr(), wireVARIANTStr)
        ),
        NDRIntField("status", 0),
    ]


IDATAFACTORY2_OPNUMS = {  # 0: Opnum0NotUsedOnWire,
    # 1: Opnum1NotUsedOnWire,
    # 2: Opnum2NotUsedOnWire,
    3: DceRpcOp(Query_Request, Query_Response),
    4: DceRpcOp(SubmitChanges_Request, SubmitChanges_Response),
    5: DceRpcOp(ConvertToString_Request, ConvertToString_Response),
    6: DceRpcOp(CreateRecordSet_Request, CreateRecordSet_Response),
    7: DceRpcOp(Execute21_Request, Execute21_Response),
    8: DceRpcOp(Synchronize21_Request, Synchronize21_Response),
}
register_dcerpc_interface(
    name="IDataFactory2",
    uuid=uuid.UUID("070669EB-B52F-11d1-9270-00C04FBBBFB3"),
    version="0.0",
    opnums=IDATAFACTORY2_OPNUMS,
)


class Execute_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("ConnectionString", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRPacketField("HandlerString", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRPacketField("QueryString", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRSignedIntField("lMarshalOptions", 0),
        NDRPacketField("Properties", wireVARIANTStr(), wireVARIANTStr),
        NDRPacketField("TableId", wireVARIANTStr(), wireVARIANTStr),
        NDRSignedIntField("lExecuteOptions", 0),
        NDRFullPointerField(
            NDRPacketField("pParameters", wireVARIANTStr(), wireVARIANTStr)
        ),
        NDRSignedIntField("lcid", 0),
        NDRFullPointerField(
            NDRPacketField("pInformation", wireVARIANTStr(), wireVARIANTStr)
        ),
    ]


class Execute_Response(NDRPacket):
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField("pParameters", wireVARIANTStr(), wireVARIANTStr)
        ),
        NDRFullPointerField(
            NDRPacketField("pInformation", wireVARIANTStr(), wireVARIANTStr)
        ),
        NDRFullPointerField(
            NDRPacketField("ppRecordset", MInterfacePointer(), MInterfacePointer)
        ),
        NDRIntField("status", 0),
    ]


class Synchronize_Request(NDRPacket):
    fields_desc = [
        NDRPacketField("ConnectionString", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRPacketField("HandlerString", FLAGGED_WORD_BLOB(), FLAGGED_WORD_BLOB),
        NDRSignedIntField("lSynchronizeOptions", 0),
        NDRFullPointerField(
            NDRPacketField("ppRecordset", MInterfacePointer(), MInterfacePointer)
        ),
        NDRFullPointerField(
            NDRPacketField("pStatusArray", wireVARIANTStr(), wireVARIANTStr)
        ),
        NDRSignedIntField("lcid", 0),
        NDRFullPointerField(
            NDRPacketField("pInformation", wireVARIANTStr(), wireVARIANTStr)
        ),
    ]


class Synchronize_Response(NDRPacket):
    fields_desc = [
        NDRFullPointerField(
            NDRPacketField("ppRecordset", MInterfacePointer(), MInterfacePointer)
        ),
        NDRFullPointerField(
            NDRPacketField("pStatusArray", wireVARIANTStr(), wireVARIANTStr)
        ),
        NDRFullPointerField(
            NDRPacketField("pInformation", wireVARIANTStr(), wireVARIANTStr)
        ),
        NDRFullPointerField(
            NDRPacketField("pResult", wireVARIANTStr(), wireVARIANTStr)
        ),
        NDRIntField("status", 0),
    ]


IDATAFACTORY3_OPNUMS = {  # 0: Opnum0NotUsedOnWire,
    # 1: Opnum1NotUsedOnWire,
    # 2: Opnum2NotUsedOnWire,
    3: DceRpcOp(Query_Request, Query_Response),
    4: DceRpcOp(SubmitChanges_Request, SubmitChanges_Response),
    5: DceRpcOp(ConvertToString_Request, ConvertToString_Response),
    6: DceRpcOp(CreateRecordSet_Request, CreateRecordSet_Response),
    7: DceRpcOp(Execute21_Request, Execute21_Response),
    8: DceRpcOp(Synchronize21_Request, Synchronize21_Response),
    9: DceRpcOp(Execute_Request, Execute_Response),
    10: DceRpcOp(Synchronize_Request, Synchronize_Response),
}
register_dcerpc_interface(
    name="IDataFactory3",
    uuid=uuid.UUID("4639DB2A-BFC5-11d2-9318-00C04FBBBFB3"),
    version="0.0",
    opnums=IDATAFACTORY3_OPNUMS,
)
