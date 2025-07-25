# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

# [ms-fax] v29.0 (Tue, 23 Apr 2024)

"""
RPC definitions for the following interfaces:
-
This file is auto-generated by midl-to-scapy, do not modify.
"""

from enum import IntEnum
import uuid


from scapy.layers.dcerpc import (
    NDRPacket,
    NDRConfFieldListField,
    NDRConfVarStrNullField,
    NDRConfVarStrNullFieldUtf16,
    NDRFieldListField,
    NDRFullEmbPointerField,
    NDRInt3264EnumField,
    NDRInt3264Field,
    NDRIntField,
    NDRPacketField,
    NDRShortField,
    NDRSignedIntField,
    NDRUnionField,
)


class FAX_COVERPAGE_INFO_EXW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwCoverPageFormat", 0),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("lpwstrCoverPageFileName", "")
        ),
        NDRSignedIntField("bServerBased", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrNote", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrSubject", "")),
    ]


class PFAX_COVERPAGE_INFO_EXW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwCoverPageFormat", 0),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("lpwstrCoverPageFileName", "")
        ),
        NDRSignedIntField("bServerBased", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrNote", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrSubject", "")),
    ]


class LPCFAX_COVERPAGE_INFO_EXW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwCoverPageFormat", 0),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("lpwstrCoverPageFileName", "")
        ),
        NDRSignedIntField("bServerBased", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrNote", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrSubject", "")),
    ]


class SYSTEMTIME(NDRPacket):
    ALIGNMENT = (2, 2)
    fields_desc = [
        NDRShortField("wYear", 0),
        NDRShortField("wMonth", 0),
        NDRShortField("wDayOfWeek", 0),
        NDRShortField("wDay", 0),
        NDRShortField("wHour", 0),
        NDRShortField("wMinute", 0),
        NDRShortField("wSecond", 0),
        NDRShortField("wMilliseconds", 0),
    ]


class FAX_JOB_PARAMW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("SizeOfStruct", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("RecipientNumber", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("RecipientName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("Tsid", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("SenderName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("SenderCompany", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("SenderDept", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("BillingCode", "")),
        NDRIntField("ScheduleAction", 0),
        NDRPacketField("ScheduleTime", SYSTEMTIME(), SYSTEMTIME),
        NDRIntField("DeliveryReportType", 0),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("DeliveryReportAddress", "")
        ),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("DocumentName", "")),
        NDRIntField("CallHandle", 0),
        NDRFieldListField(
            "Reserved", [], NDRInt3264Field("", 0), length_is=lambda _: 3
        ),
    ]


class PFAX_JOB_PARAMW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("SizeOfStruct", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("RecipientNumber", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("RecipientName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("Tsid", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("SenderName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("SenderCompany", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("SenderDept", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("BillingCode", "")),
        NDRIntField("ScheduleAction", 0),
        NDRPacketField("ScheduleTime", SYSTEMTIME(), SYSTEMTIME),
        NDRIntField("DeliveryReportType", 0),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("DeliveryReportAddress", "")
        ),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("DocumentName", "")),
        NDRIntField("CallHandle", 0),
        NDRFieldListField(
            "Reserved", [], NDRInt3264Field("", 0), length_is=lambda _: 3
        ),
    ]


class FAX_ENUM_DEVICE_RECEIVE_MODE(IntEnum):
    FAX_DEVICE_RECEIVE_MODE_OFF = 0
    FAX_DEVICE_RECEIVE_MODE_AUTO = 1
    FAX_DEVICE_RECEIVE_MODE_MANUAL = 2


class FAX_ENUM_GROUP_STATUS(IntEnum):
    FAX_GROUP_STATUS_ALL_DEV_VALID = 0
    FAX_GROUP_STATUS_EMPTY = 1
    FAX_GROUP_STATUS_ALL_DEV_NOT_VALID = 2
    FAX_GROUP_STATUS_SOME_DEV_NOT_VALID = 3


class FAX_ENUM_MESSAGE_FOLDER(IntEnum):
    FAX_MESSAGE_FOLDER_INBOX = 0
    FAX_MESSAGE_FOLDER_SENTITEMS = 1
    FAX_MESSAGE_FOLDER_QUEUE = 2


class FAX_ENUM_PERSONAL_PROF_TYPES(IntEnum):
    RECIPIENT_PERSONAL_PROF = 1
    SENDER_PERSONAL_PROF = 2


class FAX_ENUM_PRIORITY_TYPE(IntEnum):
    FAX_PRIORITY_TYPE_LOW = 0
    FAX_PRIORITY_TYPE_NORMAL = 1
    FAX_PRIORITY_TYPE_HIGH = 2


class FAX_ENUM_SMTP_AUTH_OPTIONS(IntEnum):
    FAX_SMTP_AUTH_ANONYMOUS = 0
    FAX_SMTP_AUTH_BASIC = 1
    FAX_SMTP_AUTH_NTLM = 2


class PRODUCT_SKU_TYPE(IntEnum):
    PRODUCT_SKU_UNKNOWN = 0
    PRODUCT_SKU_PERSONAL = 1
    PRODUCT_SKU_PROFESSIONAL = 2
    PRODUCT_SKU_SERVER = 4
    PRODUCT_SKU_ADVANCED_SERVER = 8
    PRODUCT_SKU_DATA_CENTER = 16
    PRODUCT_SKU_DESKTOP_EMBEDDED = 32
    PRODUCT_SKU_SERVER_EMBEDDED = 64
    PRODUCT_SKU_WEB_SERVER = 128


class FAX_ENUM_CONFIG_OPTION(IntEnum):
    FAX_CONFIG_OPTION_ALLOW_PERSONAL_CP = 0
    FAX_CONFIG_OPTION_QUEUE_STATE = 1
    FAX_CONFIG_OPTION_ALLOWED_RECEIPTS = 2
    FAX_CONFIG_OPTION_INCOMING_FAXES_PUBLIC = 3


class FAX_TIME(NDRPacket):
    ALIGNMENT = (2, 2)
    fields_desc = [NDRShortField("Hour", 0), NDRShortField("Minute", 0)]


class PFAX_TIME(NDRPacket):
    ALIGNMENT = (2, 2)
    fields_desc = [NDRShortField("Hour", 0), NDRShortField("Minute", 0)]


class FAX_RECEIPTS_CONFIGW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwAllowedReceipts", 0),
        NDRInt3264EnumField("SMTPAuthOption", 0, FAX_ENUM_SMTP_AUTH_OPTIONS),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrReserved", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrSMTPServer", "")),
        NDRIntField("dwSMTPPort", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrSMTPFrom", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrSMTPUserName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrSMTPPassword", "")),
        NDRSignedIntField("bIsToUseForMSRouteThroughEmailMethod", 0),
    ]


class PFAX_RECEIPTS_CONFIGW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwAllowedReceipts", 0),
        NDRInt3264EnumField("SMTPAuthOption", 0, FAX_ENUM_SMTP_AUTH_OPTIONS),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrReserved", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrSMTPServer", "")),
        NDRIntField("dwSMTPPort", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrSMTPFrom", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrSMTPUserName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrSMTPPassword", "")),
        NDRSignedIntField("bIsToUseForMSRouteThroughEmailMethod", 0),
    ]


class FAX_CONFIGURATIONW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("SizeOfStruct", 0),
        NDRIntField("Retries", 0),
        NDRIntField("RetryDelay", 0),
        NDRIntField("DirtyDays", 0),
        NDRSignedIntField("Branding", 0),
        NDRSignedIntField("UseDeviceTsid", 0),
        NDRSignedIntField("ServerCp", 0),
        NDRSignedIntField("PauseServerQueue", 0),
        NDRPacketField("StartCheapTime", FAX_TIME(), FAX_TIME),
        NDRPacketField("StopCheapTime", FAX_TIME(), FAX_TIME),
        NDRSignedIntField("ArchiveOutgoingFaxes", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("ArchiveDirectory", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("ProfileName", "")),
    ]


class PFAX_CONFIGURATIONW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("SizeOfStruct", 0),
        NDRIntField("Retries", 0),
        NDRIntField("RetryDelay", 0),
        NDRIntField("DirtyDays", 0),
        NDRSignedIntField("Branding", 0),
        NDRSignedIntField("UseDeviceTsid", 0),
        NDRSignedIntField("ServerCp", 0),
        NDRSignedIntField("PauseServerQueue", 0),
        NDRPacketField("StartCheapTime", FAX_TIME(), FAX_TIME),
        NDRPacketField("StopCheapTime", FAX_TIME(), FAX_TIME),
        NDRSignedIntField("ArchiveOutgoingFaxes", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("ArchiveDirectory", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("ProfileName", "")),
    ]


class FAX_GLOBAL_ROUTING_INFOW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("SizeOfStruct", 0),
        NDRIntField("Priority", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("Guid", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("FriendlyName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("FunctionName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("ExtensionImageName", "")),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("ExtensionFriendlyName", "")
        ),
    ]


class PFAX_GLOBAL_ROUTING_INFOW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("SizeOfStruct", 0),
        NDRIntField("Priority", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("Guid", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("FriendlyName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("FunctionName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("ExtensionImageName", "")),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("ExtensionFriendlyName", "")
        ),
    ]


class FAX_JOB_PARAM_EXW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwScheduleAction", 0),
        NDRPacketField("tmSchedule", SYSTEMTIME(), SYSTEMTIME),
        NDRIntField("dwReceiptDeliveryType", 0),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("lpwstrReceiptDeliveryAddress", "")
        ),
        NDRInt3264EnumField("Priority", 0, FAX_ENUM_PRIORITY_TYPE),
        NDRIntField("hCall", 0),
        NDRFieldListField(
            "dwReserved", [], NDRInt3264Field("", 0), length_is=lambda _: 4
        ),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrDocumentName", "")),
        NDRIntField("dwPageCount", 0),
    ]


class PFAX_JOB_PARAM_EXW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwScheduleAction", 0),
        NDRPacketField("tmSchedule", SYSTEMTIME(), SYSTEMTIME),
        NDRIntField("dwReceiptDeliveryType", 0),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("lpwstrReceiptDeliveryAddress", "")
        ),
        NDRInt3264EnumField("Priority", 0, FAX_ENUM_PRIORITY_TYPE),
        NDRIntField("hCall", 0),
        NDRFieldListField(
            "dwReserved", [], NDRInt3264Field("", 0), length_is=lambda _: 4
        ),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrDocumentName", "")),
        NDRIntField("dwPageCount", 0),
    ]


class LPCFAX_JOB_PARAM_EXW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwScheduleAction", 0),
        NDRPacketField("tmSchedule", SYSTEMTIME(), SYSTEMTIME),
        NDRIntField("dwReceiptDeliveryType", 0),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("lpwstrReceiptDeliveryAddress", "")
        ),
        NDRInt3264EnumField("Priority", 0, FAX_ENUM_PRIORITY_TYPE),
        NDRIntField("hCall", 0),
        NDRFieldListField(
            "dwReserved", [], NDRInt3264Field("", 0), length_is=lambda _: 4
        ),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrDocumentName", "")),
        NDRIntField("dwPageCount", 0),
    ]


class RPC_FAX_OUTBOUND_ROUTING_GROUPW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrGroupName", "")),
        NDRIntField("dwNumDevices", None, size_of="lpdwDevices"),
        NDRFullEmbPointerField(
            NDRConfFieldListField(
                "lpdwDevices", [], NDRIntField, size_is=lambda pkt: pkt.dwNumDevices
            )
        ),
        NDRInt3264EnumField("Status", 0, FAX_ENUM_GROUP_STATUS),
    ]


class PRPC_FAX_OUTBOUND_ROUTING_GROUPW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrGroupName", "")),
        NDRIntField("dwNumDevices", None, size_of="lpdwDevices"),
        NDRFullEmbPointerField(
            NDRConfFieldListField(
                "lpdwDevices", [], NDRIntField, size_is=lambda pkt: pkt.dwNumDevices
            )
        ),
        NDRInt3264EnumField("Status", 0, FAX_ENUM_GROUP_STATUS),
    ]


class FAX_PORT_INFO(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("SizeOfStruct", 0),
        NDRIntField("DeviceId", 0),
        NDRIntField("State", 0),
        NDRIntField("Flags", 0),
        NDRIntField("Rings", 0),
        NDRIntField("Priority", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("DeviceName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("Tsid", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("Csid", "")),
    ]


class PFAX_PORT_INFO(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("SizeOfStruct", 0),
        NDRIntField("DeviceId", 0),
        NDRIntField("State", 0),
        NDRIntField("Flags", 0),
        NDRIntField("Rings", 0),
        NDRIntField("Priority", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("DeviceName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("Tsid", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("Csid", "")),
    ]


class FAX_ENUM_RULE_STATUS(IntEnum):
    FAX_RULE_STATUS_VALID = 0
    FAX_RULE_STATUS_EMPTY_GROUP = 1
    FAX_RULE_STATUS_ALL_GROUP_DEV_NOT_VALID = 2
    FAX_RULE_STATUS_SOME_GROUP_DEV_NOT_VALID = 3
    FAX_RULE_STATUS_BAD_DEVICE = 4


class RPC_FAX_OUTBOUND_ROUTING_RULEW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwAreaCode", 0),
        NDRIntField("dwCountryCode", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrCountryName", "")),
        NDRUnionField(
            [
                (
                    NDRIntField("Destination", 0),
                    (
                        (lambda pkt: getattr(pkt, "bUseGroup", None) == 0),
                        (lambda _, val: val.tag == 0),
                    ),
                )
            ],
            NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("Destination", "")),
            align=(4, 8),
            switch_fmt=("l", "l"),
        ),
        NDRSignedIntField("bUseGroup", 0),
    ]


class RPC_PFAX_OUTBOUND_ROUTING_RULEW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwAreaCode", 0),
        NDRIntField("dwCountryCode", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrCountryName", "")),
        NDRUnionField(
            [
                (
                    NDRIntField("Destination", 0),
                    (
                        (lambda pkt: getattr(pkt, "bUseGroup", None) == 0),
                        (lambda _, val: val.tag == 0),
                    ),
                )
            ],
            NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("Destination", "")),
            align=(4, 8),
            switch_fmt=("l", "l"),
        ),
        NDRSignedIntField("bUseGroup", 0),
    ]


class FAX_VERSION(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRSignedIntField("bValid", 0),
        NDRShortField("wMajorVersion", 0),
        NDRShortField("wMinorVersion", 0),
        NDRShortField("wMajorBuildNumber", 0),
        NDRShortField("wMinorBuildNumber", 0),
        NDRIntField("dwFlags", 0),
    ]


class PFAX_VERSION(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRSignedIntField("bValid", 0),
        NDRShortField("wMajorVersion", 0),
        NDRShortField("wMinorVersion", 0),
        NDRShortField("wMajorBuildNumber", 0),
        NDRShortField("wMinorBuildNumber", 0),
        NDRIntField("dwFlags", 0),
    ]


class FAX_OUTBOX_CONFIG(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRSignedIntField("bAllowPersonalCP", 0),
        NDRSignedIntField("bUseDeviceTSID", 0),
        NDRIntField("dwRetries", 0),
        NDRIntField("dwRetryDelay", 0),
        NDRPacketField("dtDiscountStart", FAX_TIME(), FAX_TIME),
        NDRPacketField("dtDiscountEnd", FAX_TIME(), FAX_TIME),
        NDRIntField("dwAgeLimit", 0),
        NDRSignedIntField("bBranding", 0),
    ]


class PFAX_OUTBOX_CONFIG(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRSignedIntField("bAllowPersonalCP", 0),
        NDRSignedIntField("bUseDeviceTSID", 0),
        NDRIntField("dwRetries", 0),
        NDRIntField("dwRetryDelay", 0),
        NDRPacketField("dtDiscountStart", FAX_TIME(), FAX_TIME),
        NDRPacketField("dtDiscountEnd", FAX_TIME(), FAX_TIME),
        NDRIntField("dwAgeLimit", 0),
        NDRSignedIntField("bBranding", 0),
    ]


class FAX_ACTIVITY_LOGGING_CONFIGW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRSignedIntField("bLogIncoming", 0),
        NDRSignedIntField("bLogOutgoing", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrDBPath", "")),
    ]


class PFAX_ACTIVITY_LOGGING_CONFIGW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRSignedIntField("bLogIncoming", 0),
        NDRSignedIntField("bLogOutgoing", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrDBPath", "")),
    ]


class FAX_PORT_INFO_EXW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwDeviceID", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrDeviceName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrDescription", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrProviderName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrProviderGUID", "")),
        NDRSignedIntField("bSend", 0),
        NDRInt3264EnumField("ReceiveMode", 0, FAX_ENUM_DEVICE_RECEIVE_MODE),
        NDRIntField("dwStatus", 0),
        NDRIntField("dwRings", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrCsid", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrTsid", "")),
    ]


class PFAX_PORT_INFO_EXW(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwDeviceID", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrDeviceName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrDescription", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrProviderName", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrProviderGUID", "")),
        NDRSignedIntField("bSend", 0),
        NDRInt3264EnumField("ReceiveMode", 0, FAX_ENUM_DEVICE_RECEIVE_MODE),
        NDRIntField("dwStatus", 0),
        NDRIntField("dwRings", 0),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrCsid", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpwstrTsid", "")),
    ]


class FAX_SERVER_ACTIVITY(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwIncomingMessages", 0),
        NDRIntField("dwRoutingMessages", 0),
        NDRIntField("dwOutgoingMessages", 0),
        NDRIntField("dwDelegatedOutgoingMessages", 0),
        NDRIntField("dwQueuedMessages", 0),
        NDRIntField("dwErrorEvents", 0),
        NDRIntField("dwWarningEvents", 0),
        NDRIntField("dwInformationEvents", 0),
    ]


class PFAX_SERVER_ACTIVITY(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [
        NDRIntField("dwSizeOfStruct", 0),
        NDRIntField("dwIncomingMessages", 0),
        NDRIntField("dwRoutingMessages", 0),
        NDRIntField("dwOutgoingMessages", 0),
        NDRIntField("dwDelegatedOutgoingMessages", 0),
        NDRIntField("dwQueuedMessages", 0),
        NDRIntField("dwErrorEvents", 0),
        NDRIntField("dwWarningEvents", 0),
        NDRIntField("dwInformationEvents", 0),
    ]


class FAX_REASSIGN_INFO(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrRecipients", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrSenderName", "")),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("lpcwstrSenderFaxNumber", "")
        ),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrSubject", "")),
        NDRSignedIntField("bHasCoverPage", 0),
    ]


class PFAX_REASSIGN_INFO(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrRecipients", "")),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrSenderName", "")),
        NDRFullEmbPointerField(
            NDRConfVarStrNullFieldUtf16("lpcwstrSenderFaxNumber", "")
        ),
        NDRFullEmbPointerField(NDRConfVarStrNullFieldUtf16("lpcwstrSubject", "")),
        NDRSignedIntField("bHasCoverPage", 0),
    ]


class FAX_MESSAGE_PROPS(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [NDRIntField("dwValidityMask", 0), NDRIntField("dwMsgFlags", 0)]


class PFAX_MESSAGE_PROPS(NDRPacket):
    ALIGNMENT = (4, 4)
    fields_desc = [NDRIntField("dwValidityMask", 0), NDRIntField("dwMsgFlags", 0)]


class FAX_JOB_ENTRY(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("SizeOfStruct", 0),
        NDRIntField("JobId", 0),
        NDRFullEmbPointerField(NDRShortField("UserName", 0)),
        NDRIntField("JobType", 0),
        NDRIntField("QueueStatus", 0),
        NDRIntField("Status", 0),
        NDRIntField("Size", 0),
        NDRIntField("PageCount", 0),
        NDRFullEmbPointerField(NDRShortField("RecipientNumber", 0)),
        NDRFullEmbPointerField(NDRShortField("RecipientName", 0)),
        NDRFullEmbPointerField(NDRShortField("Tsid", 0)),
        NDRFullEmbPointerField(NDRShortField("SenderName", 0)),
        NDRFullEmbPointerField(NDRShortField("SenderCompany", 0)),
        NDRFullEmbPointerField(NDRShortField("SenderDept", 0)),
        NDRFullEmbPointerField(NDRShortField("BillingCode", 0)),
        NDRIntField("ScheduleAction", 0),
        NDRPacketField("ScheduleTime", SYSTEMTIME(), SYSTEMTIME),
        NDRIntField("DeliveryReportType", 0),
        NDRFullEmbPointerField(NDRShortField("DeliveryReportAddress", 0)),
        NDRFullEmbPointerField(NDRShortField("DocumentName", 0)),
    ]


class PFAX_JOB_ENTRY(NDRPacket):
    ALIGNMENT = (4, 8)
    fields_desc = [
        NDRIntField("SizeOfStruct", 0),
        NDRIntField("JobId", 0),
        NDRFullEmbPointerField(NDRShortField("UserName", 0)),
        NDRIntField("JobType", 0),
        NDRIntField("QueueStatus", 0),
        NDRIntField("Status", 0),
        NDRIntField("Size", 0),
        NDRIntField("PageCount", 0),
        NDRFullEmbPointerField(NDRShortField("RecipientNumber", 0)),
        NDRFullEmbPointerField(NDRShortField("RecipientName", 0)),
        NDRFullEmbPointerField(NDRShortField("Tsid", 0)),
        NDRFullEmbPointerField(NDRShortField("SenderName", 0)),
        NDRFullEmbPointerField(NDRShortField("SenderCompany", 0)),
        NDRFullEmbPointerField(NDRShortField("SenderDept", 0)),
        NDRFullEmbPointerField(NDRShortField("BillingCode", 0)),
        NDRIntField("ScheduleAction", 0),
        NDRPacketField("ScheduleTime", SYSTEMTIME(), SYSTEMTIME),
        NDRIntField("DeliveryReportType", 0),
        NDRFullEmbPointerField(NDRShortField("DeliveryReportAddress", 0)),
        NDRFullEmbPointerField(NDRShortField("DocumentName", 0)),
    ]
