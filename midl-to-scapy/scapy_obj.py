# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information

"""
Scapy pseudo-field definitions and converters.
"""

import copy
import re
import struct
import sys
from utils import Colors

SCAPY_FIELDS = {
    "b": "NDRSignedByteField",
    "B": "NDRByteField",
    "h": "NDRSignedShortField",
    "H": "NDRShortField",
    "i": "NDRSignedIntField",
    "I": "NDRIntField",
    "l": "NDRSignedIntField",
    "L": "NDRIntField",
    "q": "NDRSignedLongField",
    "Q": "NDRLongField",
    "f": "NDRIEEEFloatField",
    "d": "NDRIEEEDoubleField",
    # Special
    "void": "void",
    "__int3264": "NDRSignedInt3264Field",
    "__uint3264": "NDRInt3264Field",
}
_R_SCAPY_FIELDS = {v: k for k, v in SCAPY_FIELDS.items()}

# Types of strings when "string" attribute is present
CHAR_TYPES = ["NDRByteField", "NDRSignedByteField"]
WCHAR_TYPES = ["NDRShortField", "NDRSignedShortField"]

# Types of fields we convert into a string implicitely
IMPLICIT_STRINGS = ["NDRByteField", "NDRSignedByteField", "NDRSignedShortField"]

SCAPY_SIZES = {
    "NDRSignedByteField": 1,
    "NDRByteField": 1,
    "NDRSignedShortField": 2,
    "NDRShortField": 2,
    "NDRSignedIntField": 4,
    "NDRIntField": 4,
    "NDRSignedIntField": 4,
    "NDRIntField": 4,
    "NDRSignedLongField": 8,
    "NDRLongField": 8,
    "NDRIEEEFloatField": 4,
    "NDRIEEEDoubleField": 8,
}


def _lkp(attrs, name):
    try:
        return next(x[1] for x in attrs if x[0] == name)
    except StopIteration:
        return None


## Utils to resolve arithmetic: length_is and size_is


def _rec_rslv_arithm(ar, env=None, getattr=False, prefix="pkt."):
    if isinstance(ar, int):
        return "%d" % ar
    elif isinstance(ar, str):
        return ar
    elif isinstance(ar, tuple):
        if ar[0] == "binop":
            return "(%s %s %s)" % (
                _rec_rslv_arithm(ar[2], env, getattr, prefix),
                ar[1].replace("/", "//"),
                _rec_rslv_arithm(ar[3], env, getattr, prefix),
            )
        elif ar[0] == "monop":
            return "(%s %s)" % (ar[1], _rec_rslv_arithm(ar[2], env, getattr, prefix))
        elif ar[0] in ["id", "ptr"]:
            if env:
                return env[ar[1]]
            else:
                if getattr:
                    return "getattr(pkt, '%s', None)" % ar[1]
                else:
                    return prefix + "%s" % ar[1]
        elif ar[0] == "if":
            return "(%s if %s else %s)" % (
                _rec_rslv_arithm(ar[2], env, getattr, prefix),
                _rec_rslv_arithm(ar[1], env, getattr, prefix),
                _rec_rslv_arithm(ar[3], env, getattr, prefix),
            )
        elif ar[0] == "cast":
            assert ar[1][0] == "id", "Unknown cast type"
            from midl_convert import BUILTIN_TYPES

            typ = BUILTIN_TYPES[ar[1][1]]
            sr = struct.calcsize(typ[0] if isinstance(typ, tuple) else typ)
            return "(%s & 0x%s)" % (
                _rec_rslv_arithm(ar[2], env, getattr, prefix),
                "FF" * sr,
            )
        elif ar[0] == "call" and ar[1] == "sizeof":
            assert all(x[0] == "id" for x in ar[2]), "Unknown sizeof type"
            typespec = [x[1] for x in ar[2]]
            from midl_convert import BUILTIN_TYPES, is_builtin

            if is_builtin(typespec):
                typ = BUILTIN_TYPES[typespec[-1]]
            else:
                # A l'arrache.. arrive dans des #define
                typ = {"WCHAR": "H", "wchar_t": "H"}[typespec[-1]]
            sr = struct.calcsize(typ[0] if isinstance(typ, tuple) else typ)
            return "%s" % sr
    assert False, "Unknown arithmetic expression %s" % repr(ar)


def res_size_is(size_is, getattr=False):
    if isinstance(size_is, list) and len(size_is) == 1:
        if isinstance(size_is[0], tuple) and size_is[0][0] == "arithm_expr":
            return _rec_rslv_arithm(size_is[0][1], getattr=getattr)
        if getattr:
            return "getattr(pkt, '%s', None)" % size_is[0]
        else:
            return "pkt.%s" % size_is[0]
    assert False, "Unknown size_is %s" % repr(size_is)


## Utils to invert arithmetics: length_of and count_of


def _rec_rslv_arithm_getmain(ar):
    """Used to find the main field of a length_is/size_is"""
    if isinstance(ar, int):
        return None
    elif isinstance(ar, tuple):
        parts = []
        if ar[0] == "binop":
            if ar[1] in ["&"]:
                raise ValueError
            parts = [
                x
                for x in [
                    _rec_rslv_arithm_getmain(ar[2]),
                    _rec_rslv_arithm_getmain(ar[3]),
                ]
                if x
            ]
            if len(parts) == 1:
                return parts[0]
            else:
                return None
        elif ar[0] == "monop":
            return _rec_rslv_arithm_getmain(ar[2])
        elif ar[0] in ["id", "ptr"]:
            return ar[1]
        elif ar[0] == "if":
            raise ValueError
        elif ar[0] == "cast":
            raise ValueError
        elif ar[0] == "call" and ar[1] == "sizeof":
            return None
    assert False, "Unknown arithmetic expression %s" % repr(ar)


def res_size_is_getmain(size_is):
    """Recursively iterate and return the id value if there's only one"""
    if (
        isinstance(size_is, list)
        and len(size_is) == 1
        and isinstance(size_is[0], tuple)
        and size_is[0][0] == "arithm_expr"
    ):
        try:
            return _rec_rslv_arithm_getmain(size_is[0][1])
        except ValueError:
            return None
    elif isinstance(size_is, list) and len(size_is) == 1:
        return size_is[0]
    assert False, "Unknown size_is %s" % repr(size_is)


def _rec_invert_arithmetic(ar, cur):
    """Used to invert arithmetics"""
    if isinstance(ar, int):
        return "%d" % ar
    elif isinstance(ar, tuple):
        if ar[0] == "binop":
            sign = {
                "+": "-",
                "-": "+",
                "/": "*",
                "*": "/",
            }[ar[1]]
            if _rec_rslv_arithm_getmain(ar[3]):
                return _rec_invert_arithmetic(ar[3], ("binop", sign, cur, ar[2]))
            else:
                return _rec_invert_arithmetic(ar[2], ("binop", sign, cur, ar[3]))
        elif ar[0] == "monop":
            return _rec_invert_arithmetic(ar[2], ("monop", ar[1], cur))
        elif ar[0] in ["id", "ptr"]:
            return cur
        elif ar[0] == "call" and ar[1] == "sizeof":
            return ar
    assert False, "Unknown arithmetic expression %s" % repr(ar)


def invert_arithmetic(size_is):
    """Recursively iterate and invert arithmetics"""
    if (
        isinstance(size_is, list)
        and len(size_is) == 1
        and isinstance(size_is[0], tuple)
        and size_is[0][0] == "arithm_expr"
    ):
        return _rec_invert_arithmetic(size_is[0][1], ("id", "x"))
    elif isinstance(size_is, list) and len(size_is) == 1:
        return None
    assert False, "Unknown size_is %s" % repr(size_is)


## Utils to resolve Unions


def _rslv_case_expr(switch_attr, switch_type, expr):
    if isinstance(expr, list) and all(
        isinstance(x, tuple) and x[0] == "arithm_expr" for x in expr
    ):
        vals = [_rec_rslv_arithm(x[1]) for x in expr]
        if len(vals) > 1:
            test = "in [%s]" % ",".join(vals)
        elif len(vals) == 1:
            test = "== %s" % vals[0]
        else:
            raise Exception("Impossible")
        return "((lambda pkt: %s %s), (lambda _, val: val.tag %s))" % (
            switch_attr,
            test,
            test,
        )
    assert switch_type, (
        "Error: Using enum values in an Union without switch_type ! :(\nPlease add a switch_type(<enum>) in the idl.\n%s"
        % repr(switch_attr)
    )
    if isinstance(expr, list):
        assert switch_type[0] == "custom", "Unknown enum type ! %s" % repr(expr)
        if isinstance(switch_type[1], str):
            # implicit
            identifier = switch_type[1]
        else:
            identifier = switch_type[1].name
        vals = [
            (
                _rec_rslv_arithm(e[1])
                if isinstance(e, tuple) and e[0] == "arithm_expr"
                else "%s.%s"
                % (
                    identifier,
                    e,
                )
            )
            for e in expr
        ]
        if len(vals) > 1:
            test = "in [%s]" % ",".join(vals)
        elif len(vals) == 1:
            test = "== %s" % vals[0]
        else:
            raise Exception("Impossible")
        return "((lambda pkt: %s %s), (lambda _, val: val.tag %s))" % (
            switch_attr,
            test,
            test,
        )
    assert False, "Unknown case expression %s, %s" % (repr(expr), repr(switch_type))


def _get_switch_fmt(switch_is, context):
    try:
        switch_name = re.match(r".*'(.*)'.*", switch_is).group(1)
    except AttributeError:
        assert False, "Can't parse switch_is: %s" % switch_is
    try:
        fld = next(x for x in context.read_only_fields if x.name == switch_name)
    except StopIteration:
        assert False, "Could not find %s in struct around the NDRUnion !" % switch_name
    if isinstance(fld, ScapyStructField):
        fld = fld.subtype
        assert isinstance(fld, ScapyEnum)
        if "v1_enum" in fld.idl_attributes:
            return ("I", "I")
        return ("H", "I")
    else:
        fmt = _R_SCAPY_FIELDS[fld.scapy_field]
        return (fmt, fmt)


## Utils to handle alignment / conformant counts


class Context:
    """
    Used to store deferred fields and conformant counts

    [C706] sect 14.3.7
    """

    def __init__(self):
        self.conformants = []
        self.root_conformant = None
        self.read_only_fields = []

    def set_current(self, current):
        if not self.conformants:
            self.root_conformant = current

    def add_conformant(self, name):
        if self.root_conformant:
            self.conformants.append(name)

    def get_conformant_count(self, current):
        if self.root_conformant is current and self.conformants:
            return "    DEPORTED_CONFORMANTS=%s\n" % self.conformants
        return ""


def get_alignment(field):
    """
    Returns a tuple (ndr_alignment, ndr64_alignment) for a field.
    """
    # [C706] chap 14
    if isinstance(field, (ScapyStruct, ScapyStructField)):
        if isinstance(field, ScapyStructField):
            if isinstance(field.subtype, ScapyEnum):
                if "v1_enum" in field.subtype.idl_attributes:
                    return (4, 4)
                return (2, 4)
            else:
                fields = field.subtype.fields
        else:
            fields = field.fields
        alignments = [
            (
                (4, 8)
                if any(y in ["ptr", "unique", "ref"] for y in x.idl_attributes)
                else get_alignment(x)
            )
            for x in fields
        ]
        if isinstance(field, ScapyUnion):
            alignments.append((2, 4))
        if isinstance(field, ScapyStructField) and field.is_array:
            # Struct is secretely a conformant array
            alignments.append((4, 8))
        if not alignments:
            return (0, 0)
        return (max(x[0] for x in alignments), max(x[1] for x in alignments))
    elif isinstance(field, ScapyArrayField):
        alignment = get_alignment(field.subtype)
        if field.length:
            # No "information type" as fixed length
            return alignment
        else:
            return max(alignment[0], 4), max(alignment[1], 8)
    return (field.sz, field.sz)


# --- Field definitions


class ScapyField:
    def __init__(self, name, ptr_lvl, scapy_field, field_type_name, idl_attributes):
        self.name = name
        self.ptr_lvl = ptr_lvl
        self.sz = SCAPY_SIZES.get(scapy_field, 1)
        self.scapy_field = scapy_field
        self.field_type = field_type_name
        self.idl_attributes = idl_attributes
        self.inv_length_or_size_is = None
        assert not ptr_lvl or any(
            x in ("ref", "unique", "ptr") for x in idl_attributes
        ), "Invalid pointer with no pointer tag :( This is a bug."
        assert isinstance(field_type_name, str), (
            "Invalid type for field_type: %s" % field_type_name
        )

    def ptr_wrap(self, fld, toplevel=False, lvl=None, skipref=False):
        # ref only applies to the first pointer, if there is a sub-ptr
        if lvl is None:
            lvl = self.ptr_lvl
        if not lvl:
            return fld
        if "ref" in self.idl_attributes and not skipref:
            if toplevel:
                # Top-level reference = no wrap. See C706 chap 14 - "Transfer Syntax NDR"
                return self.ptr_wrap(fld, toplevel, lvl - 1, skipref=True)
            else:
                return "NDRRefEmbPointerField(%s)" % self.ptr_wrap(
                    fld, toplevel, lvl - 1
                )
        elif any(x in ["ptr", "unique"] for x in self.idl_attributes) or skipref:
            # Other pointers See C706 chap 14 - "Transfer Syntax NDR"
            fld = self.ptr_wrap(fld, toplevel, lvl - 1)
            if toplevel:
                return "NDRFullPointerField(%s)" % fld
            else:
                return "NDRFullEmbPointerField(%s)" % fld
        else:
            assert False, "ptr_lvl > 1 but no pointer marker !"

    def to_string(self, context, toplevel=False):
        lvl = self.ptr_lvl
        if "context_handle" in self.idl_attributes:
            # Special case: context_handle
            return (
                f'NDRPacketField("{self.name}", NDRContextHandle(), NDRContextHandle)'
            )
        elif self.scapy_field == "void":
            # Special case: void
            return f'StrFixedLenField("{self.name}", "", length=0)'
        elif any(x[0] in ["size_is", "max_is"] for x in self.idl_attributes):
            assert False, "This should have been detected as an array: " + self.name
        elif "string" in self.idl_attributes:
            assert lvl >= 1, "String attribute with wrong pointer value? %s: %s" % (
                self.name,
                repr(self.ptr_lvl),
            )
            # Special case: string attribute
            # [C706] 4.2.21.1 - "Such a string is equivalent to a conformant array"
            if self.scapy_field in CHAR_TYPES:
                fld = f'NDRConfVarStrNullField("{self.name}", "")'
            elif self.scapy_field in WCHAR_TYPES:
                fld = f'NDRConfVarStrNullFieldUtf16("{self.name}", "")'
            else:
                assert False, "Unknown string on %s" % self.scapy_field
        else:
            # Normal integer
            default = "0"
            suffix = ""
            if self.inv_length_or_size_is:
                if self.inv_length_or_size_is[1] is not None:
                    suffix += (
                        ', size_of="%s", adjust=lambda _, x: %s'
                        % self.inv_length_or_size_is
                    )
                else:
                    suffix += ', size_of="%s"' % self.inv_length_or_size_is[0]
                default = "None"
            fld = f'{self.scapy_field}("{self.name}", {default}{suffix})'
        return self.ptr_wrap(fld, toplevel=toplevel, lvl=lvl)


class ScapyArrayField(ScapyField):
    def __init__(
        self,
        name,
        ptr_lvl,
        subtype,
        length,
        idl_attributes,
    ):
        if isinstance(subtype, ScapyStructField):
            if isinstance(subtype.subtype, ScapyEnum):
                field = "FieldListField"
            else:
                field = "PacketListField"
        elif isinstance(subtype, ScapyField):
            field = "FieldListField"
        else:
            assert False, "Unknown array subtype: %s" % subtype
        field_type = "%s[%s]" % (subtype.field_type, length or "")
        super(ScapyArrayField, self).__init__(
            name, ptr_lvl, field, field_type, idl_attributes
        )
        self.subtype = subtype
        self.length = length

    def to_string(self, context, toplevel=False, _in_array=False):
        length_is = _lkp(self.idl_attributes, "length_is")
        size_is = _lkp(self.idl_attributes, "size_is")
        max_is = _lkp(self.idl_attributes, "max_is")
        suffix = ""
        prefix = "NDR"

        if size_is or max_is:
            suffix += ", size_is=lambda pkt: " + res_size_is(size_is or max_is)

        if self.length is None or self.length == "*":
            # Conformant Array
            # [C706] 4.2.18.1 - An array is called conformant if it has an <array_bounds_declarator> that is empty or
            # contains an * (asterisk).
            # https://docs.microsoft.com/en-us/windows/win32/rpc/conformant-arrays
            # [MS-RPCE 2.2.5.3.2.1]
            prefix += "Conf"
            if not toplevel and not self.ptr_lvl:
                # [C706] 14.3.7.1 - Structure Containing a Conformant Array
                context.add_conformant(self.name)
                suffix += ", conformant_in_struct=True"

        if length_is:
            # Varying arrays
            # [C706] 4.2.18.2 - An array is called varying if none of its <array_bounds_declarator> components is empty
            # or contains an * (asterisk), and it has either a last_is, first_is or length_is attribute.
            # https://docs.microsoft.com/en-us/windows/win32/rpc/varying-arrays
            # [MS-RPCE 2.2.5.3.2.2]
            prefix += "Var"
            suffix += ", length_is=lambda pkt: " + res_size_is(length_is)
        elif "string" in self.subtype.idl_attributes or "string" in self.idl_attributes:
            # Strings are always considered Varying
            prefix += "Var"

        # Find type.
        if "string" in self.subtype.idl_attributes or "string" in self.idl_attributes:
            # [C706] 14.3.5
            # NDR defines a special representation for an array whose elements are strings.
            # Modified by [MS-RPCE] 2.2.4.4
            if self.length and self.length != "*":
                # This is a Varying, non-conformant string. In this case, the length acts
                # as a 'Maximum Length'. Since we don't implement it... skip it.
                if self.subtype.scapy_field in CHAR_TYPES:
                    fld = f'{prefix}StrLenField("{self.name}", "")'
                elif self.subtype.scapy_field in WCHAR_TYPES:
                    fld = f'{prefix}StrLenFieldUtf16("{self.name}", "")'
                else:
                    assert False, "Unknown string on %s" % self.subtype.scapy_field
            elif not size_is and not max_is:
                assert False, "String array with no length ! %s" % self.name
            else:
                # NDR string
                if self.subtype.scapy_field in CHAR_TYPES:
                    fld = f'{prefix}StrLenField("{self.name}", ""{suffix})'
                elif self.subtype.scapy_field in WCHAR_TYPES:
                    fld = f'{prefix}StrLenFieldUtf16("{self.name}", ""{suffix})'
                else:
                    assert False, "Unknown string on %s" % self.subtype.scapy_field
        elif (length_is or size_is or max_is) or (
            self.length is None or self.length == "*"
        ):
            # Varying array or Conformant array (or both)
            ptr_suffix = suffix
            if (
                any(x in ["ptr", "unique"] for x in self.subtype.idl_attributes)
                and self.subtype.ptr_lvl >= 1
            ):
                ptr_suffix += ", ptr_pack=True"
            if length_is or size_is or max_is:
                if self.scapy_field == "PacketListField":
                    sub_name = (
                        self.subtype.subtype
                        and self.subtype.subtype.name
                        or self.subtype.struct_name
                    )
                    fld = f'{prefix}{self.scapy_field}("{self.name}", [], {sub_name}{ptr_suffix})'
                elif self.scapy_field == "FieldListField":
                    # Note: we freely abstract 1 level of pointer when the subtype is str or bytes,
                    # because it's more managable in python (even though it should technically be a real array of bytes).
                    # The following check test if we do not need this abstraction.
                    if (
                        self.subtype.ptr_lvl == 0
                        and (
                            self.subtype.scapy_field in IMPLICIT_STRINGS
                            or (
                                any(
                                    x in self.name.lower()
                                    for x in ["str", "data", "buffer"]
                                )
                                and self.subtype.scapy_field
                                in (IMPLICIT_STRINGS + WCHAR_TYPES)
                            )
                        )
                        and size_is
                    ):
                        if self.subtype.scapy_field in CHAR_TYPES:
                            fld = f'{prefix}StrLenField("{self.name}", ""{suffix})'
                        else:
                            fld = f'{prefix}StrLenFieldUtf16("{self.name}", ""{suffix})'
                    else:
                        subtype = copy.deepcopy(self.subtype)
                        subtype.name = ""
                        fld = f'{prefix}{self.scapy_field}("{self.name}", [], {subtype.to_string(context, toplevel=toplevel)}{ptr_suffix})'
                else:
                    assert False
            else:
                assert False, (
                    "Unknown conformant array with no length_is nor size_is nor max_is ! %s"
                    % self.name
                )
        else:
            # Fixed Arrays
            # https://docs.microsoft.com/en-us/windows/win32/rpc/fixed-arrays
            if self.scapy_field == "PacketListField":
                fld = f'{self.scapy_field}("{self.name}", [{self.subtype.subtype.name}()] * {self.length}, {self.subtype.subtype.name}, count_from=lambda _: {self.length})'
            elif self.scapy_field == "FieldListField":
                if self.subtype.scapy_field in CHAR_TYPES:
                    # Array of bytes
                    fld = f'StrFixedLenField("{self.name}", "", length={self.length})'
                elif self.subtype.scapy_field in WCHAR_TYPES:
                    # Array of UTF16 (most likely)
                    fld = f'StrFixedLenFieldUtf16("{self.name}", "", length={self.length} * 2)'
                else:
                    fld = f'NDR{self.scapy_field}("{self.name}", [0] * {self.length}, {self.subtype.scapy_field}("", 0), length_is=lambda _: {self.length})'
            else:
                assert False, "How did you get here?"
        return self.ptr_wrap(fld, toplevel=toplevel)


class ScapyStructField(ScapyField):
    def __init__(self, name, ptr_lvl, subtype, struct_name, idl_attributes):
        super(ScapyStructField, self).__init__(
            name, ptr_lvl, "NDRPacketField", struct_name, idl_attributes
        )
        self.subtype = subtype
        self.struct_name = struct_name
        # The following is weird and explained below in comments
        self.is_array = any(
            x[0] in ["size_is", "length_is", "max_is"] for x in self.idl_attributes
        )

    def to_string(self, context, toplevel=False):
        if isinstance(self.subtype, ScapyEnum):
            # Special case: an enum
            if "v1_enum" in self.subtype.idl_attributes:
                return f'NDRIntEnumField("{self.name}", 0, {self.struct_name})'
            else:
                return f'NDRInt3264EnumField("{self.name}", 0, {self.struct_name})'
        length_is = _lkp(self.idl_attributes, "length_is")
        size_is = _lkp(self.idl_attributes, "size_is")
        max_is = _lkp(self.idl_attributes, "max_is")
        if length_is or size_is or max_is:
            prefix = "NDR"
            suffix = ""
            if size_is or max_is:
                # Conformant varying array (alternative)
                # [C706] 4.2.21
                # "When declaring a conformant array parameter, IDL provides an alternative to using [ ]
                # (brackets). A parameter that is a pointer to a type is treated as an array of that type if the
                # parameter has any of the array attributes min_is, max_is, size_is"
                # https://docs.microsoft.com/en-us/windows/win32/rpc/conformant-arrays
                prefix += "Conf"
                if not toplevel and not self.ptr_lvl:
                    # [C706] 14.3.7.1 - Structure Containing a Conformant Array
                    context.add_conformant(self.name)
                    suffix = ", conformant_in_struct=True"
            if length_is:
                # Varying arrays
                # [C706] 4.2.18.2
                # https://docs.microsoft.com/en-us/windows/win32/rpc/varying-arrays
                prefix += "Var"
            if any(x in ["ptr", "unique"] for x in self.idl_attributes):
                # suffix += ", ptr_pack=True"
                pass
            if size_is or max_is:
                suffix += ", size_is=lambda pkt: " + res_size_is(size_is or max_is)
            if length_is:
                suffix += ", length_is=lambda pkt: " + res_size_is(length_is)
            fld = f'{prefix}PacketListField("{self.name}", [], {self.struct_name}{suffix})'
        else:
            if self.subtype.recursive:
                default = "None"
            else:
                default = f"{self.struct_name}()"
            fld = f'{self.scapy_field}("{self.name}", {default}, {self.struct_name})'
        return self.ptr_wrap(fld, toplevel=toplevel)


# --- Packet definitions


class ScapyStruct:
    def __init__(
        self, name, ptr_lvl, fields, idl_attributes, struct_name, recursive=False
    ):
        self.name = name
        self.ptr_lvl = ptr_lvl
        self.fields = self.match_struct_attributes(fields)
        self.idl_attributes = idl_attributes
        self.struct_name = struct_name
        self.recursive = recursive
        if recursive:
            # Super hack. A recursive field is only refered to by other fields,
            # not actually built into a Scapy structure. So we hack its name
            self.name = "NDRRecursiveClass('%s')" % self.name

    def match_struct_attributes(self, fields):
        """
        List all `length_is` and `size_is` in fields and mirror into `length_of` and `count_of`.
        Also handles implicit switch_type of union fields
        """
        if not isinstance(fields, list):  # ScapyEnum
            return fields
        mapped_fields = {x.name: x for x in fields}

        # Handle length_is/size_is
        for fld in (
            x
            for x in fields
            if any(y[0] in ["size_is", "length_is"] for y in x.idl_attributes)
        ):
            # Field has a size_is or length_is attribute
            lengthfld = sizefld = None
            size_is = _lkp(fld.idl_attributes, "size_is")
            length_is = _lkp(fld.idl_attributes, "length_is")

            def _procfld(mainfld, length_or_size_is):
                if mainfld in mapped_fields:
                    # check we can access it
                    inv_length_or_size_is = invert_arithmetic(length_or_size_is)
                    mapped_fld = mapped_fields[mainfld]
                    if inv_length_or_size_is:
                        inv_length_or_size_is = _rec_rslv_arithm(
                            inv_length_or_size_is, env={"x": "x"}
                        )
                    mapped_fld.inv_length_or_size_is = (fld.name, inv_length_or_size_is)

            if length_is:
                lengthfld = res_size_is_getmain(length_is)
                if lengthfld:
                    _procfld(lengthfld, length_is)
            if size_is:
                sizefld = res_size_is_getmain(size_is)
                # if length and size point to the same, prioritize length
                if sizefld and (not lengthfld or lengthfld != sizefld):
                    _procfld(sizefld, size_is)

        # handle switch_is
        for fld in (
            x for x in fields if any(y[0] == "switch_is" for y in x.idl_attributes)
        ):
            # Field might have an implicit switch_type, in which case we shall add it.
            switch_is = _lkp(fld.idl_attributes, "switch_is")[0]
            switch_type = _lkp(fld.idl_attributes, "switch_type")

            if not switch_type and isinstance(switch_is, str):
                # inline: add implicit switch_type for processing
                reffld = mapped_fields[switch_is]
                # This only makes sense if the subtype is an enum
                if isinstance(reffld, ScapyStructField) and isinstance(
                    reffld.subtype, ScapyEnum
                ):
                    fld.idl_attributes.append(
                        ("switch_type", ("custom", reffld.field_type))
                    )

        return fields

    def __repr__(self):
        return (Colors.BLUE + "<ScapyStruct %s=[%s] ptr=%s>" + Colors.RESET) % (
            self.name,
            ";".join(
                "%s %s" % ("*" * x.ptr_lvl + x.name, x.idl_attributes)
                for x in self.fields
            ),
            self.ptr_lvl,
        )

    def to_string(self, context=None, toplevel=False, read_only_fields=None):
        if not context:
            context = Context()
        if not toplevel:
            context.set_current(self)
        context.read_only_fields = read_only_fields or self.fields.copy()
        fields = ",\n".join(
            x.to_string(context, toplevel=toplevel) for x in self.fields
        )

        # Get alignment for the structure ([MS-RPCE] sect 2.2.5.3.4.1)
        alignment = get_alignment(self) if not toplevel else (1, 1)

        # [MS-RPCE] sect 2.2.5.3.4.2 and 2.2.5.3.4.3
        # When the structure is conformant or varying, the padding is already handled
        # by the field in charge of the "representation of the array elements"
        if self.fields and any(
            x[0] in ["size_is", "max_is", "length_is", "min_is"]
            for x in self.fields[-1].idl_attributes
        ):
            alignment = (1, 1)

        return "class %s(NDRPacket):\n%s%s    fields_desc = [%s]\n" % (
            self.name,
            # [MS-RPCE] 2.2.5.3.4.1 - Structure alignment
            ("    ALIGNMENT=%s\n" % str(alignment)) if alignment != (1, 1) else "",
            context.get_conformant_count(self),
            fields,
        )


class ScapyUnion(ScapyStruct, ScapyField):
    def __init__(self, name, ptr_lvl, fields, idl_attributes, struct_name):
        super(ScapyUnion, self).__init__(
            name, ptr_lvl, fields, idl_attributes, struct_name
        )
        self.field_type = name
        for f in self.fields:
            f.name = self.name

    def __repr__(self):
        return (Colors.RED + "<ScapyUnion %s=[%s]>" + Colors.RESET) % (
            self.name,
            ";".join(x.name for x in self.fields),
        )

    def to_string(self, context, toplevel=False):
        switch_type = _lkp(self.idl_attributes, "switch_type")
        switch_is = _lkp(self.idl_attributes, "switch_is")
        if switch_is:
            switch_is = res_size_is(switch_is, getattr=True)
            switch_fmt = _get_switch_fmt(switch_is, context)
        else:
            switch_is = "None"
            switch_fmt = ("I", "I")
        fields_resolved = list(
            zip(
                self.fields,
                (x.to_string(context, toplevel=toplevel) for x in self.fields),
            )
        )
        try:
            default_field = next(
                x[1]
                for x in fields_resolved
                if "default" in x[0].idl_attributes and x[0].scapy_field != "void"
            )
        except StopIteration:
            default_field = 'StrFixedLenField("%s", "", length=0)' % self.fields[0].name
        fields = ",\n".join(
            "(%s,%s)"
            % (
                x[1],
                _rslv_case_expr(
                    switch_is, switch_type, _lkp(x[0].idl_attributes, "case")
                ),
            )
            for x in fields_resolved
            if "default" not in x[0].idl_attributes
        )
        # if ms_union
        alignment = (
            struct.calcsize("<" + switch_fmt[0]),
            max(struct.calcsize("<" + switch_fmt[1]), get_alignment(self)[1]),
        )
        fld = "NDRUnionField([%s],%s,align=%s,switch_fmt=%s)" % (
            fields,
            default_field,
            alignment,
            switch_fmt,
        )
        return self.ptr_wrap(fld, toplevel=toplevel)


class ScapyEnum(ScapyStruct):
    def __repr__(self):
        return (Colors.YELLOW + "<ScapyEnum %s={%s}>" + Colors.RESET) % (
            self.name,
            ";".join(self.fields.keys()),
        )

    def to_string(self):
        return "class %s(IntEnum):\n    %s\n" % (
            self.name,
            "\n    ".join(
                "%s = %s" % (k, v if isinstance(v, tuple) else v)
                for k, v in self.fields.items()
            ),
        )


# --- Functions definitions


class ScapyFunc:
    def __init__(self, name, return_type, in_args, out_args, opnum=None):
        self.name = name
        self.return_type = return_type
        self.in_args = in_args
        self.out_args = out_args
        self.opnum = opnum
        # Build resquest and response
        self.request = ScapyStruct(
            self.name + "_Request", 0, self.in_args, [], self.name + "_Request"
        )
        self.response = ScapyStruct(
            self.name + "_Response", 0, self.out_args, [], self.name + "_Response"
        )

    def __repr__(self):
        return (Colors.GREEN + "<ScapyFunc %s %s (%s)->(%s)>" + Colors.RESET) % (
            self.name,
            self.return_type and self.return_type.field_type or "void",
            ", ".join(
                "%s%s%s %s" % (x.ptr_lvl * "*", x.name, x.idl_attributes, x.field_type)
                for x in self.in_args
            ),
            ", ".join(
                "%s%s%s %s" % (x.ptr_lvl * "*", x.name, x.idl_attributes, x.field_type)
                for x in self.out_args
            ),
        )

    def to_string(self):
        return (
            (
                self.request.to_string(
                    toplevel=True, read_only_fields=self.in_args + self.out_args
                )
                or ""
            )
            + "\n"
            + (
                self.response.to_string(
                    toplevel=True, read_only_fields=self.in_args + self.out_args
                )
                or ""
            )
        )


class ScapyInterfaceDefinition:
    def __init__(self, name, idl_attributes, opnums):
        self.name = name
        # If it doesn't have an uuid and version, it's probably malformed...
        self.uuid = _lkp(idl_attributes, "uuid")
        self.version = _lkp(idl_attributes, "version") or "0.0"
        self.opnums = opnums
        self.object = "object" in idl_attributes

    def __repr__(self):
        return "<Interface definition %s>" % self.name

    def to_string(self):
        if self.uuid is None:
            return ""
        return "%s_OPNUMS = {%s\n}\n" % (
            self.name.upper(),
            ",\n".join(
                (
                    (
                        "%s:%s"
                        % (
                            k,
                            "DceRpcOp(%s, %s)"
                            % (
                                v.request and v.request.name,
                                v.response and v.response.name,
                            ),
                        )
                    )
                    if not isinstance(v, str)
                    else ("# %s: %s" % (k, v))
                )
                for k, v in sorted(self.opnums.items(), key=lambda x: x[0])
            ),
        ) + "%s(name='%s', uuid=uuid.UUID('%s'), %s opnums=%s)" % (
            ("register_com_interface" if self.object else "register_dcerpc_interface"),
            self.name,
            self.uuid,
            ("version='%s'," % self.version) if not self.object else "",
            "%s_OPNUMS" % self.name.upper(),
        )


if __name__ == "__main__":
    print("You cannot call this file directly !")
    sys.exit(1)
