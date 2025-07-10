# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information

"""
Convert the syntax tree from PLY based on the parsed MIDL file to a class-based syntax tree
"""

from enum import Enum, auto
import copy
import os
import sys

from midl_parser import parser, lexer
from utils import Colors

# Useful doc:
# - pointers: https://docs.microsoft.com/en-us/windows/win32/rpc/kinds-of-pointers
# - C706 chap 12 - "Interface Definition Language"
# - [MSRPCE]

# --- Build AST


BUILTIN_TYPE_MODIFIERS = [
    "signed",
    "unsigned",
    "const",
    "short",
    "pipe",
]

# https://docs.microsoft.com/en-us/windows/win32/midl/midl-predefined-and-base-types
BUILTIN_TYPES = {
    "byte": ("b", "B"),
    "char": ("b", "B"),
    "short": ("h", "H"),
    "int": ("i", "I"),
    "boolean": "I",
    "long": ("l", "L"),
    "__int32": ("i", "I"),
    "__int64": ("q", "Q"),
    "hyper": ("q", "Q"),
    "float": "f",
    "double": "d",
    "handle_t": "Q",
    "error_status_t": "L",
    # Special [MS-RPCE]
    "void": "void",
    "wchar_t": "H",
    "__int3264": ("__int3264", "__uint3264"),
}


class Types(Enum):
    BUILTIN = auto()
    CUSTOM = auto()
    ARRAY = auto()
    STRUCT = auto()
    UNION = auto()
    ENUM = auto()


class Type:
    __slots__ = ["name", "ptr_lvl", "idl_attributes", "origin"]
    TYPE = Types.BUILTIN

    def __init__(self, decl, idl_attributes):
        assert decl[0][:3] in ["id", "ptr"], "Invalid decl type %s for Type" % decl[0]
        self.name = decl[1]
        self.ptr_lvl = decl[0].count("ptr")
        self.idl_attributes = idl_attributes
        self.origin = None

    def __repr__(self):
        fname = "%s%s" % (self.name, "*" * self.ptr_lvl)
        if self.TYPE == Types.BUILTIN:
            return "<BuiltinType %s '%s' %s>" % (fname, self.fmt, self.idl_attributes)
        elif self.TYPE == Types.STRUCT:
            return (Colors.BLUE + "<StructType %s (%d fields)>" + Colors.RESET) % (
                fname,
                len(self.fields),
            )
        elif self.TYPE == Types.CUSTOM:
            return "<CustomType %s=%s%s %s>" % (
                self.name,
                self.type,
                "*" * self.ptr_lvl,
                self.idl_attributes,
            )
        elif self.TYPE == Types.UNION:
            return (Colors.RED + "<UnionType %s (%s values)>" + Colors.RESET) % (
                fname,
                len(self.fields),
            )
        elif self.TYPE == Types.ARRAY:
            return "<ArrayType %s[%s]>" % (fname, self.array_length)
        elif self.TYPE == Types.ENUM:
            return (Colors.YELLOW + "<EnumType %s (%s values)>" + Colors.RESET) % (
                fname,
                len(self.enums.values()),
            )

    def copy(self):
        return copy.copy(self)


class BuiltinType(Type):
    __slots__ = ["fmt", "type"]
    TYPE = Types.BUILTIN

    def __init__(
        self,
        c,
        decl,
        typespec,
        idl_attributes,
    ):
        super(BuiltinType, self).__init__(decl, idl_attributes)
        if self.TYPE == Types.BUILTIN:
            assert all(
                x in BUILTIN_TYPE_MODIFIERS for x in typespec[:-1]
            ), "Invalid type modifier: %s" % (typespec[:-1])
            modifiers = typespec[:-1]
            typ = typespec[-1]
            self.type = " ".join(typespec)
            if "short" in modifiers:
                typ = "short"
            if "signed" in modifiers:
                self.fmt = BUILTIN_TYPES[typ][0]
            elif "unsigned" in modifiers:
                self.fmt = BUILTIN_TYPES[typ][1]
            else:
                if isinstance(BUILTIN_TYPES[typ], tuple):
                    self.fmt = BUILTIN_TYPES[typ][0]
                else:
                    self.fmt = BUILTIN_TYPES[typ]
        elif self.TYPE == Types.CUSTOM:
            if "const" in typespec:
                # Ignore const keyword
                typespec.remove("const")
            if typespec[0] == "struct":
                typespec.pop(0)
            assert len(typespec) == 1, (
                "Custom types should have a typespec length of 1, got %s" % typespec
            )
            self.type = typespec[0]


class StructType(Type):
    __slots__ = ["fields", "struct_name", "pack"]
    TYPE = Types.STRUCT

    def __init__(self, c, decl, blk, idl_attributes, struct_name):
        super(StructType, self).__init__(decl, idl_attributes)
        self.struct_name = struct_name
        self.pack = c.pragma["pack"]
        fields = []
        for attr in blk:
            if attr[0] == "attr":
                _, f_idl_attributes, f_typespec, f_decls = attr
                if ("id", "ignore") in f_idl_attributes:
                    continue
                for f_decl in f_decls:
                    f_typ = c.build_type(f_decl, f_typespec, f_idl_attributes)
                    fields.append(f_typ)
            elif attr[0] == "struct":
                _, f_idl_attributes, f_blk, f_decls = attr
                for f_decl in f_decls:
                    f_struct = c.build_struct(f_decl, f_blk, f_idl_attributes, None)
                    fields.append(f_struct)
            elif attr[0] == "union":
                _, f_idl_attributes, f_struct_name, f_blk, f_decls = attr
                for f_decl in f_decls:
                    f_union = c.build_union(
                        f_decl, f_blk, f_idl_attributes, f_struct_name
                    )
                    fields.append(f_union)
            else:
                assert False, "Unimplemented parsing of struct's %s" % attr[0]
        self.fields = fields


class ArrayType(Type):
    __slots__ = ["subtype", "array_length"]
    TYPE = Types.ARRAY

    def __init__(self, c, decl, typespec, idl_attributes):
        super(ArrayType, self).__init__(decl[1], idl_attributes)
        self.array_length = decl[2]
        if typespec is not None:
            if is_builtin(typespec):
                self.subtype = BuiltinType(c, decl[1], typespec, [])
            else:
                self.subtype = CustomType(c, decl[1], typespec, [])


class UnionType(StructType):
    __slots__ = ["fields", "struct_name"]
    TYPE = Types.UNION


class CustomType(BuiltinType):
    TYPE = Types.CUSTOM


class EnumType(Type):
    __slots__ = ["enums", "enum_name", "origin"]
    TYPE = Types.ENUM

    def __init__(self, c, decl, enums, idl_attributes, enum_name):
        super(EnumType, self).__init__(decl, idl_attributes)
        self.enum_name = enum_name
        self.origin = None
        cur = 0
        self.enums = {}
        for key, val in enums:
            if val is None:
                cur += 1
                self.enums[key] = cur
            else:
                self.enums[key] = val
                cur = val


def is_builtin(typespec):
    return typespec[-1] in BUILTIN_TYPES


class Function:
    def __init__(self, c, name, return_type, arguments, idl_attrs):
        if ("id", "propget") in idl_attrs:
            # com stuff
            name = "get_" + name
        elif ("id", "propput") in idl_attrs:
            # com stuff
            name = "put_" + name
        self.name = name
        self.return_type = c.build_type(("id", "_ret"), return_type, idl_attrs)
        self.in_args = []
        self.out_args = []
        for arg in arguments:
            if arg == "void":
                continue
            idl_attrs, typespec, decl = arg
            type = c.build_type(decl, typespec, idl_attrs)
            if isinstance(type, BuiltinType) and type.type == "handle_t":
                # Parameters of type handle_t (primitive handle parameters) are not transmitted on the network.
                continue
            if ("id", "in") in idl_attrs:
                self.in_args.append(type)
            if ("id", "out") in idl_attrs:
                self.out_args.append(type)
        # [C706] sect 4.3.8
        if not any(
            x.type in ["error_status_t", "error_status"]
            for x in self.out_args
            if isinstance(x, BuiltinType)
        ):
            sname = "status"
            if any(x.name == "status" for x in self.out_args):
                # conflict on the 'status' name
                sname = "comm_status"
            # add implicit 'status' out argument
            self.out_args.append(
                BuiltinType(c, ("id", sname), ["unsigned", "long"], [])
            )

    def __repr__(self):
        return (Colors.GREEN + "<Function %s(%s) -> (%s)>" + Colors.RESET) % (
            self.name,
            ", ".join(x.name for x in self.in_args),
            ", ".join(x.name for x in self.out_args),
        )


class Interface:
    def __init__(self, name, parent_class, idl_attrs, ienv):
        self.name = name
        self.idl_attrs = idl_attrs
        self.parent_class = parent_class
        self.ienv = ienv
        self.origin = None
        try:
            self.pointer_default = next(
                x[2][0][1]
                for x in idl_attrs
                if x[0] == "call" and x[1] == "pointer_default"
            )
        except StopIteration:
            self.pointer_default = "unique"

    def __repr__(self):
        c = sum(1 for x in self.ienv.values() if isinstance(x, Function))
        return "<Interface %s (%d fonctions)>" % (self.name, c)


class Compiler:
    def __init__(self):
        self.pragma = {
            "pack": None,
        }
        self.loaded_dcom = False

    def build_type(self, decl, typespec, idl_attrs):
        """
        Build a Type
        """
        if (decl, typespec) == (None, None):
            # typically, [default] in case of an union
            decl = ("id", "_none")
            return BuiltinType(self, decl, ["void"], idl_attrs)
        assert all(x[0] in "id" for x in typespec), "Invalid typespec %s" % typespec
        typespec = [x[1] for x in typespec]
        # Strip __stdcall
        if typespec[-1] == "__stdcall":
            typespec.pop(-1)
        # Normal
        if decl[0] == "array":
            return ArrayType(self, decl, typespec, idl_attrs)
        elif is_builtin(typespec):
            return BuiltinType(self, decl, typespec, idl_attrs)
        else:
            return CustomType(self, decl, typespec, idl_attrs)

    def build_struct(self, decl, blk, idl_attributes, struct_name):
        """
        Build a StructType
        """
        return StructType(self, decl, blk, idl_attributes, struct_name)

    def build_union(self, decl, blk, idl_attributes, struct_name):
        """
        Build a UnionType
        """
        return UnionType(self, decl, blk, idl_attributes, struct_name)

    def build_enum(self, decl, enums, idl_attributes, enum_name):
        """
        Build an Enum
        """
        return EnumType(self, decl, enums, idl_attributes, enum_name)

    def build_typedef(self, typedef):
        """
        Build a typedef: generate the various objects it declares
        """
        env = {}
        if typedef[0] == "type":
            _, idl_attrs, typespec, declarators = typedef
            for declarator in declarators:
                typ = self.build_type(declarator, typespec, idl_attrs)
                env[typ.name] = typ
        elif typedef[0] == "struct":
            _, struct_name, blk, declarators = typedef
            for declarator in declarators:
                stc = self.build_struct(declarator, blk, [], struct_name)
                env[stc.name] = stc
                env[stc.struct_name] = stc  # To help resolving. Not an actual object
        elif typedef[0] == "union":
            _, idl_attributes, struct_name, blk, declarators = typedef
            for declarator in declarators:
                unio = self.build_union(declarator, blk, idl_attributes, struct_name)
                env[unio.name] = unio
                # help resolution
                env[unio.struct_name] = unio
        elif typedef[0] == "enum":
            _, idl_attributes, enum_name, enums, declarators = typedef
            for declarator in declarators:
                enu = self.build_enum(declarator, enums, idl_attributes, enum_name)
                env[enu.name] = enu
                env[enu.enum_name] = enu  # To help resolving. Not an actual object
                # add values for resolution
                env.update({k: enu.name + "." + k for k in enu.enums})
        elif typedef[0] == "val":
            _, typespec, declarator, val = typedef
            typ = self.build_type(declarator, typespec, [])
            env[typ.name] = val
        elif typedef[0] == "macro":
            _, macro = typedef
            if macro[0] == "pragma":
                prgm = macro[1][1]
                # Compiler instructions
                if prgm == "pack":
                    if len(macro) == 5:
                        # enable
                        self.pragma["pack"] = macro[3]
                    elif len(macro) == 4:
                        # disable
                        self.pragma["pack"] = None
                else:
                    assert False, "Unknown pragma pack %s" % repr(macro)
            elif macro[0] == "define":
                if len(macro) == 2:
                    env[macro[1]] = 1
                elif len(macro) == 4:
                    if isinstance(macro[2][0], tuple) and macro[2][0][0] in [
                        "id",
                        "ptr",
                    ]:
                        # A type
                        typ = self.build_type(macro[1], macro[2], macro[3])
                        env[typ.name] = typ
                    else:
                        # A const
                        env[macro[1][1]] = macro[2][0]
                else:
                    assert False, "Unimplemented define macro: %s" % repr(macro)
            elif macro[0] in ["if", "ifdef", "ifndef", "else", "endif", "empty"]:
                # For the bold
                pass
            else:
                assert False, "Unimplemented macro %s" % repr(macro)
        else:
            assert False, "Unimplemented typedef %s" % typedef[0]
        return env

    def build_func(self, func, if_ptr=None):
        """
        Build a function
        """
        _, idl_attributes, return_type, name, arguments = func
        func = Function(self, name, return_type, arguments, idl_attributes)
        if if_ptr:
            self.chk_ptr_type(func, if_ptr)
        return func

    def build_interface(self, interface, env, fname=None):
        """
        Build an interface
        """
        ienv = env.copy()
        _, name, parent_class, idl_attrs, expressions = interface
        if ("id", "object") in idl_attrs and not self.loaded_dcom:
            self.loaded_dcom = True
            # DCOM
            pth = os.path.join(os.path.dirname(fname), "ms-dcom.idl")
            # Parse it and update the environment
            env.update(self.process_file(pth))
        for e in expressions:
            if e[0] == "typedef":
                ienv.update(self.build_typedef(e[1]))
            elif e[0] == "macro":
                ienv.update(self.build_typedef(e))
            elif e[0] == "func":
                func = self.build_func(e)
                ienv[func.name] = func
            elif e[0] == "import" or e[0] == "#include":
                # Find file in the same folder as current file
                pth = os.path.join(os.path.dirname(fname), e[1])
                # Parse it and update the environment
                ienv.update(self.process_file(pth))
            else:
                assert False, "Unexpected keyword %s" % e[0]
        return Interface(name, parent_class, idl_attrs, ienv)

    def process_file(self, fname):
        """
        Parse a file, process its data and build an AST
        """
        with open(fname, "r") as fd:
            lexer.lineno = 1
            data = parser.parse(fd.read())
        env = {}
        for e in data:
            if e[0] == "import":
                # Find file in the same folder as current file
                pth = os.path.join(os.path.dirname(fname), e[1])
                # Parse it and update the environment
                env.update(self.process_file(pth))
            elif e[0] == "typedef":
                env.update(self.build_typedef(e[1]))
            elif e[0] == "interface":
                interface = self.build_interface(e, env, fname=fname)
                env[interface.name] = interface
            elif e[0] == "macro":
                env.update(self.build_typedef(e))
            elif e[0] == ";":
                assert data.index(e) == len(data) - 1, "Standalone coma !"
            elif e[0] == "interface-definition":
                env[e[1]] = Interface(e[1], None, [], {})
            elif e[0] == "coclass":
                for f in e[4]:
                    if f[0] == "interface-definition":
                        env[f[1]] = Interface(f[1], None, [], {})
                    elif f[0] == "interface":
                        interface = self.build_interface(f, env, fname=fname)
                        env[interface.name] = interface
                    elif f[0] == ";":
                        pass
                    else:
                        assert False, "Unexpected content in coclass: %s" % f
            else:
                if e[0] == "func":
                    assert (
                        False
                    ), "Unexpected function outside an interface. Check the IDL file"
                else:
                    assert False, "Unexpected keyword %s" % e[0]
        # Add origin
        for obj in env.values():
            if isinstance(obj, (Interface, StructType, EnumType)):
                obj.origin = obj.origin or fname
        return env


# --- Main

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Wrong usage.\n python midl_convert.py [files]")
        sys.exit(1)
    else:
        for fname in sys.argv[1:]:
            print("### %s" % fname)
            c = Compiler()
            f = c.process_file(fname)
            interfaces = [x for x in f.values() if isinstance(x, Interface)]
            for i in interfaces:
                print("Interface %s:" % i.name)
                print(
                    "\n".join((" - " + k + ": " + repr(v)) for k, v in i.ienv.items())
                )
            if not interfaces:
                print("No interface found. Listing environment:")
                print("\n".join(repr(x) for x in f.values() if x.origin == fname))
