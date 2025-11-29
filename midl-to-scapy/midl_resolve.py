# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information

"""
Convert a MIDL AST into Scapy pseudo-packets, and perform
the names resolution.
"""

import os
import re
import struct
import sys

from midl_convert import (
    Compiler,
    Function,
    Interface,
    CustomType,
    StructType,
    Types,
    is_builtin,
    BUILTIN_TYPES,
)

from scapy_obj import (
    ScapyEnum,
    ScapyArrayField,
    ScapyField,
    ScapyFunc,
    ScapyInterfaceDefinition,
    ScapyStruct,
    ScapyStructField,
    ScapyUnion,
    SCAPY_FIELDS,
)

# --- Actual code


class Resolver:
    """
    This class resolves references to other structs, fields...
    """

    def __init__(self, input_data):
        self.input_data = input_data
        self.environment = []  # what will end up in the file
        self.globalnamespace = {}
        self.current_interface = None

    def resolve_file(self, fname, filter={}):
        """
        Process a parsed file.

        :param filter: a dict filter: {"interfacename": [opnums, ...]}
                       to only include some filters for certain interfaces.
        """
        # All interfaces
        all_interfaces = {
            x.name: x for x in self.input_data.values() if isinstance(x, Interface)
        }
        # Scope to file
        orig = os.path.split(fname)[1]
        interfaces_scoped = [
            x for x in all_interfaces.values() if getattr(x, "origin", None) == orig
        ]
        if interfaces_scoped:
            # File contains interfaces

            _resolved_interfaces = {}

            def _resolve_interface_rec(iface):
                parent = None
                # If cached, return instantly
                if iface.name in _resolved_interfaces:
                    return _resolved_interfaces[iface.name]
                # If interface has a parent class, resolve it first
                if iface.parent_class:
                    parent = _resolved_interfaces[iface.parent_class] = (
                        _resolve_interface_rec(all_interfaces[iface.parent_class])
                    )
                # Resolve the interface
                iface = _resolved_interfaces[iface.name] = self.resolve_interface(
                    iface,
                    parent=parent,
                    filter=filter.get(iface.name, None),
                )
                return iface

            for i in interfaces_scoped:
                _resolve_interface_rec(i)
        else:
            # Has no interface: export everything
            exported = []
            orig = os.path.split(fname)[1]
            for k, obj in self.input_data.items():
                if getattr(obj, "origin", None) != orig:
                    continue
                elt = self.resolve_type(k, self.input_data, toplevel=True)
                struct_name = getattr(elt, "struct_name", None)
                if struct_name and struct_name in exported and elt in self.environment:
                    # Already exported
                    pass
                elif struct_name:
                    exported.append(struct_name)

    def resolve_interface_idl_attributes(self, idl_attributes):
        """Resolve interface-specific idl_attributes"""
        res = []
        for attr in idl_attributes:
            if attr[0] == "call":
                if attr[1] in [
                    "uuid",
                    "version",
                    "pointer_default",
                    "endpoint",
                    "helpstring",
                ]:
                    res.append((attr[1], attr[2][0]))
                else:
                    assert False, "Unknown interface idl_attribute: %s" % repr(attr)
            elif attr[0] == "id" and attr[1] in [
                "ms_union",
                "object",
                "dual",
                "local",
                "restricted",
                "oleautomation",
                "nonextensible",
                "odl",
                "hidden",
            ]:
                res.append(attr[1])
            else:
                assert False, "Unknown interface idl_attribute: %s" % repr(attr)
        return res

    def resolve_interface(self, interface, parent=None, filter=None):
        """
        Process an interface into Scapy packets and functions.

        :param parent: a parent interface, if any.
        :param filter: a list of opnums to allow.
        """
        self.current_interface = interface
        self.globalnamespace[interface.name] = interface
        interface_opnums = {}
        for i, func in enumerate(
            x for x in interface.ienv.values() if isinstance(x, Function)
        ):
            if not func.in_args and len(func.out_args) == 1:
                # Function has no in nor out arguments
                if re.match(
                    r"^((Opnum\d+(NotUsedOnWire|NotImplemented))|(Lsar_LSA_.._\d+))$",
                    func.name,
                ):
                    # Function should be skipped.
                    interface_opnums[i] = func.name
                    continue
            if filter is not None and i not in filter:
                # Function is filtered out
                continue
            env = interface.ienv
            in_args = [self.make_field(x, env, toplevel=True) for x in func.in_args]
            out_args = [self.make_field(x, env, toplevel=True) for x in func.out_args]
            return_type = self.make_field(func.return_type, env, toplevel=True)
            scapy_func = ScapyFunc(func.name, return_type, in_args, out_args, opnum=i)
            self.environment.append(scapy_func)
            interface_opnums[i] = scapy_func
        # Process the idl attributes of the interface
        interface_idl_attrs = self.resolve_interface_idl_attributes(interface.idl_attrs)
        # Build the final interface
        iface = ScapyInterfaceDefinition(
            name=interface.name,
            idl_attributes=interface_idl_attrs,
            opnums=interface_opnums,
        )
        # If we have a parent interface, add its opnums
        if parent is not None and parent.opnums:
            max_opnum = max(parent.opnums.keys()) + 1
            iface.opnums = {i + max_opnum: func for i, func in iface.opnums.items()}
            iface.opnums.update(parent.opnums)
        # Finally append to the environment
        self.environment.append(iface)
        return iface

    def _resolve_arithm_values(self, x, env):
        """
        Resolve any global constants in an arithmetic value.
        """
        if isinstance(x, int):
            return x
        if x[0] in ["binop", "if"]:
            return x[:2] + (
                self._resolve_arithm_values(x[2], env),
                self._resolve_arithm_values(x[3], env),
            )
        elif x[0] == "cast":
            # Resolve cast type if needed
            if x[1][1] in BUILTIN_TYPES:
                typ = x[1]
            else:
                restyp = env[x[1][1]]
                assert restyp.TYPE == Types.BUILTIN, "Can only cast to builtin types !"
                typ = ("id", restyp.type.split(" ")[-1])
            return x[:1] + (typ, self._resolve_arithm_values(x[2], env))
        elif x[0] == "monop":
            return x[:2] + (self._resolve_arithm_values(x[2], env),)
        elif x[0] == "call" and x[1] == "sizeof":
            assert all(x[0] == "id" for x in x[2]), "Unknown sizeof type"
            typespec = [x[1] for x in x[2]]
            if is_builtin(typespec):
                typ = BUILTIN_TYPES[typespec[-1]]
                return struct.calcsize(typ[0])
            else:
                typ2 = self.resolve_type(typespec[-1], env)
                if isinstance(typ2, CustomType):
                    return typ2.sz * 8
                else:
                    # FIXME for structures... I just hardcoded the few
                    if typ2.name == "BIND_INFO_BLOB":
                        return 16
                    elif typ2.name == "GUID":
                        return 16
                    raise Exception("Unimplemented: size for " + typ2.name)
        elif x[0] == "id":
            # Try to resolve a global value. If it fails, it's probably
            # a local value.
            if x[1] in env:
                return self._resolve_arithm_values(env[x[1]], env)
            else:
                return x
        else:
            return x

    def resolve_idl_attributes(self, idl_attributes, env):
        """Resolve idl_attributes"""
        res = []
        for attr in idl_attributes:
            if attr[0] == "id":
                if attr[1] in ["in", "out"]:
                    continue
                res.append(attr[1])
            elif attr[0] == "call":
                if attr[1] == "range":
                    # Alias range to a max_is, only if it already has already
                    # signs of a conformant value.
                    if ("id", "string") in idl_attributes:
                        attr = (attr[0], "max_is", attr[2][1:])
                    else:
                        continue
                if attr[1] in [
                    "switch_is",
                    "length_is",
                    "max_is",
                    "size_is",
                    "case",
                ]:
                    assert isinstance(attr[2], list)
                    assert all(
                        (
                            isinstance(x, int)
                            or x[0] in ["id", "ptr"]
                            or x[0] in ["binop", "monop", "cast", "if", "call"]
                        )
                        for x in attr[2]
                    ), repr(attr[2])
                    # Process the value of the call
                    value = []
                    for x in attr[2]:
                        if isinstance(x, int) or x[0] in [
                            "binop",
                            "monop",
                            "cast",
                            "if",
                            "call",
                        ]:
                            value.append(
                                ("arithm_expr", self._resolve_arithm_values(x, env))
                            )
                        elif x[0] == "id" and attr[1] != "case":
                            if attr[1] in env:
                                # In env: should be resolved and converted to an arithmetic value
                                # (or operation)
                                value.append(
                                    ("arithm_expr", self._resolve_arithm_values(x, env))
                                )
                            else:
                                # Most likely a relative value (e.g. size_is = pkt.otherField)
                                value.append(x[1])
                        else:
                            value.append(x[1])
                    res.append(
                        (
                            attr[1],
                            value,
                        )
                    )
                elif attr[1] in ["switch_type", "switch"]:
                    assert all(x[0] in ["id", "ptr"] for x in attr[2]), repr(attr[2])
                    typespec = [x[1] for x in attr[2] if x[1] != "enum"]
                    if attr[1] == "switch":
                        # c-compat mode
                        typespec = typespec[:-1]
                    if is_builtin(typespec):
                        t = ("native", typespec[-1])
                    else:
                        assert (
                            len(typespec) == 1
                        ), "Unknown typespec in switch_type %s" % repr(typespec)
                        t = ("custom", self.resolve_type(typespec[0], env))
                    res.append(("switch_type", t))
                elif attr[1] in [
                    "iid_is",
                    "helpstring",
                    "id",
                    "defaultvalue",
                    "call_as",
                    "annotation",
                ]:  # ignore
                    pass
                else:
                    assert False, "Unknown call attr: %s" % repr(attr)
            else:
                assert False, "Unknown idl attr: '%s'" % repr(attr)
        return res

    def resolve_type(self, type, env, toplevel=False, strct_types=[]):
        """
        Resolve a type, and add it to the enviroment
        """
        if type not in self.globalnamespace:
            # Need prior resolution
            field = self.make_field(
                env[type], env, toplevel=toplevel, strct_types=strct_types
            )
            self.globalnamespace[type] = field
            if (
                isinstance(field, (ScapyStruct, ScapyEnum))
                and not isinstance(field, ScapyUnion)
                and not getattr(field, "recursive", False)
            ):
                self.globalnamespace[field.struct_name] = field
                self.environment.append(field)
        if isinstance(self.globalnamespace[type], Interface):
            # It's an interface. Resovling it as a type should instead return a pointer
            # to a MInterfacePointer
            return self.make_field(
                CustomType(None, ("id", type), ["MInterfacePointer"], []),
                env,
                toplevel=toplevel,
            )
        return self.globalnamespace[type]

    def make_field(self, arg, env, toplevel=False, strct_types=[], subfld=False):
        """
        Resolve a arg, and add it to the enviroment
        """
        # Special check for Interfaces (DCOM)
        if isinstance(arg, Interface):
            # It's an interface. Resovling it as a type should instead return a pointer
            # to a MInterfacePointer
            return self.make_field(
                CustomType(None, ("id", arg.name), ["MInterfacePointer"], []),
                env,
                toplevel=toplevel,
            )
        arg = arg.copy()
        idl_attributes = self.resolve_idl_attributes(arg.idl_attributes, env)
        # Special checks for BUILTIN and CUSTOM
        if arg.TYPE in [Types.BUILTIN, Types.CUSTOM]:
            new_ptr_lvl = arg.ptr_lvl
            if arg.TYPE == Types.CUSTOM:
                # Do the resolution for CUSTOM fields
                new_arg = self.resolve_type(
                    arg.type, env, toplevel=toplevel, strct_types=strct_types
                )
                idl_attributes += [
                    x
                    for x in new_arg.idl_attributes
                    # The fact that we remove all pointer attributes from children is technically
                    # slightly broken. We should ideally remove them only if they we added because
                    # they were the default value, and also not store default values in the environment.
                    if x not in idl_attributes and x not in ("ref", "unique", "ptr")
                ]
                new_ptr_lvl += new_arg.ptr_lvl
            # Welcome to [C706] 4.2.21. IF, <BUNCH OF CONDITIONS>
            if (
                not subfld
                and arg.TYPE != Types.ARRAY
                and new_ptr_lvl
                and any(x[0] in ("size_is", "max_is", "min_is") for x in idl_attributes)
            ):
                # "...pointer..."
                # "if the parameter has any of the array attributes min_is, max_is, size_is."
                # THEN IT IS SECRETELY AN ARRAY !
                from midl_convert import ArrayType

                newarg = ArrayType(
                    None, ("array", ("id", arg.name), "*"), None, []
                )  # dummy

                # This will be a pointer to an array of whatever the type was
                arg.ptr_lvl -= 1
                new_ptr_lvl = 1

                # The attributes to keep in the parent (the array)
                idl_attributes = [
                    x
                    for x in idl_attributes
                    if x[0] in ("size_is", "length_is", "max_is", "min_is", "case")
                    or x in ("ref", "unique", "ptr")
                ]

                # The child attributes
                arg.idl_attributes = [
                    x
                    for x in arg.idl_attributes
                    if (
                        x[0] != "call"
                        or x[1]
                        not in ("size_is", "length_is", "max_is", "min_is", "case")
                    )
                    and (x[0] != "id" or x[1] not in ("ref", "unique", "ptr"))
                ]

                # Set the child subtype
                newarg.subtype = arg
                arg = newarg
            arg.ptr_lvl = new_ptr_lvl
        # Apply default pointer policies
        if arg.ptr_lvl and not any(
            x in ("ref", "unique", "ptr") for x in idl_attributes
        ):
            if toplevel:
                # [C706] 4.2.20.3 - Pointer Attributes on Parameters
                # By default, the first indirection operator (an *, asterisk) in a parameter declaration is treated as a
                # reference pointer.
                idl_attributes.append("ref")
            else:
                # Elsewhere, use interface <ptr_attr>
                if self.current_interface:
                    idl_attributes.append(self.current_interface.pointer_default)
                else:
                    idl_attributes.append("unique")
        # Build field
        if arg.TYPE == Types.BUILTIN:
            return ScapyField(
                arg.name,
                arg.ptr_lvl,
                SCAPY_FIELDS[arg.fmt],
                arg.type,
                idl_attributes=idl_attributes,
            )
        elif arg.TYPE == Types.CUSTOM:
            if isinstance(new_arg, ScapyStructField):
                return ScapyStructField(
                    arg.name,
                    arg.ptr_lvl,
                    new_arg.subtype,
                    new_arg.subtype.name,
                    idl_attributes=idl_attributes,
                )
            elif isinstance(new_arg, ScapyUnion):
                return ScapyUnion(
                    arg.name,
                    arg.ptr_lvl,
                    new_arg.fields,
                    idl_attributes=idl_attributes,
                    struct_name=new_arg.struct_name,
                )
            elif isinstance(new_arg, ScapyStruct):
                return ScapyStructField(
                    arg.name,
                    arg.ptr_lvl,
                    new_arg,
                    new_arg.name,
                    idl_attributes=idl_attributes,
                )
            elif isinstance(new_arg, ScapyField):
                return ScapyField(
                    arg.name,
                    arg.ptr_lvl,
                    new_arg.scapy_field,
                    arg.type,
                    idl_attributes=idl_attributes,
                )
            else:
                assert False, "Unimplemented Custom->%s" % repr(arg.type)
        elif arg.TYPE == Types.ARRAY:
            sub_arg = self.make_field(arg.subtype, env, subfld=True)
            if arg.array_length and not isinstance(arg.array_length, int):
                if arg.array_length == "*":
                    # Special case: conformant arrays. it's alright
                    pass
                elif arg.array_length[0] == "binop":
                    from scapy_obj import _rec_rslv_arithm

                    arg.array_length = _rec_rslv_arithm(arg.array_length, env)
                else:
                    # Resolve const
                    assert (
                        arg.array_length[0] == "id"
                    ), "Unknown array length %s" % repr(arg.array_length)
                    arg.array_length = env[arg.array_length[1]]
            return ScapyArrayField(
                arg.name,
                arg.ptr_lvl,
                sub_arg,
                arg.array_length,
                idl_attributes=idl_attributes,
            )
        elif arg.TYPE == Types.STRUCT:
            if arg.struct_name in strct_types:
                # Recursion loop detected: most likely a struct containing somehow a
                # pointer to itself.
                return ScapyStruct(
                    name=arg.name,
                    ptr_lvl=arg.ptr_lvl,
                    fields=[],
                    idl_attributes=idl_attributes,
                    struct_name=arg.struct_name,
                    # Recursive flag: it's a virtual struct. Don't actually print it.
                    recursive=True,
                )

            def proc_f(v):
                field = self.make_field(
                    v, env, strct_types=strct_types + [arg.struct_name]
                )
                if isinstance(field, ScapyStruct) and not isinstance(
                    field, (ScapyUnion, ScapyEnum)
                ):
                    # Weird bizarre case where you just throw an struct inside a struct
                    struct_name = "%s%s" % (field.name, arg.struct_name)
                    field.name = struct_name
                    self.environment.append(field)
                    return ScapyStructField(
                        field.name,
                        field.ptr_lvl,
                        field,
                        struct_name,
                        field.idl_attributes,
                    )
                return field

            fields = [proc_f(v) for v in arg.fields]
            return ScapyStruct(
                arg.name,
                arg.ptr_lvl,
                fields,
                idl_attributes=idl_attributes,
                struct_name=arg.struct_name,
            )
        elif arg.TYPE == Types.UNION:

            def proc_f(i, v):
                # special handling: case is a #define'd value: switch_type is native and case is an ID
                if any(
                    x[0] == "switch_type" and x[1][0] == "native"
                    for x in idl_attributes
                ) and any(
                    isinstance(x, tuple)
                    and x[0] == "call"
                    and x[1] == "case"
                    and isinstance(x[2][0], tuple)
                    and x[2][0][0] == "id"
                    for x in v.idl_attributes
                ):
                    i, caseval = next(
                        (i, x[2][0])
                        for (i, x) in enumerate(v.idl_attributes)
                        if isinstance(x, tuple) and x[0] == "call" and x[1] == "case"
                    )
                    from scapy_obj import _rec_rslv_arithm

                    v.idl_attributes[i] = (
                        "call",
                        "case",
                        [_rec_rslv_arithm(caseval, env)],
                    )
                field = self.make_field(
                    v, env, strct_types=strct_types + [arg.struct_name]
                )
                if isinstance(field, ScapyStruct) and not isinstance(
                    field, (ScapyUnion, ScapyEnum)
                ):
                    # Weird bizarre case where you just throw an struct inside an union
                    struct_name = field.name + "_sub%s" % i
                    field.name = struct_name
                    self.environment.append(field)
                    return ScapyStructField(
                        field.name,
                        field.ptr_lvl,
                        field,
                        struct_name,
                        field.idl_attributes,
                    )
                return field

            fields = [proc_f(*v) for v in enumerate(arg.fields)]
            return ScapyUnion(
                arg.name,
                arg.ptr_lvl,
                fields,
                idl_attributes=idl_attributes,
                struct_name=arg.struct_name,
            )
        elif arg.TYPE == Types.ENUM:
            enums = {}
            for key, val in arg.enums.items():
                if isinstance(val, tuple) and val[0] == "id":
                    if val[1] in arg.enums:
                        # Depend of other in enum
                        val = val[1]
                    elif val[1] in env:
                        # depend of other declared value
                        val = env[val[1]]
                        # make sure it resolves
                        enumname = val.split(".")[0]
                        r = self.resolve_type(enumname, env, toplevel=False)
                    else:
                        assert False, "Unknown enum key: %s" % val[1]
                    # Optional additional offset
                    if len(val) == 3:
                        val += "+ %d" % val[2]
                elif isinstance(val, tuple) and val[0] == "binop":
                    from scapy_obj import _rec_rslv_arithm

                    val = _rec_rslv_arithm(val, env, prefix="").replace(
                        arg.name + ".", ""
                    )
                enums[key] = val

            return ScapyEnum(
                arg.name,
                arg.ptr_lvl,
                enums,
                idl_attributes=idl_attributes,
                struct_name=arg.enum_name,
            )
        else:
            assert False, "What is this? %s" % arg.TYPE


# --- Main

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Wrong usage.\n python midl_resolve.py [files]")
        sys.exit(1)
    else:
        for fname in sys.argv[1:]:
            print("### %s" % fname)
            # Parse & build AST
            c = Compiler()
            f = c.process_file(fname)
            # Convert into Scapy code
            d = Resolver(f)
            d.resolve_file(fname)
            # Print
            cfunc = sum(1 for x in d.environment if isinstance(x, ScapyFunc))
            cstrct = sum(1 for x in d.environment if isinstance(x, ScapyStruct))
            print("Environment: %s structures, %s functions" % (cstrct, cfunc))
            for obj in d.environment:
                print("- %s" % repr(obj))
