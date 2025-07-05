# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information

"""
Parse Microsoft Interface Definition Language (MIDL)
"""

import sys

# https://github.com/dabeaz/ply/blob/master/doc/ply.md
# https://docs.microsoft.com/en-us/windows/win32/midl/midl-language-reference

from ply.lex import lex
from ply.yacc import yacc

DEBUG = 0

# --- Tokenizer

# Reserved keywords
reserved = {
    "typedef": "TYPEDEF",
    "interface": "INTERFACE",
    "coclass": "COCLASS",
    "import": "IMPORT",
    "void": "VOID",
    "struct": "STRUCT",
    "union": "UNION",
    "enum": "ENUM",
    "pipe": "PIPETYPE",
}

# All tokens must be named in advance.
tokens = [
    "LPAREN",
    "RPAREN",
    "LBRACE",
    "RBRACE",
    "LBRACK",
    "RBRACK",
    "STRING",
    "IDENT",
    "UUID",
    "FLOAT",
    "INTEGER",
    "STAR",
    "PLUS",
    "MINUS",
    "DIVIDE",
    "PIPE",
    "LESSTHAN",
    "GREATERTHAN",
    "COMA",
    "SEMI",
    "MACROBEGIN",
    "MACROEND",
    "TILDE",
    "AMPERSAND",
] + list(reserved.values())

precedence = (
    ("nonassoc", "LESSTHAN", "GREATERTHAN"),
    ("left", "="),
    ("left", "PLUS", "MINUS"),
    ("left", "STAR", "DIVIDE", "AMPERSAND", "PIPE"),
    ("left", "?", ":"),
    ("right", "LPAREN", "RPAREN"),
    ("right", "TILDE"),
    ("right", "IDENT"),
    ("right", "UMINUS"),
)

literals = ["=", ":", "?"]

states = (("macro", "inclusive"),)

# A string containing ignored characters (spaces and tabs)
t_ignore = " \t"

# C or C++ comment (ignore)
def t_comment(t):
    r"(/\*(.|\n)*?\*/)|(//.*)"
    t.lexer.lineno += t.value.count("\n")


# Macro
def t_MACROBEGIN(t):
    r"(\#)|(cpp_quote\(\s*\")|(midl_pragma)"
    t.lexer.begin("macro")
    return t


def t_macro_MACROEND(t):
    r"(\"\s*\))?\n"
    t.lexer.begin("INITIAL")
    t.lexer.lineno += t.value.count("\n")
    return t


# Define a rule so we can track line numbers
def t_newline(t):
    r"\n+"
    t.lexer.lineno += t.value.count("\n")


# Token matching rules are written as regexs
t_STAR = r"\*"
t_TILDE = r"\~"
t_AMPERSAND = r"\&"
t_PLUS = r"\+"
t_MINUS = r"\-"
t_DIVIDE = r"\/"
t_PIPE = r"\|"
t_LESSTHAN = r"\<"
t_GREATERTHAN = r"\>"
t_LPAREN = r"\("
t_RPAREN = r"\)"
t_LBRACE = r"\["
t_RBRACE = r"\]"
t_LBRACK = r"\{"
t_RBRACK = r"\}"
t_SEMI = r";"
t_COMA = r","


def t_STRING(t):
    r"L?\"([^\\\n]|(\\.))*?\" "
    t.value = t.value[1:-1]
    return t


def t_UUID(t):
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    return t


def t_IDENT(t):
    r"[a-zA-Z_][a-zA-Z_0-9]*"
    t.type = reserved.get(t.value, "IDENT")  # Check for reserved words
    return t


# A function can be used if there is an associated action.
# Write the matching regex in the docstring.
def t_FLOAT(t):
    r"((\d+)(\.\d+)(e(\+|-)?(\d+))?|(\d+)e(\+|-)?(\d+))"
    t.value = float(t.value)
    return t


def t_INTEGER(t):
    r"(0[xX][0-9a-fA-F]+L?)|(\d+L?)"
    if t.value[:2] == "0x":
        t.value = int(t.value.rstrip("L"), 16)
    else:
        t.value = int(t.value.rstrip("L"))
    return t


# Error handler for illegal characters
def t_error(t):
    t.lexer.skip(1)
    print(f"Illegal character {t.value[0]!r}")
    sys.exit(1)


# Build the lexer object
lexer = lex()

# --- Parser


# Write functions for each grammar rule which is
# specified in the docstring.
def p_expression(p):
    """
    expression : macro expression
               | interface expression
               | interface SEMI expression
               | interface-definition SEMI expression
               | interface-definition expression
               | expr SEMI expression
               | expr SEMI
               | expr
               | macro
               | interface
               | SEMI
    """
    if len(p) == 3:
        if p[2] == ";":
            p[0] = [p[1]]
        else:
            p[0] = [p[1]] + p[2]
    elif len(p) == 4:
        # Inconsistency: this shouldn't exist for interfaces... but is
        # of course in ms-dcom
        p[0] = [p[1]] + p[3]
    elif len(p) == 2:
        p[0] = [p[1]]


def p_macro(p):
    r"""
    macro : MACROBEGIN IDENT IDENT tup-elem MACROEND
          | MACROBEGIN IDENT IDENT '=' tup-elem SEMI MACROEND
          | MACROBEGIN IDENT IDENT tup-elem stars MACROEND
          | MACROBEGIN IDENT IDENT LBRACE idl-type-attribute-list RBRACE tup-elem stars MACROEND
          | MACROBEGIN MACROBEGIN IDENT IDENT tup-elem MACROEND
          | MACROBEGIN IDENT atom-expr MACROEND
          | MACROBEGIN IDENT MACROEND
          | MACROBEGIN MACROEND
    """
    if len(p) == 3:
        # no macro
        p[0] = ("macro", ("empty",))
    elif len(p) == 4:
        # endif
        p[0] = ("macro", (p[2],))
    elif len(p) == 5:
        # ifdef xxxx
        if p[2] == "include":
            # We alias #include to import
            p[0] = ("import", p[3])
        else:
            p[0] = ("macro", (p[2], p[3]))
    elif len(p) == 6:
        # define x y
        p[0] = ("macro", (p[2], ("id", p[3]), p[4], []))
    elif len(p) == 7:
        if p[2] == "#":
            # cpp_comment("#define x y")
            p[0] = ("macro", (p[3], ("id", p[4]), p[5], []))
        else:
            # define X *
            p[0] = ("macro", (p[2], (len(p[5]) * "ptr", p[3]), p[4], []))
    elif len(p) == 8:
        if p[4] == "=":
            # define x = y;
            p[0] = ("macro", (p[2], ("id", p[3]), p[5], []))
    elif len(p) == 10:
        #define PCWSTR      [string] const wchar_t*
        p[0] = ("macro", (p[2], (len(p[8]) * "ptr", p[3]), p[7], p[5]))


def p_atom_expr(p):
    """
    atom-expr : atom-expr AMPERSAND atom-expr
              | atom-expr PLUS atom-expr
              | atom-expr MINUS atom-expr
              | atom-expr STAR atom-expr
              | atom-expr DIVIDE atom-expr
              | atom-expr PIPE atom-expr
              | atom-expr GREATERTHAN atom-expr
              | atom-expr GREATERTHAN GREATERTHAN atom-expr
              | atom-expr GREATERTHAN '=' atom-expr
              | atom-expr LESSTHAN atom-expr
              | atom-expr LESSTHAN LESSTHAN atom-expr
              | atom-expr LESSTHAN '=' atom-expr
              | atom-expr '?' atom-expr ':' atom-expr
              | LPAREN atom-expr RPAREN atom-expr
              | LPAREN atom-expr RPAREN
              | TILDE atom-expr
              | atom
    """
    if len(p) == 6:
        p[0] = ("if", p[1], p[3], p[5])
    elif len(p) == 5:
        if p[3] in ["=", "<", ">"]:
            p[0] = ("binop", p[2] + p[3], p[1], p[4])
        else:
            p[0] = ("cast", p[2], p[4])
    elif len(p) == 4:
        if p[1] == "(":
            p[0] = p[2]
        else:
            p[0] = ("binop", p[2], p[1], p[3])
    elif len(p) == 3:
        p[0] = ("monop", p[1], p[2])
    elif len(p) == 2:
        p[0] = p[1]


def p_tup_elems(p):
    """
    tup-elem : IDENT type-specifier
             | ENUM type-specifier
             | STRUCT type-specifier
             | atom-expr
    """
    if len(p) == 2:
        p[0] = [p[1]]
    elif len(p) == 3:
        # Theese rules are to avoid conflicts between
        # tup-elem->atom-expr->atom->IDENT
        # type-specifier->IDENT
        # by making sure type-specifier is double (won't match atom-expr)
        p[0] = [("id", p[1])] + p[2]


def p_tup_elem(p):
    """
    tup-elems : tup-elem COMA tup-elems
              | COMA tup-elems
              | tup-elem COMA
              | tup-elem
    """
    if len(p) == 4:
        p[0] = p[1] + p[3]
    elif len(p) == 3:
        # Weird cases: size_is(,*pcNames)
        # or size_is(*pcNames,)
        if p[1] == ",":
            p[0] = p[2]
        else:
            p[0] = p[1]
    elif len(p) == 2:
        p[0] = p[1]


def p_atom(p):
    """
    atom : UUID
         | STRING
         | star-ident
         | FLOAT
         | INTEGER
         | MINUS INTEGER %prec UMINUS
         | IDENT LPAREN tup-elems RPAREN
         | IDENT LPAREN RPAREN
    """
    if len(p) == 4:
        p[0] = ("call", p[1])
    elif len(p) == 5:
        p[0] = ("call", p[1], p[3])
    elif len(p) == 3:
        # UMINUS
        p[0] = - p[2]
    elif len(p) == 2:
        p[0] = p[1]


def p_name(p):
    """
    name : star-ident
         | star-ident LBRACE RBRACE
         | star-ident LBRACE STAR RBRACE
         | star-ident LBRACE atom-expr RBRACE
         | VOID stars
         | VOID
    """
    if len(p) == 4:
        p[0] = ("array", p[1], None)
    elif len(p) == 5:
        p[0] = ("array", p[1], p[3])
    elif len(p) == 3:
        p[0] = ("id", "void")
    elif len(p) == 2:
        if p[1] == "void":
            p[0] = ("id", p[1])
        else:
            p[0] = p[1]


def p_stars(p):
    """
    stars : stars STAR
          | STAR
    """
    if len(p) == 3:
        p[0] = p[1] + p[2]
    elif len(p) == 2:
        p[0] = p[1]


def p_starident(p):
    """
    star-ident : stars IDENT
               | IDENT
    """
    if len(p) == 3:
        p[0] = (len(p[1]) * "ptr", p[2])
    elif len(p) == 2:
        p[0] = ("id", p[1])


def p_coma_separated_ident(p):
    """
    coma-separated-idents : coma-separated-idents COMA name
                          | name
    """
    if len(p) == 2:
        p[0] = [p[1]]
    elif len(p) == 4:
        p[0] = p[1] + [p[3]]


def p_struct_attr(p):
    """
    struct-attr : LBRACE idl-type-attribute-list RBRACE type-specifier coma-separated-idents
                | LBRACE idl-type-attribute-list RBRACE LBRACE idl-type-attribute-list RBRACE type-specifier coma-separated-idents
                | type-specifier coma-separated-idents
                | UNION LBRACK struct-block RBRACK declarator-list
                | LBRACE idl-type-attribute-list RBRACE UNION IDENT LBRACK union-block RBRACK declarator-list
                | LBRACE idl-type-attribute-list RBRACE UNION LBRACK union-block RBRACK declarator-list
                | LBRACE idl-type-attribute-list RBRACE UNION LBRACK union-block RBRACK
                | UNION LBRACK struct-block RBRACK
                | STRUCT LBRACK struct-block RBRACK
                | STRUCT LBRACK struct-block RBRACK declarator-list
                | STRUCT IDENT LBRACK struct-block RBRACK declarator-list
                | LBRACE idl-type-attribute-list RBRACE STRUCT LBRACK struct-block RBRACK declarator-list
                | LBRACE idl-type-attribute-list RBRACE STRUCT IDENT LBRACK struct-block RBRACK declarator-list
    """
    if len(p) == 10:
        p[0] = ("union", p[2], p[5], p[7], p[9])
    elif len(p) == 9:
        if p[4] == "union":
            p[0] = ("union", p[2], "_u", p[6], p[8])
        elif p[4] == "struct":
            p[0] = ("struct", p[2], p[6], p[8])
        else:
            # wtf, [range(0, 1024)] [size_is(count)]... whereas there should only be 1 per spec
            p[0] = ("attr", p[2] + p[5], p[7], p[8])
    elif len(p) == 8:
        # This is weird but seen. Fallback to using a dummy name
        p[0] = ("union", p[2], "_u", p[6], [("id", "value")])
    elif len(p) == 7:
        if p[1] == "struct":
            p[0] = ("struct", [], p[4], p[6])
    elif len(p) == 6:
        if p[1] == "union":
            # Get underscore name
            p[0] = ("union", [], "_" + p[5][0][1], p[3], p[5])
        elif p[1] == "struct":
            p[0] = ("struct", [], p[3], p[5])
        else:
            p[0] = ("attr", p[2], p[4], p[5])
    elif len(p) == 5:
        if p[1] == "union":
            # This is weird but seen. Fallback to using a dummy name
            p[0] = ("union", [], "_u", p[3], [("id", "u")])
        elif p[1] == "struct":
            p[0] = ("struct", [], p[3], [("id", "s")])
    elif len(p) == 3:
        p[0] = ("attr", [], p[1], p[2])


def p_struct_block(p):
    """
    struct-block : struct-attr SEMI struct-block
                 | struct-attr SEMI
                 | macro struct-block
                 | macro
    """
    if len(p) == 2:
        p[0] = []  # discard macro
    elif len(p) == 3:
        if p[2] != ";":
            p[0] = p[2]  # discard macro
        else:
            p[0] = [p[1]]
    else:
        p[0] = [p[1]] + p[3]


def p_union_attr(p):
    """
    union-attr : LBRACE idl-type-attribute-list RBRACE LBRACE idl-type-attribute-list RBRACE type-specifier coma-separated-idents
               | LBRACE idl-type-attribute-list RBRACE type-specifier coma-separated-idents
               | LBRACE idl-type-attribute-list RBRACE STRUCT LBRACK struct-block RBRACK
               | LBRACE idl-type-attribute-list RBRACE STRUCT LBRACK struct-block RBRACK coma-separated-idents
               | LBRACE idl-type-attribute-list RBRACE STRUCT IDENT LBRACK struct-block RBRACK coma-separated-idents
               | LBRACE idl-type-attribute-list RBRACE
    """
    if len(p) == 10:
        p[0] = ("struct", p[2], p[7], p[9])
    elif len(p) == 9:
        if p[4] == "struct":
            p[0] = ("struct", p[2], p[6], p[8])
        else:
            # Inconsistent...
            p[0] = ("attr", p[2] + p[5], p[7], p[8])
    elif len(p) == 8:
        p[0] = ("struct", p[2], p[6], [("id", "u")])
    elif len(p) == 6:
        p[0] = ("attr", p[2], p[4], p[5])
    elif len(p) == 4:
        p[0] = ("attr", p[2], None, [None])


def p_union_block(p):
    """
    union-block : union-attr SEMI union-block
                | union-attr SEMI
    """
    if len(p) == 3:
        p[0] = [p[1]]
    else:
        p[0] = [p[1]] + p[3]


def p_union_attr_c(p):
    """
    union-attr-c : IDENT star-ident ':' type-specifier coma-separated-idents
                 | IDENT atom ':' type-specifier coma-separated-idents
    """
    p[0] = ("attr", [("call", "case", [p[2]])], p[4], p[5])


def p_union_block_c(p):
    """
    union-block-c : union-attr-c SEMI union-block-c
                  | union-attr-c SEMI
    """
    if len(p) == 3:
        p[0] = [p[1]]
    else:
        p[0] = [p[1]] + p[3]


def p_enum_attr(p):
    """
    enum-attr : IDENT '=' atom-expr
              | IDENT
    """
    if len(p) == 4:
        p[0] = (p[1], p[3])
    elif len(p) == 2:
        p[0] = (p[1], None)


def p_enum_block(p):
    """
    enum-block : enum-attr COMA enum-block
               | enum-attr COMA
               | enum-attr
    """
    if len(p) == 4:
        p[0] = [p[1]] + p[3]
    elif len(p) in [2, 3]:
        p[0] = [p[1]]


def p_type_specifier(p):
    """
    type-specifier : type-specifier name
                   | STRUCT name
                   | ENUM name
                   | name
                   | name LPAREN name RPAREN
    """
    if len(p) == 5:
        # special case: a cast union. e.g. SAFEARRAY(VARIANT). ignore
        p[0] = [p[1]]
    elif len(p) == 3:
        if p[1] in ["struct", "enum"]:
            p[0] = [("id", p[1]), p[2]]
        else:
            p[0] = p[1] + [p[2]]
    elif len(p) == 2:
        p[0] = [p[1]]


def p_type_attribute(p):
    """
    idl-type-attribute : atom-expr
                       | macro atom-expr
    """
    if len(p) == 2:
        p[0] = p[1]
    elif len(p) == 3:
        # Discard macro (will this hurt us later?). macros used in attributes are only #ifdefs...
        p[0] = p[2]


def p_type_attribute_list(p):
    """
    idl-type-attribute-list : idl-type-attribute-list COMA idl-type-attribute
                            | idl-type-attribute-list COMA
                            | idl-type-attribute
    """
    if len(p) == 4:
        p[0] = p[1] + [p[3]]
    elif len(p) == 3:
        p[0] = p[1]
    elif len(p) == 2:
        p[0] = [p[1]]


def p_declaratorlist(p):
    """
    declarator-list : declarator-list COMA name
                    | name
    """
    if len(p) == 4:
        p[0] = p[1] + [p[3]]
    elif len(p) == 2:
        p[0] = [p[1]]


def p_expr_typedef(p):
    """
    expr : TYPEDEF attribute-list-group UNION IDENT LBRACK union-block RBRACK declarator-list
         | TYPEDEF attribute-list-group UNION LBRACK union-block RBRACK declarator-list
         | attribute-list-group TYPEDEF UNION LBRACK union-block RBRACK declarator-list
         | TYPEDEF STRUCT IDENT LBRACK struct-block RBRACK declarator-list
         | TYPEDEF STRUCT LBRACK struct-block RBRACK declarator-list
         | TYPEDEF attribute-list-group STRUCT IDENT LBRACK struct-block RBRACK declarator-list
         | TYPEDEF attribute-list-group ENUM IDENT LBRACK enum-block RBRACK declarator-list
         | TYPEDEF attribute-list-group ENUM LBRACK enum-block RBRACK declarator-list
         | attribute-list-group TYPEDEF ENUM IDENT LBRACK enum-block RBRACK declarator-list
         | TYPEDEF ENUM IDENT LBRACK enum-block RBRACK declarator-list
         | TYPEDEF ENUM LBRACK enum-block RBRACK declarator-list
         | TYPEDEF attribute-list-group type-specifier declarator-list
         | TYPEDEF type-specifier declarator-list
         | TYPEDEF UNION IDENT idl-type-attribute-list IDENT LBRACK union-block-c RBRACK declarator-list
         | TYPEDEF PIPETYPE type-specifier declarator-list
    """
    # https://docs.microsoft.com/en-us/windows/win32/midl/typedef
    if len(p) == 10:
        if p[2] == "union":
            # this is a C-like union but in MIDL :( (ms-oaut.idl)
            p[0] = ("typedef", ("union", p[4], p[3], p[7], p[9]))
    elif len(p) == 9:
        if p[3] == "union":
            p[0] = ("typedef", ("union", p[2], p[4], p[6], p[8]))
        elif p[3] == "enum":
            if p[2] == "typedef":
                p[0] = ("typedef", ("enum", p[1], p[4], p[6], p[8]))
            else:
                p[0] = ("typedef", ("enum", p[2], p[4], p[6], p[8]))
        elif p[3] == "struct":
            # struct with idl attributes. this makes NO sense. ignore them
            p[0] = ("typedef", ("struct", p[4], p[6], p[8]))
    elif len(p) == 8:
        # Again, this is inconsistent but seen. Fallback to using a dummy name
        if p[3] == "union":
            if p[1] == "typedef":
                p[0] = ("typedef", ("union", p[2], "dummy", p[5], p[7]))
            elif p[2] == "typedef":
                p[0] = ("typedef", ("union", p[1], "dummy", p[5], p[7]))
        elif p[3] == "enum":
            p[0] = ("typedef", ("enum", p[2], "dummy", p[5], p[7]))
        elif p[2] == "enum":
            p[0] = ("typedef", ("enum", [], p[3], p[5], p[7]))
        else:
            p[0] = ("typedef", ("struct", p[3], p[5], p[7]))
    elif len(p) == 7:
        if p[2] == "struct":
            # Inconsistent: no struct name
            p[0] = ("typedef", ("struct", "_" + p[6][0][1], p[4], p[6]))
        elif p[2] == "enum":
            # Inconsistent: no struct name
            p[0] = ("typedef", ("enum", [], "_" + p[6][0][1], p[4], p[6]))
    elif len(p) == 6:
        # Inconsistent ! Missing struct name...
        p[0] = ("typedef", ("struct", p[6][0], p[4], p[6]))
    elif len(p) == 5:
        if p[2] == "pipe":
            p[0] = ("typedef", ("type", [], [("id", "pipe")] + p[3], p[4]))
        else:
            p[0] = ("typedef", ("type", p[2], p[3], p[4]))
    elif len(p) == 4:
        p[0] = ("typedef", ("type", [], p[2], p[3]))


def p_expr_enum(p):
    """
    expr : ENUM IDENT LBRACK enum-block RBRACK
    """
    # Alternative syntax for typedef enum
    p[0] = ("typedef", ("enum", [], p[2], p[4], [("id", p[2])]))


def p_expr_struct(p):
    """
    expr : STRUCT IDENT LBRACK struct-block RBRACK
    """
    # Alternative syntax for typedef struct
    p[0] = ("typedef", ("struct", p[2], p[4], [("id", p[2])]))


def p_expr_def(p):
    """
    expr : type-specifier name '=' atom-expr
    """
    p[0] = ("typedef", ("val", p[1], p[2], p[4]))


def p_attribute_list_group(p):
    """
    attribute-list-group : LBRACE idl-type-attribute-list RBRACE attribute-list-group
                         | LBRACE idl-type-attribute-list RBRACE
    """
    # There are some slight inconsistencies in how attributes are defined. In MS-SAMR you will find both:
    # [in] [switch_is(InVersion)] SAMPR_REVISION_INFO *InRevisionInfo,
    # and
    # [in, switch_is(ValidationType)] PSAM_VALIDATE_INPUT_ARG InputArg,
    # so this concatenates them all
    if len(p) == 5:
        p[0] = p[2] + p[4]
    elif len(p) == 4:
        p[0] = p[2]


def p_arg(p):
    """
    arg : attribute-list-group type-specifier name
        | type-specifier name
    """
    if len(p) == 4:
        p[0] = (p[1], p[2], p[3])
    elif len(p) == 3:
        p[0] = ([], p[1], p[2])


def p_arg_list(p):
    """
    arg-list : arg COMA arg-list
             | VOID
             | arg
    """
    if len(p) == 4:
        p[0] = [p[1]] + p[3]
    elif len(p) == 2:
        p[0] = [p[1]]


def p_expr_func(p):
    """
    expr : type-specifier IDENT LPAREN arg-list RPAREN
         | type-specifier IDENT LPAREN RPAREN
         | LBRACE idl-type-attribute-list RBRACE type-specifier IDENT LPAREN arg-list RPAREN
         | LBRACE idl-type-attribute-list RBRACE type-specifier IDENT LPAREN RPAREN
    """
    if len(p) == 5:
        p[0] = ("func", [], p[1], p[2], ["void"])
    elif len(p) == 6:
        p[0] = ("func", [], p[1], p[2], p[4])
    elif len(p) == 8:
        p[0] = ("func", p[2], p[4], p[5], ["void"])
    elif len(p) == 9:
        p[0] = ("func", p[2], p[4], p[5], p[7])


def p_expr_interface(p):
    """
    interface : attribute-list-group INTERFACE IDENT LBRACK expression RBRACK
              | attribute-list-group INTERFACE IDENT ':' IDENT LBRACK expression RBRACK
              | attribute-list-group INTERFACE IDENT ':' IDENT LBRACK RBRACK
              | attribute-list-group COCLASS IDENT LBRACK expression RBRACK
              | attribute-list-group COCLASS IDENT ':' IDENT LBRACK expression RBRACK
    """
    if len(p) == 7:
        p[0] = (p[2], p[3], None, p[1], p[5])
    elif len(p) == 8:
        # Empty content with inheritance
        p[0] = (p[2], p[3], p[5], p[1], [])
    elif len(p) == 9:
        # Supports inheritance
        p[0] = (p[2], p[3], p[5], p[1], p[7])


def p_expr_interface_definition(p):
    """
    interface-definition : INTERFACE IDENT
                         | attribute-list-group INTERFACE IDENT
    """
    if len(p) == 3:
        p[0] = ("interface-definition", p[2])
    elif len(p) == 4:
        p[0] = ("interface-definition", p[3])


def p_expr_import(p):
    """
    expr : IMPORT STRING
    """
    p[0] = ("import", p[2])


def p_error(p):
    print(f"Syntax error at {p.value!r} on line {p.lexer.lineno}")
    sys.exit(1)


# Build the parser
parser = yacc(debug=DEBUG)

# --- Main

if __name__ == "__main__":
    if len(sys.argv) > 2:
        print("Wrong usage.\n python midl_parser.py [file]")
        sys.exit(1)
    elif len(sys.argv) == 2:
        with open(sys.argv[1], "r") as fd:
            result = parser.parse(fd.read(), debug=DEBUG)
        print(result)
    elif len(sys.argv) == 1:
        while True:
            s = ""
            print(">", end="")
            while True:
                try:
                    s += input() + "\n"
                except EOFError:
                    break
                if not s:
                    continue
            result = parser.parse(s, debug=DEBUG)
            print(result)
