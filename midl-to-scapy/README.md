# midl-to-scapy

- the root of this folder contains the MIDL to Scapy compiler
  - `midl_parser.py` does the lexing
  - `midl_convert.py` builds the AST from the lexed tree
  - `midl_resolve.py` does the processing of the AST (resolution of the structures, etc.)
  - `scapy_obj.py` creates the Scapy code from the processed AST.
- `idl/` contains the current version of the IDLs used
- `patches/` contains some patches applied over Microsoft's spec
