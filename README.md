# scapy-rpc

More details over in [the associated article](https://www.sstic.org/2025/presentation/l_outillage_reseau_windows_une_affaire_d_implementation/)

This repo contains two sub-projects:

## midl-to-scapy

A **Microsoft Interface Definition Language** (MIDL) parser that creates [Scapy](https://github.com/secdev/scapy) code, to interact with [MS-RPC](https://docs.microsoft.com/en-us/windows/win32/rpc) interfaces.

https://github.com/user-attachments/assets/044fb364-2a53-4ad7-97c9-e3c8e0c970fc

1. get your hands on the IDL file for an interface.
    - grab it from the section "Full IDL" from official documentations
    - use [RpcView](https://github.com/silverf0x/RpcView) to extract it from a running RPC server

2. run the tool on the IDL file to generate a Scapy interface


## scapy-rpc

A pre-compiled version of 117 windows interfaces (available through the Open Specifications).

**Compilation steps:**

1. run ./get-idls.sh to download all the IDLs. This will apply some minor patches to some.
2. run ./compile.sh which calls `midl-to-scapy` on all the downloaded IDLs.
