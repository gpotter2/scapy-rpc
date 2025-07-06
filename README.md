# scapy-rpc

[![Scapy RPC unit tests](https://github.com/gpotter2/scapy-rpc/actions/workflows/unittests.yml/badge.svg?branch=master&event=push)](https://github.com/gpotter2/scapy-rpc/actions/workflows/unittests.yml?query=event%3Apush)

More details over in [the associated article](https://www.sstic.org/media/SSTIC2025/SSTIC-actes/l_outillage_reseau_windows_une_affaire_d_implement/SSTIC2025-Article-l_outillage_reseau_windows_une_affaire_d_implementation-potter.pdf) (english) or [the presentation](https://www.sstic.org/2025/presentation/l_outillage_reseau_windows_une_affaire_d_implementation/) (french).

This repo contains two sub-projects:

## midl-to-scapy

A **Microsoft Interface Definition Language** (MIDL) parser that creates [Scapy](https://github.com/secdev/scapy) code, to interact with [MS-RPC](https://docs.microsoft.com/en-us/windows/win32/rpc) interfaces.

https://github.com/user-attachments/assets/044fb364-2a53-4ad7-97c9-e3c8e0c970fc

1. get your hands on the IDL file for an interface.
    - grab it from the section "Full IDL" from official documentations
    - use [RpcView](https://github.com/silverf0x/RpcView) to extract it from a running RPC server
    - use `Get-RpcServer <DLL> | Format-RpcServer` from [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools)

2. run the tool on the IDL file to generate a Scapy interface


## scapy-rpc

A pre-compiled version of 110 windows interfaces (available through the Open Specifications).

**Compilation steps:**

1. run ./get-idls.sh to download all the IDLs. This will apply some minor patches to some.
2. run ./compile.sh which calls `midl-to-scapy` on all the downloaded IDLs.

## License

scapy-rpc's code, tests and tools are licensed under GPL v2.
