# ScapyRPC

Provides:
- `tools.smbserver`: a SMB server that extends the one in Scapy to support serving files, and using netlogon to get the sessionkey (requires RPCs)
- `tools.smb_scan_winver`: tiny SMB tool to scan Windows versions
- A bunch of WIP stuff or examples on how to use Scapy + this project

#### PLAN

- don't release `midl-to-scapy` just yet
- keep offensive stuff here !
- develop enough stuff to make the DCE/RPC & SMB implementation of Scapy look good

# midl-to-scapy

A **Microsoft Interface Definition Language** (MIDL) parser that creates [Scapy](https://github.com/secdev/scapy) code, to interact with [MS-RPC](https://docs.microsoft.com/en-us/windows/win32/rpc) interfaces.

**This does not implement parsing for the whole MIDL language**

Tested on / included:
- [MS-BKRP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-bkrp/90b08be4-5175-4177-b4ce-d920d797e3a8) BackupKey Remote Protocol (v25.0)
- [MS-DCOM](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0) Distributed Component Object Model Remote Protocol (v23.0)
- [MS-DSRS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47) Directory Replication Service Remote Protocol (v42.0)
- [MS-EVEN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f) EventLog Remoting Protocol (v24.0)
- [MS-EVEN6](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/18000371-ae6d-45f7-95f3-249cbe2be39b) EventLog Remoting Protocol Version 6.0 (v24.0)
- [MS-LSAD](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc) Local Security Authority (Domain Policy) Remote Protocol (v46.0)
- [MS-LSAT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/1ba21e6f-d8a9-462c-9153-4375f2020894) Local Security Authority (Translation Methods) Remote Protocol (v32.0)
- [MS-NRPC](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f) Netlogon Remote Protocol (v40.0)
- [MS-NSPI](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nspi/6dd0a3ea-b4d4-4a73-a857-add03a89a543) Name Service Provider Interface Protocol (v15.0)
- [MS-OXABREF](https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxabref/88c2b896-fe4f-4e28-8a87-e83a73d9c90e) Address Book Name Service Provider Interface Referral Protocol (v13.0)
- [MS-OXNSPI](https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxnspi/63662a26-c8fc-4493-a41a-fbcbb7e43136) Exchange Server Name Service Provider Interface Protocol (v13.1)
- [MS-PAR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/695e3f9a-f83f-479a-82d9-ba260497c2d0) Print System Asynchronous Remote Protocol (v17.0)
- [MS-RPRN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1) Print System Remote Protocol (v37.0)
- [MS-RRP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78) Windows Remote Registry Protocol (v37.0)
- [MS-SAMR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380) Security Account Manager (SAM) Remote Protocol (Client-to-Server) (v45.0)
- [MS-SCMR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f) Service Control Manager Remote Protocol (v33.0)
- [MS-SRVS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9) Server Service Remote Protocol (v38.0)
- [MS-TSCH](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931) Task Scheduler Service Remoting Protocol (v27.0)
- [MS-WKST](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/5bb08058-bc36-4d3c-abeb-b132228281b7) Workstation Service Remote Protocol (v31.0)


### Usage:

1. get your hands on the IDL file for an interface.
    - grab it from the section "Full IDL" from official documentations
    - use [RpcView](https://github.com/silverf0x/RpcView) to extract it from a running RPC server

2. run the tool on the IDL file to generate a Scapy interface

