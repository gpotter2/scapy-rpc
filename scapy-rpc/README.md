<!-- start_ppi_description -->

# scapy-rpc

This package provides a plugin that hooks into Scapy to register additional RPC dissectors/builders.
Imports are lazy-loaded to not slow down startup.

This provides 110 MIDL interfaces retrieved from Microsoft's learn website, with minor patches.

#### Usage

```
$ scapy
>>> from scapy.layers.msrpce.raw.ms_lsad import *
OR
>>> load_layer("msrpce.raw.ms_lsad")
```

Then use it as specified in the DCE/RPC doc, which contains much more details:
https://scapy.readthedocs.io/en/latest/layers/dcerpc.html

<!-- stop_ppi_description -->

#### Installation

```
$ cd scapy-rpc
$ pip install .
OR for an editable install (my favorite)
$ pip install -e .
```
