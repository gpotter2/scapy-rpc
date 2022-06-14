# scapy-rpc

This package provides a plugin that hooks into Scapy to register additional RPC dissectors/builders.
Imports are lazy-loaded to not slow down startup.

#### Installation

```
$ cd scapy-rpc
$ pip install .
OR for an editable install (my favorite)
$ pip install -e .
```

#### Usage

```
$ scapy
>>> from scapy.layers.msrpce.raw.ms_lsad import *
OR
>>> load_layer("msrpce.raw.ms_lsad")
```

Then use it as specified in the DCE/RPC doc:
https://scapy.readthedocs.io/en/latest/layers/dcerpc.html

#### Special

Load EERR (Extended ERRor remote data structure) and Enable "Extended Error Information" in gpedit.msc to
have much more detailed error codes.
```
$ scapy
>>> load_layer("msrpce.raw.ms_eerr")
```
