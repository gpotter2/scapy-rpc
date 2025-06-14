#!/bin/bash

#
# Compile RPCs
#

current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
destination_path=$current_path/../scapy-rpc
mkdir -p $destination_path/msrpcs

shopt -s globstar

echo "midl_to_scapy.py"
find $current_path/idl -name "*.idl" | while read filename; do
  [ -e "$filename" ] || continue
  name=${filename##*/}
  base=${name%.idl}
  [[ "$base" =~ ^(ms-dtyp|demo|ms-fax_faxobs|ms-eerr)$ ]] && continue
  base=${base//-/_}
  echo "- Compiling $name"
  python3 $current_path/midl_to_scapy.py $filename > $destination_path/msrpcs/$base.py
  RES=$?
  if [ $RES -ne 0 ]; then
    echo "ERROR: returned $RES"
    exit $RES
  fi
done
