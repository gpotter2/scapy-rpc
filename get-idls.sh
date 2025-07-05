#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RPC
# See https://scapy.net/ for more information

#
# Get IDLs from the protocol documentations
#

current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

# 1. Scrap IDLs
echo "1. Scrap IDLs"
if [ "$1" != "--skip" ]; then
    python3 "$current_path/midl-to-scapy/idl/idl_scraper.py" || exit $?
else
    echo "Skipped."
fi

# 2. Check that patches apply
echo "2. Checkint that patches apply..."
for patch in $current_path/midl-to-scapy/idl/patches/*.patch; do
    echo "Checking $patch..."
    git apply --check $patch || exit $?
done

# 3. Apply patches
echo "3. Applying patches"
git apply $current_path/midl-to-scapy/idl/patches/*.patch || exit $?
