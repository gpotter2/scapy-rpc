# SPDX-License-Identifier: Apache-2.0
# This file is part of Scapy RPC
# Copyright 2022 Akamai Technologies, Inc.
# Copyright 2025 Gabriel Potter

"""
Retrieves the IDLs for all RPCs from microsoft's documentation.

This is based off 'Akamai RPC Toolkit'
https://github.com/akamai/akamai-security-research/tree/main/rpc_toolkit
"""

import concurrent.futures
import json
import pathlib
import re
import requests
import sys

from bs4 import BeautifulSoup
from tqdm import tqdm

PROTOCOLS = [
    {
        "name": "Windows Protocols",
        "folder": "win",
        "root": "https://docs.microsoft.com/en-us/openspecs/windows_protocols",
        "list": "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-winprotlp/e36c976a-6263-42a8-b119-7a3cc41ddd2a",
        "extras": [
            # Protocols not listed in the "list"
            "ms-dltm",
            "ms-dmrp",
            "ms-dtyp",
            "ms-tsts",
        ],
    },
    {
        "name": "Exchange Protocols",
        "folder": "win",
        "root": "https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols",
        "list": "https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprotlp/229f77ea-6518-4fe7-84fe-bd535fc6c32e",
        "extras": [
            # Protocols not listed in the "list"
            "ms-oxcrpc",
        ],
    },
    {
        "name": "SharePoint Protocols",
        "folder": "win",
        "root": "https://learn.microsoft.com/en-us/openspecs/sharepoint_protocols",
        "list": "https://learn.microsoft.com/en-us/openspecs/sharepoint_protocols/MS-SPPROTLP/51f9ccbf-ea59-4bb5-9fe6-27bc5af855ff",
    },
]

DEFAULT = "DEFAULT"


def get_protocol_list(TECHNICAL_DOCS_URL):
    """
    Fetch the list of protocol names from Microsoft's technical documents page.
    """
    html = requests.get(TECHNICAL_DOCS_URL).content
    soup = BeautifulSoup(html, "html.parser")
    table_rows = soup.find("table").find("tbody").find_all("tr")
    idl_names = []
    for row in table_rows:
        left_cell = row.find("td")
        a = left_cell.find("a")
        assert a["data-linktype"] == "relative-path"
        relative_url = left_cell.find("a")["href"]
        name, uuid = relative_url.split("/")[1:]
        idl_names.append(name)
    return idl_names


def get_toc_items_from_protocol_name(protocol_name, PROTOCOLS_URL):
    """
    Fetch the table of contents JSON file for a specific protocol, and return its "items" list.
    This is the first step towards getting the URLs for all relvant IDL files.
    """
    toc_url = PROTOCOLS_URL + "/" + protocol_name + "/toc.json"
    toc_page = requests.get(toc_url).content
    return json.loads(toc_page).get("items", None)


def get_dicts_rec(array):
    """
    Recursively yields all dicationary objects from the table of content JSON.
    This is a helper function for get_idl_page_uuids_from_toc_items().
    """
    for element in array:
        yield (element)
        if "children" in element:
            for child in get_dicts_rec(element["children"]):
                yield (child)


def get_idl_page_uuids_from_toc_items(items):
    """
    Fetch the UUIDs of the pages where IDL files are documented.
    These are *not* the UUIDs of the interfaces! :) Just pages identifiers.
    """
    idl_page_uuids = {}
    for item in get_dicts_rec(items):
        toc_title = item.get("toc_title", "")
        if (
            "Full" in toc_title
            and "IDL" in toc_title
            or "Formal MIDL Definition" in toc_title
        ) and "children" not in item:
            # This is the case when only a single IDL is present for the protocol.
            # Mark this IDL page as DEFAULT.
            idl_page_uuids[DEFAULT] = item.get("href", "")
        elif (
            toc_title.endswith(".idl")
            or toc_title.endswith(".h")
            and "Appendix" in toc_title
        ):
            # This is the case where multiple IDL files are present for the protocol.
            try:
                idl_name = re.search(r"(\w+\.(idl|h))", toc_title).group(1)
                idl_page_uuids[idl_name] = item.get("href", "")
            except AttributeError:
                print(
                    f"could not fetch IDL name from TOC. toc_title = {toc_title}",
                    file=sys.stderr,
                )
    return idl_page_uuids


def get_idl_urls(protocol_name, PROTOCOLS_URL):
    """
    Return the IDL urls for each IDL in the page.
    """
    # 1. Get the list of TOC items
    toc_items = get_toc_items_from_protocol_name(protocol_name, PROTOCOLS_URL)
    if not toc_items:
        return

    # 2. Find TOC items that contain an IDL
    idl_page_uuids = get_idl_page_uuids_from_toc_items(toc_items)
    if not idl_page_uuids:
        return

    # 3. Build the URLs from those TOC items and return them
    return {
        name: PROTOCOLS_URL + "/" + protocol_name + "/" + uuid
        for name, uuid in idl_page_uuids.items()
    }


def get_idl_from_url(idl_url):
    """
    Download and parse a IDL from its link.
    """
    idl_page = requests.get(idl_url).content
    idl_soup = BeautifulSoup(idl_page, "html.parser")
    dds = idl_soup.find_all("dd")
    if len(dds) > 0:  # Found an IDL code blob
        idl_text = "\n".join(
            dd.find("pre").get_text() for dd in dds
        )  # Sometimes the code appears across multiple frames :(
        return idl_text.replace(
            "\xa0", " "
        )  # There's this stupid character which is in fact single-space


def download_protocol_idls(protocol_name, entry, output):
    """
    Entry point for each protocol: find IDLs if any, download them, write them.
    """
    num_files_saved = 0

    # 1. Get potential IDL URLs
    idl_urls = get_idl_urls(protocol_name, entry["root"])
    if not idl_urls:
        return num_files_saved

    # 2. For each URL, download it and write it to disk.
    for idl_name, idl_url in idl_urls.items():
        # Build file name
        file_name = protocol_name
        if idl_name != DEFAULT:
            # A few special cases, the general idea is to just add a _
            if idl_name == "Claims.idl":
                file_name = "ms-adts-claims.idl"
            else:
                file_name += "_" + idl_name
        else:
            file_name += ".idl"

        # Download IDL
        idl_file = get_idl_from_url(idl_url)
        if not idl_file:
            print(f"Could not fetch an IDL from {idl_url}", file=sys.stderr)
            continue

        # Write it to disk
        with open(output / file_name, "w") as f:
            try:
                f.write(idl_file)
                num_files_saved += 1
            except (TypeError, AttributeError) as e:
                print(
                    f"Failed to write a file for protocol {protocol_name}, IDL URL = {idl_url}, error = {e}",
                    file=sys.stderr,
                )

    return num_files_saved


def main():
    """
    Main entry point: download all the IDLs for all protocols list.
    """
    curdir = pathlib.Path(__file__).parent

    for i, entry in enumerate(PROTOCOLS):
        print("Polling '%s'..." % entry["name"])

        # 1. Get the list of protocols for this entry
        protocols = get_protocol_list(entry["list"])
        if "extras" in entry:
            protocols += entry["extras"]

        # 2. For each of them, try to download the IDL
        count = 0
        with tqdm(total=len(protocols)) as progress:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                # Submit all tasks
                futures = {
                    executor.submit(
                        download_protocol_idls,
                        protocol_name,
                        entry,
                        curdir / entry["folder"],
                    ): protocol_name
                    for protocol_name in protocols
                }

                # Get results as they come
                for future in concurrent.futures.as_completed(futures):
                    try:
                        count += future.result()
                        progress.update(1)
                    except Exception as ex:
                        print(ex, file=sys.stderr)

        print("Found %d IDLs for %s" % (count, entry["name"]))


if __name__ == "__main__":
    main()
