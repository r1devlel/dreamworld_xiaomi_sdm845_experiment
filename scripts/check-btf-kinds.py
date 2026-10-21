#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reject BTF blobs containing kinds the in-kernel parser does not know.

This tree's BTF_KIND_MAX is BTF_KIND_DATASEC (15).  Newer pahole versions can
emit FLOAT/ENUM64 (and tags), which the kernel rejects while resolving
attach_btf_id.  Catch that at build time instead of on the device.
"""
import struct
import sys

BTF_MAGIC = 0xEB9F
BTF_KIND_MAX = 15  # BTF_KIND_DATASEC
KIND_NAMES = {
    16: "FLOAT",
    17: "DECL_TAG",
    18: "TYPE_TAG",
    19: "ENUM64",
}


def main(path):
    data = open(path, "rb").read()
    if len(data) < 24:
        raise SystemExit(f"{path}: too short for a BTF header")

    magic, version, _flags, hdr_len, type_off, type_len, _str_off, _str_len = \
        struct.unpack_from("<HBBIIIII", data, 0)
    if magic != BTF_MAGIC or version != 1:
        raise SystemExit(f"{path}: bad BTF magic/version {magic:#x}/{version}")

    pos = hdr_len + type_off
    end = pos + type_len
    if end > len(data):
        raise SystemExit(f"{path}: type section is out of bounds")

    types = 0
    while pos < end:
        if pos + 12 > end:
            raise SystemExit(f"{path}: truncated btf_type at offset {pos}")
        _name_off, info, _size_type = struct.unpack_from("<III", data, pos)
        pos += 12
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        types += 1

        if kind > BTF_KIND_MAX:
            name = KIND_NAMES.get(kind, "UNKNOWN")
            raise SystemExit(
                f"{path}: type {types} uses unsupported BTF kind "
                f"{kind} ({name}), max is {BTF_KIND_MAX}")

        # Skip the kind-specific payload.
        if kind == 1:            # BTF_KIND_INT
            pos += 4
        elif kind == 3:          # BTF_KIND_ARRAY
            pos += 12
        elif kind in (4, 5):     # BTF_KIND_STRUCT / UNION
            pos += 12 * vlen
        elif kind == 6:          # BTF_KIND_ENUM
            pos += 8 * vlen
        elif kind == 13:         # BTF_KIND_FUNC_PROTO
            pos += 8 * vlen
        elif kind == 14:         # BTF_KIND_VAR
            pos += 4
        elif kind == 15:         # BTF_KIND_DATASEC
            pos += 12 * vlen
        # PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT and FUNC have no
        # extra payload in this BTF version.

    print(f"{path}: {types} types, all kinds <= {BTF_KIND_MAX}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <btf-file>")
    main(sys.argv[1])
