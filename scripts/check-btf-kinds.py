#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reject BTF blobs the in-kernel parser cannot handle.

This tree's BTF_KIND_MAX is BTF_KIND_DATASEC (15).  Newer pahole versions can
emit FLOAT/ENUM64 (and tags), which the kernel rejects while resolving
attach_btf_id.  The parser also has BTF_MAX_TYPE/BTF_MAX_NAME_OFFSET limits;
a modern vmlinux BTF has far more than 64k types and a multi-megabyte string
section, so the 4.9-era limits reject an otherwise valid blob.  Catch both
problems at build time instead of on the device.
"""
import struct
import sys

BTF_MAGIC = 0xEB9F
BTF_KIND_MAX = 15  # BTF_KIND_DATASEC
# These must match include/uapi/linux/btf.h.  5.15-sized limits are required
# for the embedded vmlinux BTF (currently >160k types and a ~3.6MB string
# section).
BTF_MAX_TYPE = 0x000FFFFF
BTF_MAX_NAME_OFFSET = 0x00FFFFFF
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

    magic, version, _flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", data, 0)
    if magic != BTF_MAGIC or version != 1:
        raise SystemExit(f"{path}: bad BTF magic/version {magic:#x}/{version}")

    if str_len == 0 or str_len - 1 > BTF_MAX_NAME_OFFSET:
        raise SystemExit(
            f"{path}: string section length {str_len} exceeds "
            f"BTF_MAX_NAME_OFFSET {BTF_MAX_NAME_OFFSET:#x}")

    str_start = hdr_len + str_off
    if str_start + str_len > len(data):
        raise SystemExit(f"{path}: string section is out of bounds")

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

    if types > BTF_MAX_TYPE:
        raise SystemExit(
            f"{path}: {types} types exceeds BTF_MAX_TYPE {BTF_MAX_TYPE:#x}")

    print(f"{path}: {types} types (<= {BTF_MAX_TYPE}), "
          f"str_len {str_len} (<= {BTF_MAX_NAME_OFFSET + 1}), "
          f"all kinds <= {BTF_KIND_MAX}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <btf-file>")
    main(sys.argv[1])
