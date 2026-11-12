#!/usr/bin/env python3
# Copyright 2026 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Structured seed generator for ultrahdr_container_fuzzer.

Emits structurally-valid ISOBMFF skeletons of Ultra HDR HEIF/AVIF files
(brand 'tmap', meta box, base + gain map image items, 'tmap' item carrying an
ISO 21496-1 gain map metadata blob, 'dimg' reference from tmap to
[primary, gainmap]) so that mutation-based fuzzing can reach libultrahdr's
container parsing paths. Random bytes cannot produce this hierarchy, which is
why the corpus is generated here (run from ossfuzz.sh) instead of relied upon
from mutation alone.

Usage: generate_container_seeds.py <output-dir>
"""

import os
import struct
import sys


def box(btype: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + btype + payload


def fullbox(btype: bytes, version: int, flags: int, payload: bytes) -> bytes:
    return box(btype, struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload)


def fourcc(s: str) -> bytes:
    return s.encode("ascii")


def iso21496_metadata(multichannel: bool, use_base_cg: bool, backward: bool,
                      common_denominator: bool) -> bytes:
    """ISO/IEC 21496-1 gain map metadata blob, layout per
    uhdr_gainmap_metadata_frac::decodeGainmapMetadata()."""
    channels = 3 if multichannel else 1
    flags = ((1 << 0) if multichannel else 0) | ((1 << 1) if use_base_cg else 0) \
        | ((1 << 2) if backward else 0) | ((1 << 3) if common_denominator else 0)
    out = struct.pack(">HHB", 0, 0, flags)  # min_version, writer_version, flags
    if common_denominator:
        out += struct.pack(">I", 1 << 8)  # common denominator
        out += struct.pack(">I", 1 << 8)  # base hdr headroom N
        out += struct.pack(">I", 16 << 8)  # alternate hdr headroom N
        for _ in range(channels):
            out += struct.pack(">iI", -1 << 8, 1 << 8)  # gain map min N/D
            out += struct.pack(">iI", 1 << 12, 1 << 8)  # gain map max N/D
            out += struct.pack(">iI", 1 << 8, 1 << 8)  # gamma N/D
            out += struct.pack(">iI", 1 << 8, 1 << 8)  # base offset N/D
            out += struct.pack(">iI", 0, 1 << 8)  # alternate offset N/D
    else:
        out += struct.pack(">I", 1 << 8) + struct.pack(">I", 1 << 8)  # base headroom N/D
        out += struct.pack(">I", 16 << 8) + struct.pack(">I", 1 << 8)  # alt headroom N/D
        for _ in range(channels):
            out += struct.pack(">iI", -1 << 8, 1 << 8)
            out += struct.pack(">iI", 1 << 12, 1 << 8)
            out += struct.pack(">iI", 1 << 8, 1 << 8)
            out += struct.pack(">iI", 1 << 8, 1 << 8)
            out += struct.pack(">iI", 0, 1 << 8)
    return out


def nclx_colr(primaries: int, transfer: int, matrix: int, full_range: bool) -> bytes:
    return box(b"colr", fourcc("nclx") + struct.pack(">HHHB", primaries, transfer,
                                                     matrix, 0x80 if full_range else 0))


def av1c() -> bytes:
    # minimal AV1DecoderConfigurationRecord (marker=1, version=1, seq_profile=0,
    # seq_level_idx=0, 4:2:0 8-bit)
    return box(b"av1C", bytes([0x81, 0x00, 0x0C, 0x00]))


def hvcc() -> bytes:
    # minimal HEVCDecoderConfigurationRecord (configurationVersion=1, no arrays)
    return box(b"hvcC", bytes([0x01, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0xF0]))


def build_container(codec: str, multichannel: bool, use_base_cg: bool, backward: bool,
                    common_denominator: bool, with_gainmap: bool) -> bytes:
    item_type = fourcc("av01") if codec == "avif" else fourcc("hvc1")
    major = fourcc("avif") if codec == "avif" else fourcc("heic")
    compat = [fourcc("mif1"), fourcc("miaf"), major, fourcc("tmap")]
    ftyp = box(b"ftyp", major + struct.pack(">I", 0) + b"".join(compat))

    codestream_a = (b"\x12\x00\x0a\x0a\x00\x00\x00\x24\xaa\xfb\x00\x00\x00\x3d\x13\x00"
                    + bytes(64))
    codestream_b = (b"\x12\x00\x0a\x0a\x00\x00\x00\x24\xaa\xfc\x00\x00\x00\x3d\x13\x00"
                    + bytes(48))
    metadata = iso21496_metadata(multichannel, use_base_cg, backward, common_denominator)

    mdat_payload = codestream_a + (codestream_b if with_gainmap else b"") + metadata
    off_a = 0
    off_b = len(codestream_a)
    off_m = off_b + (len(codestream_b) if with_gainmap else 0)

    # ---- properties (ipco) ----
    ispe = fullbox(b"ispe", 0, 0, struct.pack(">II", 64, 64))
    colr_base = nclx_colr(1, 13, 5, True)  # BT.709 / sRGB / BT.601, full range
    colr_tmap = nclx_colr(9, 16, 9, False)  # BT.2100 PQ, limited range
    codec_prop = av1c() if codec == "avif" else hvcc()

    ipco = box(b"ipco", ispe + codec_prop + colr_base + colr_tmap)

    def assoc(item_id: int, indices):
        payload = struct.pack(">H", item_id) + bytes([len(indices)])
        payload += bytes([(1 << 7) | i for i in indices])
        return payload

    # ipma property indices are 1-based
    ipma_entries = [assoc(1, [1, 2, 3])]
    if with_gainmap:
        ipma_entries.append(assoc(2, [1, 2, 3]))
    ipma_entries.append(assoc(3, [1, 4]))
    ipma = fullbox(b"ipma", 0, 0,
                   struct.pack(">I", len(ipma_entries)) + b"".join(ipma_entries))
    iprp = box(b"iprp", ipco + ipma)

    # ---- item info ----
    def infe(item_id: int, itype: bytes, name: bytes) -> bytes:
        return fullbox(b"infe", 2, 0,
                       struct.pack(">HH", item_id, 0) + itype + name + b"\x00")

    entries = [infe(1, item_type, b"Color")]
    if with_gainmap:
        entries.append(infe(2, item_type, b"GMap"))
    entries.append(infe(3, fourcc("tmap"), b"GMapData"))
    iinf = fullbox(b"iinf", 0, 0, struct.pack(">H", len(entries)) + b"".join(entries))

    # ---- item location (iloc), offset/length size = 4 bytes, no base offset ----
    def iloc_entry(item_id: int, offset: int, length: int) -> bytes:
        return struct.pack(">HHH", item_id, 0, 1) + struct.pack(">II", offset, length)

    locs = [iloc_entry(1, off_a, len(codestream_a))]
    if with_gainmap:
        locs.append(iloc_entry(2, off_b, len(codestream_b)))
    locs.append(iloc_entry(3, off_m, len(metadata)))
    iloc = fullbox(b"iloc", 0, 0,
                   bytes([0x44, 0x00]) + struct.pack(">H", len(locs)) + b"".join(locs))


    hdlr = fullbox(b"hdlr", 0, 0,
                   struct.pack(">I", 0) + fourcc("pict") + struct.pack(">III", 0, 0, 0) + b"\x00")
    pitm = fullbox(b"pitm", 0, 0, struct.pack(">H", 1))

    meta_payload = hdlr + pitm + iinf
    if with_gainmap:
        # iref: tmap item (3) --dimg--> [primary (1), gain map (2)]
        iref = fullbox(b"iref", 0, 0, struct.pack(">HHHH", 3, 2, 1, 2))
        meta_payload += iref
    meta_payload += iprp + iloc
    meta = fullbox(b"meta", 0, 0, meta_payload)

    mdat = box(b"mdat", mdat_payload)
    return ftyp + meta + mdat


def main() -> None:
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out_dir, exist_ok=True)

    variants = [
        ("avif_mono", dict(codec="avif", multichannel=False, use_base_cg=False,
                           backward=False, common_denominator=False, with_gainmap=True)),
        ("avif_multi", dict(codec="avif", multichannel=True, use_base_cg=False,
                            backward=False, common_denominator=False, with_gainmap=True)),
        ("avif_common_denom", dict(codec="avif", multichannel=False, use_base_cg=False,
                                   backward=False, common_denominator=True, with_gainmap=True)),
        ("avif_use_base_cg", dict(codec="avif", multichannel=False, use_base_cg=True,
                                  backward=False, common_denominator=False, with_gainmap=True)),
        ("avif_backward", dict(codec="avif", multichannel=False, use_base_cg=False,
                               backward=True, common_denominator=False, with_gainmap=True)),
        ("heic_mono", dict(codec="heic", multichannel=False, use_base_cg=False,
                           backward=False, common_denominator=False, with_gainmap=True)),
        ("heic_multi", dict(codec="heic", multichannel=True, use_base_cg=False,
                            backward=False, common_denominator=False, with_gainmap=True)),
        ("heic_common_denom", dict(codec="heic", multichannel=False, use_base_cg=True,
                                   backward=False, common_denominator=True, with_gainmap=True)),
        ("avif_plain_no_tmap", dict(codec="avif", multichannel=False, use_base_cg=False,
                                    backward=False, common_denominator=False,
                                    with_gainmap=False)),
        ("heic_plain_no_tmap", dict(codec="heic", multichannel=False, use_base_cg=False,
                                    backward=False, common_denominator=False,
                                    with_gainmap=False)),
    ]

    for name, kwargs in variants:
        data = build_container(**kwargs)
        with open(os.path.join(out_dir, f"ultrahdr_container_{name}.uhdr"), "wb") as fh:
            fh.write(data)
    print(f"wrote {len(variants)} seeds to {out_dir}")


if __name__ == "__main__":
    main()

