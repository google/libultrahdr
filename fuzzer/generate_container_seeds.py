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

Each seed ends with a trailing 0x00 mode byte so the harness selects decode
mode without truncating the container payload (FuzzedDataProvider consumes
integrals from the end of the buffer).

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
    uhdr_gainmap_metadata_frac::decodeGainmapMetadata().

    Flag bits (see gainmapmetadata.h):
      bit 7 = multichannel, bit 6 = use base colour space,
      bit 2 = backward, bit 3 = common denominator (legacy layout).
    """
    channels = 3 if multichannel else 1
    flags = ((1 << 7) if multichannel else 0) | ((1 << 6) if use_base_cg else 0) \
        | ((1 << 2) if backward else 0) | ((1 << 3) if common_denominator else 0)
    out = struct.pack(">HHB", 0, 0, flags)  # min_version, writer_version, flags
    if common_denominator:
        # Legacy layout: one common D, then numerators only.
        out += struct.pack(">I", 1 << 8)  # common denominator
        out += struct.pack(">I", 1 << 8)  # base hdr headroom N
        out += struct.pack(">I", 16 << 8)  # alternate hdr headroom N
        for _ in range(channels):
            out += struct.pack(">i", -1 << 8)  # gain map min N
            out += struct.pack(">i", 1 << 12)  # gain map max N
            out += struct.pack(">I", 1 << 8)  # gamma N
            out += struct.pack(">i", 1 << 8)  # base offset N
            out += struct.pack(">i", 0)  # alternate offset N
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


def build_iloc(locs: list) -> bytes:
    # offset_size=4, length_size=4, base_offset_size=0, index_size=0
    return fullbox(b"iloc", 0, 0,
                   bytes([0x44, 0x00]) + struct.pack(">H", len(locs)) + b"".join(locs))


def iloc_entry(item_id: int, offset: int, length: int) -> bytes:
    # construction_method=0 (file), data_reference_index=0, extent_count=1
    return struct.pack(">HHH", item_id, 0, 1) + struct.pack(">II", offset, length)


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
    rel_a = 0
    rel_b = len(codestream_a)
    rel_m = rel_b + (len(codestream_b) if with_gainmap else 0)

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

    hdlr = fullbox(b"hdlr", 0, 0,
                   struct.pack(">I", 0) + fourcc("pict") + struct.pack(">III", 0, 0, 0) + b"\x00")
    pitm = fullbox(b"pitm", 0, 0, struct.pack(">H", 1))

    iref = b""
    if with_gainmap:
        # iref contains a SingleItemTypeReferenceBox 'dimg':
        # tmap item (3) --dimg--> [primary (1), gain map (2)]
        dimg = box(b"dimg", struct.pack(">HHHH", 3, 2, 1, 2))
        iref = fullbox(b"iref", 0, 0, dimg)

    # Build meta once with placeholder file offsets (iloc size is fixed), then
    # rewrite iloc with absolute offsets into the file (mdat payload start).
    n_items = 2 + (1 if with_gainmap else 0)
    placeholder_locs = [iloc_entry(i + 1, 0, 1) for i in range(n_items)]
    meta_prefix = hdlr + pitm + iinf + iref + iprp
    meta_with_placeholder = fullbox(b"meta", 0, 0,
                                    meta_prefix + build_iloc(placeholder_locs))
    mdat_data_off = len(ftyp) + len(meta_with_placeholder) + 8

    locs = [iloc_entry(1, mdat_data_off + rel_a, len(codestream_a))]
    if with_gainmap:
        locs.append(iloc_entry(2, mdat_data_off + rel_b, len(codestream_b)))
    locs.append(iloc_entry(3, mdat_data_off + rel_m, len(metadata)))
    meta = fullbox(b"meta", 0, 0, meta_prefix + build_iloc(locs))
    assert len(meta) == len(meta_with_placeholder)

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
        # Trailing 0 selects decode mode in the harness without truncating the
        # ISOBMFF payload (FDP reads integrals from the end).
        data = build_container(**kwargs) + b"\x00"
        with open(os.path.join(out_dir, f"ultrahdr_container_{name}.uhdr"), "wb") as fh:
            fh.write(data)
    print(f"wrote {len(variants)} seeds to {out_dir}")


if __name__ == "__main__":
    main()
