# UltraHDR API Changes (v1.5.0 to Potential v2.0.0)

This document details the architectural and API changes planned for the transition from **UltraHDR v1.5.0** (and v1.5.1) to **Potential v2.0.0**, focusing on multi-format container support (HEIF & AVIF), C++ class hierarchy reorganization, C-API extensions, and `libheif` integration.

---

## 1. Executive Summary

| Feature / Aspect | UltraHDR v1.5.0 / v1.5.1 | Potential UltraHDR v2.0.0 |
| :--- | :--- | :--- |
| **Supported Formats** | JPEG (`.jpg`, `.jpeg`) only | JPEG, HEIF/HEIC (`.heic`), and AVIF (`.avif`) |
| **C-API Codec Enums** | `UHDR_CODEC_HEIF` & `UHDR_CODEC_AVIF` reserved | `UHDR_CODEC_HEIF` & `UHDR_CODEC_AVIF` fully implemented |
| **C++ Class Architecture** | Monolithic `JpegR` class for all operations | Refactored `UltraHdr` base class with `JpegR`, `HeifUltraHdr`, and `AvifUltraHdr` subclasses |
| **Decoder Transparency** | Probes JPEG markers only | Format-agnostic probe and decode across JPEG, HEIF, and AVIF |
| **Underlying HEIF Engine** | None | `libheif` with ISO 21496-1 tone map (`tmap`) item support |
| **Conditional Build** | N/A | `UHDR_ENABLE_HEIF` compile-time flag (zero overhead when disabled) |

---

## 2. C-API (`ultrahdr_api.h`) Updates

The public C-ABI interface remains backwards-compatible, while activating multi-format encoding and decoding.

### 2.1. Encoder Format Selection
Callers can configure the target output container using `uhdr_enc_set_output_format()`:

```c
// JPEG Output (Default / Existing v1.x behavior)
uhdr_enc_set_output_format(enc_handle, UHDR_CODEC_JPG);

// HEIF / HEIC Output (HEVC base + Gain map in ISO BMFF container)
uhdr_enc_set_output_format(enc_handle, UHDR_CODEC_HEIF);

// AVIF Output (AV1 base + Gain map in ISO BMFF container)
uhdr_enc_set_output_format(enc_handle, UHDR_CODEC_AVIF);
```

### 2.2. Supported Encode Intent Modes for HEIF/AVIF
* **Encode API-0 (HDR Raw Intent)**:
  * Input: Raw HDR image (`uhdr_enc_set_raw_image(..., UHDR_HDR_IMG)`).
  * Automatically tone-maps to SDR base, computes gain map, compresses both via `libheif`, and encapsulates metadata.
* **Encode API-1 (HDR + SDR Raw Intents)**:
  * Input: Raw HDR image + Raw SDR image.
  * Generates gain map from the difference, compresses SDR and gain map into HEIF/AVIF container.
* **Encode API-2 / 3 / 4 (Pre-compressed Intents)**:
  * Pre-compressed JPEG intents are specific to JPEG workflows. For HEIF/AVIF, pre-compressed intent transcoding is not supported and returns `UHDR_CODEC_UNSUPPORTED_FEATURE`.

### 2.3. Unified Transparent Decoding
The decoder APIs (`uhdr_dec_probe()` and `uhdr_decode()`) automatically detect container type from the stream header:
* Checks magic bytes: JPEG markers (`0xFF 0xD8 0xFF`) vs ISO BMFF `ftyp` box (`heic`, `avif`, `mif1`, etc.).
* Transparently routes decoding to `JpegR`, `HeifUltraHdr`, or `AvifUltraHdr`.
* Extracts primary image, gain map auxiliary track, ISO 21496-1 metadata, and color profiles seamlessly into the destination buffer.

### 2.4. Optional Native 10-Bit AVIF Base Images
`uhdr_enc_set_max_base_image_bit_depth()` lets an encoder opt into a maximum AVIF base-image
depth of 10 bits. The default remains 8 bits for compatibility. The 10-bit route applies only to
AVIF Encode API-0 with P010 or RGBA1010102 HDR input, and to API-1 with RGBA8888 SDR input. For
API-1, RGBA8888 is converted directly to a 10-bit YCbCr 4:4:4 base instead of passing through an
8-bit YCbCr intermediate. That conversion avoids another precision loss, but cannot restore detail
already discarded before the encoder receives the SDR image. Other API-1 formats and output codecs
keep their existing behavior.

Native 10-bit bases can improve base-layer and reconstructed HDR fidelity, but may increase encode
memory, file size, and decoder requirements. If the active AV1 encoder cannot produce the requested
10-bit base, encoding returns its error instead of silently falling back to 8 bits. The gain map
remains 8-bit. These changes do not alter decoder behavior.

---

## 3. C++ Class Hierarchy Reorganization

To support multiple container formats without duplicating gain map math, the monolithic `JpegR` class has been modularized:

```
                  ┌────────────────────────┐
                  │        UltraHdr        │
                  │   (ultrahdrcommon.h)   │
                  └───────────┬────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
   ┌───────────┐      ┌───────────────┐    ┌───────────────┐
   │   JpegR   │      │ HeifUltraHdr  │    │ AvifUltraHdr  │
   │ (jpegr.h) │      │(heifultrahdr.h│    │(avifultrahdr.h│
   └───────────┘      └───────────────┘    └───────────────┘
```

### 3.1. `UltraHdr` Base Class (`<ultrahdr/ultrahdrcommon.h>`)
Contains all shared, format-independent algorithms:
* Gain map generation (`generateGainMap()`).
* Gain map application and tone mapping math (`applyGainMap()`).
* Color space transformations, primaries/matrix conversions, and ICC profile handling.
* Metadata encoding and decoding (`uhdr_gainmap_metadata_ext_t`).

### 3.2. Format-Specific Derived Classes
* **`JpegR`** (`<ultrahdr/jpegr.h>`):
  * Handles JPEG MPF (Multi-Picture Format), EXIF, and XMP marker parsing and packing.
  * Methods: `encodeJpegR()`, `decodeJpegR()`.
* **`HeifUltraHdr`** (`<ultrahdr/heifultrahdr.h>`):
  * Handles HEVC bitstream encoding/decoding via `libheif`.
  * Methods: `encodeHeicUltraHdr()`, `decodeHeicUltraHdr()`.
* **`AvifUltraHdr`** (`<ultrahdr/avifultrahdr.h>`):
  * Handles AV1 bitstream encoding/decoding via `libheif`.
  * Methods: `encodeAvifUltraHdr()`, `decodeAvifUltraHdr()`.

---

## 4. `libheif` & ISO 21496-1 Container Encapsulation

Under v2.0.0, HEIF and AVIF Ultra HDR images adhere to ISO/IEC 23008-12 and ISO 21496-1:
1. **Derived Tone Map Item (`tmap`)**: The gain map metadata is stored as an uncompressed `tmap` item with type `fourcc("tmap")`.
2. **Item References (`dimg`)**: The `tmap` item references the base image (index 0) and the gain map image (index 1) via a `dimg` (derived image) reference box.
3. **Alternate Entity Grouping (`altr`)**: An `altr` box groups the tone-mapped item with the base image to signal alternative presentations.
4. **Color Profiles**: NCLX (`colr`) and ICC profile boxes are attached directly to the derived item and gain map image item.

---

## 5. Build System & Portability

### 5.1. Compile-Time Guard (`UHDR_ENABLE_HEIF`)
* When **enabled**: Links `libheif`, enabling HEIC and AVIF support.
* When **disabled**: `libultrahdr` builds as a standalone, zero-dependency JPEG-only library.

### 5.2. Build Configurations
* **Google3 (`BUILD`)**: Linked via `//third_party/libheif:libheif` with `UHDR_ENABLE_HEIF`.
* **Android (`Android.bp`)**: Standard AOSP build configuration (kept untouched on the staging branch).
* **Upstream CMake (`CMakeLists.txt`)**: Enabled via `-DUHDR_ENABLE_HEIF=ON` using `find_package(libheif)` or `pkg-config`. Fully compatible with Linux and macOS (Apple Silicon & Intel).
