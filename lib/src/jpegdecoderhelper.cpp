/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <setjmp.h>

#include <cmath>
#include <cstring>

#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/ultrahdr.h"
#include "ultrahdr/jpegdecoderhelper.h"

using namespace std;

namespace ultrahdr {

static const uint32_t kAPP0Marker = JPEG_APP0;      // JFIF
static const uint32_t kAPP1Marker = JPEG_APP0 + 1;  // EXIF, XMP
static const uint32_t kAPP2Marker = JPEG_APP0 + 2;  // ICC, ISO Metadata

static constexpr uint8_t kICCSig[] = {
    'I', 'C', 'C', '_', 'P', 'R', 'O', 'F', 'I', 'L', 'E', '\0',
};

static constexpr uint8_t kXmpNameSpace[] = {
    'h', 't', 't', 'p', ':', '/', '/', 'n', 's', '.', 'a', 'd', 'o', 'b', 'e',
    '.', 'c', 'o', 'm', '/', 'x', 'a', 'p', '/', '1', '.', '0', '/', '\0',
};

static constexpr uint8_t kExifIdCode[] = {
    'E', 'x', 'i', 'f', '\0', '\0',
};

static constexpr uint8_t kIsoMetadataNameSpace[] = {
    'u', 'r', 'n', ':', 'i', 's', 'o', ':', 's', 't', 'd', ':', 'i', 's',
    'o', ':', 't', 's', ':', '2', '1', '4', '9', '6', ':', '-', '1', '\0',
};

/*!\brief module for managing input */
struct jpeg_source_mgr_impl : jpeg_source_mgr {
  jpeg_source_mgr_impl(const uint8_t* ptr, int len);
  ~jpeg_source_mgr_impl() = default;

  const uint8_t* mBufferPtr;
  size_t mBufferLength;
};

/*!\brief module for managing error */
struct jpeg_error_mgr_impl : jpeg_error_mgr {
  jmp_buf setjmp_buffer;
};

static void jpegr_init_source(j_decompress_ptr cinfo) {
  jpeg_source_mgr_impl* src = static_cast<jpeg_source_mgr_impl*>(cinfo->src);
  src->next_input_byte = static_cast<const JOCTET*>(src->mBufferPtr);
  src->bytes_in_buffer = src->mBufferLength;
}

static boolean jpegr_fill_input_buffer(j_decompress_ptr /* cinfo */) {
  ALOGE("%s : should not reach here", __func__);
  return FALSE;
}

static void jpegr_skip_input_data(j_decompress_ptr cinfo, long num_bytes) {
  jpeg_source_mgr_impl* src = static_cast<jpeg_source_mgr_impl*>(cinfo->src);

  if (num_bytes > static_cast<long>(src->bytes_in_buffer)) {
    ALOGE("jpegr_skip_input_data - num_bytes > (long)src->bytes_in_buffer");
  } else {
    src->next_input_byte += num_bytes;
    src->bytes_in_buffer -= num_bytes;
  }
}

static void jpegr_term_source(j_decompress_ptr /*cinfo*/) {}

jpeg_source_mgr_impl::jpeg_source_mgr_impl(const uint8_t* ptr, int len)
    : mBufferPtr(ptr), mBufferLength(len) {
  init_source = jpegr_init_source;
  fill_input_buffer = jpegr_fill_input_buffer;
  skip_input_data = jpegr_skip_input_data;
  resync_to_restart = jpeg_resync_to_restart;
  term_source = jpegr_term_source;
}

static void jpegrerror_exit(j_common_ptr cinfo) {
  jpeg_error_mgr_impl* err = reinterpret_cast<jpeg_error_mgr_impl*>(cinfo->err);
  longjmp(err->setjmp_buffer, 1);
}

static void output_message(j_common_ptr cinfo) {
  char buffer[JMSG_LENGTH_MAX];

  (*cinfo->err->format_message)(cinfo, buffer);
  ALOGE("%s\n", buffer);
}

static void jpeg_extract_marker_payload(const j_decompress_ptr cinfo, const uint32_t marker_code,
                                        const uint8_t* marker_fourcc_code,
                                        const uint32_t fourcc_length,
                                        std::vector<JOCTET>& destination,
                                        int& markerPayloadOffsetRelativeToSourceBuffer) {
  size_t pos = 2; /* position after reading SOI marker (0xffd8) */
  markerPayloadOffsetRelativeToSourceBuffer = -1;

  for (jpeg_marker_struct* marker = cinfo->marker_list; marker; marker = marker->next) {
    pos += 4; /* position after reading next marker and its size (0xFFXX, [SIZE = 2 bytes]) */

    if (marker->marker == marker_code && marker->data_length > fourcc_length &&
        !memcmp(marker->data, marker_fourcc_code, fourcc_length)) {
      destination.resize(marker->data_length);
      memcpy(static_cast<void*>(destination.data()), marker->data, marker->data_length);
      markerPayloadOffsetRelativeToSourceBuffer = pos;
      return;
    }
    pos += marker->original_length; /* position after marker's payload */
  }
}

static uhdr_img_fmt_t getOutputSamplingFormat(const j_decompress_ptr cinfo) {
  if (cinfo->num_components == 1)
    return UHDR_IMG_FMT_8bppYCbCr400;
  else {
    int a = cinfo->max_h_samp_factor / cinfo->comp_info[1].h_samp_factor;
    int b = cinfo->max_v_samp_factor / cinfo->comp_info[1].v_samp_factor;
    if (a == 1 && b == 1)
      return UHDR_IMG_FMT_24bppYCbCr444;
    else if (a == 1 && b == 2)
      return UHDR_IMG_FMT_16bppYCbCr440;
    else if (a == 2 && b == 1)
      return UHDR_IMG_FMT_16bppYCbCr422;
    else if (a == 2 && b == 2)
      return UHDR_IMG_FMT_12bppYCbCr420;
    else if (a == 4 && b == 1)
      return UHDR_IMG_FMT_12bppYCbCr411;
    else if (a == 4 && b == 2)
      return UHDR_IMG_FMT_10bppYCbCr410;
  }
  return UHDR_IMG_FMT_UNSPECIFIED;
}

bool JpegDecoderHelper::decompressImage(const void* image, int length, decode_mode_t mode) {
  if (image == nullptr) {
    ALOGE("received nullptr for compressed image data");
    return false;
  }
  if (length <= 0) {
    ALOGE("received bad compressed image size %d", length);
    return false;
  }

  // reset context
  mResultBuffer.clear();
  mXMPBuffer.clear();
  mEXIFBuffer.clear();
  mICCBuffer.clear();
  mIsoMetadataBuffer.clear();
  mOutFormat = UHDR_IMG_FMT_UNSPECIFIED;
  for (int i = 0; i < kMaxNumComponents; i++) {
    mPlanesMCURow[i].reset();
    mPlaneWidth[i] = 0;
    mPlaneHeight[i] = 0;
  }
  mExifPayLoadOffset = -1;

  return decode(image, length, mode);
}

bool JpegDecoderHelper::decode(const void* image, int length, decode_mode_t mode) {
  jpeg_source_mgr_impl mgr(static_cast<const uint8_t*>(image), length);
  jpeg_decompress_struct cinfo;
  jpeg_error_mgr_impl myerr;

  cinfo.err = jpeg_std_error(&myerr);
  myerr.error_exit = jpegrerror_exit;
  myerr.output_message = output_message;

  if (0 == setjmp(myerr.setjmp_buffer)) {
    jpeg_create_decompress(&cinfo);
    cinfo.src = &mgr;
    jpeg_save_markers(&cinfo, kAPP0Marker, 0xFFFF);
    jpeg_save_markers(&cinfo, kAPP1Marker, 0xFFFF);
    jpeg_save_markers(&cinfo, kAPP2Marker, 0xFFFF);
    int ret_val = jpeg_read_header(&cinfo, TRUE /* require an image to be present */);
    if (JPEG_HEADER_OK != ret_val) {
      ALOGE("jpeg_read_header(...) returned %d, expected %d", ret_val, JPEG_HEADER_OK);
      jpeg_destroy_decompress(&cinfo);
      return false;
    }
    int payloadOffset = -1;
    jpeg_extract_marker_payload(&cinfo, kAPP1Marker, kXmpNameSpace,
                                sizeof kXmpNameSpace / sizeof kXmpNameSpace[0], mXMPBuffer,
                                payloadOffset);
    jpeg_extract_marker_payload(&cinfo, kAPP1Marker, kExifIdCode,
                                sizeof kExifIdCode / sizeof kExifIdCode[0], mEXIFBuffer,
                                mExifPayLoadOffset);
    jpeg_extract_marker_payload(&cinfo, kAPP2Marker, kICCSig, sizeof kICCSig / sizeof kICCSig[0],
                                mICCBuffer, payloadOffset);
    jpeg_extract_marker_payload(&cinfo, kAPP2Marker, kIsoMetadataNameSpace,
                                sizeof kIsoMetadataNameSpace / sizeof kIsoMetadataNameSpace[0],
                                mIsoMetadataBuffer, payloadOffset);

    if (cinfo.image_width < 1 || cinfo.image_height < 1) {
      ALOGE("received bad image width or height, wd = %d, ht = %d. wd and height shall be >= 1",
            cinfo.image_width, cinfo.image_height);
      jpeg_destroy_decompress(&cinfo);
      return false;
    }
    if (cinfo.image_width > kMaxWidth || cinfo.image_height > kMaxHeight) {
      ALOGE(
          "max width, max supported by library are %d, %d respectively. Current image width and "
          "height are %d, %d. Recompile library with updated max supported dimensions to proceed",
          kMaxWidth, kMaxHeight, cinfo.image_width, cinfo.image_height);
      jpeg_destroy_decompress(&cinfo);
      return false;
    }
    if (cinfo.num_components != 1 && cinfo.num_components != 3) {
      ALOGE(
          "ultrahdr primary image and supplimentary images are images encoded with 1 component "
          "(grayscale) or 3 components (YCbCr / RGB). Unrecognized number of components %d",
          cinfo.num_components);
      jpeg_destroy_decompress(&cinfo);
      return false;
    }

    for (int i = 0, product = 0; i < cinfo.num_components; i++) {
      if (cinfo.comp_info[i].h_samp_factor < 1 || cinfo.comp_info[i].h_samp_factor > 4) {
        ALOGE(
            "received bad horizontal sampling factor for component index %d, sample factor h = %d, "
            "this is expected to be with in range [1-4]",
            i, cinfo.comp_info[i].h_samp_factor);
        jpeg_destroy_decompress(&cinfo);
        return false;
      }
      if (cinfo.comp_info[i].v_samp_factor < 1 || cinfo.comp_info[i].v_samp_factor > 4) {
        ALOGE(
            "received bad vertical sampling factor for component index %d, sample factor v = %d, "
            "this is expected to be with in range [1-4]",
            i, cinfo.comp_info[i].v_samp_factor);
        jpeg_destroy_decompress(&cinfo);
        return false;
      }
      product += cinfo.comp_info[i].h_samp_factor * cinfo.comp_info[i].v_samp_factor;
      if (product > 10) {
        ALOGE(
            "received bad sampling factors for components, sum of product of h_samp_factor, "
            "v_samp_factor across all components exceeds 10");
        jpeg_destroy_decompress(&cinfo);
        return false;
      }
    }

    for (int i = 0; i < cinfo.num_components; i++) {
      mPlaneWidth[i] = std::ceil(((float)cinfo.image_width * cinfo.comp_info[i].h_samp_factor) /
                                 cinfo.max_h_samp_factor);
      mPlaneHeight[i] = std::ceil(((float)cinfo.image_height * cinfo.comp_info[i].v_samp_factor) /
                                  cinfo.max_v_samp_factor);
    }

    if (cinfo.num_components == 3 &&
        (mPlaneWidth[1] != mPlaneWidth[2] || mPlaneHeight[1] != mPlaneHeight[2])) {
      ALOGE(
          "cb, cr planes are not sampled identically. cb width %d, cb height %d, cr width %d, cr "
          "height %d",
          (int)mPlaneWidth[1], (int)mPlaneWidth[2], (int)mPlaneHeight[1], (int)mPlaneHeight[2]);
      jpeg_destroy_decompress(&cinfo);
      return false;
    }

    if (PARSE_STREAM == mode) {
      jpeg_destroy_decompress(&cinfo);
      return true;
    }

    if (DECODE_STREAM == mode) {
      mode = cinfo.num_components == 1 ? DECODE_TO_YCBCR_CS : DECODE_TO_RGB_CS;
    }

    if (DECODE_TO_RGB_CS == mode) {
      if (cinfo.jpeg_color_space != JCS_YCbCr && cinfo.jpeg_color_space != JCS_RGB) {
        ALOGE("expected input color space to be JCS_YCbCr or JCS_RGB but got %d",
              cinfo.jpeg_color_space);
        jpeg_destroy_decompress(&cinfo);
        return false;
      }
#ifdef JCS_ALPHA_EXTENSIONS
      mResultBuffer.resize(cinfo.image_width * cinfo.image_height * 4);
      cinfo.out_color_space = JCS_EXT_RGBA;
#else
      mResultBuffer.resize(cinfo.image_width * cinfo.image_height * 3);
      cinfo.out_color_space = JCS_RGB;
#endif
    } else if (DECODE_TO_YCBCR_CS == mode) {
      if (cinfo.jpeg_color_space != JCS_YCbCr && cinfo.jpeg_color_space != JCS_GRAYSCALE) {
        ALOGE("expected input color space to be JCS_YCbCr or JCS_GRAYSCALE but got %d",
              cinfo.jpeg_color_space);
        jpeg_destroy_decompress(&cinfo);
        return false;
      }
      if (cinfo.jpeg_color_space == JCS_YCbCr) {
        if (cinfo.comp_info[0].h_samp_factor != 2 || cinfo.comp_info[0].v_samp_factor != 2 ||
            cinfo.comp_info[1].h_samp_factor != 1 || cinfo.comp_info[1].v_samp_factor != 1 ||
            cinfo.comp_info[2].h_samp_factor != 1 || cinfo.comp_info[2].v_samp_factor != 1) {
          ALOGE("apply gainmap supports only 4:2:0 sub sampling format, stopping image decode");
          jpeg_destroy_decompress(&cinfo);
          return false;
        }
      }
      int size = 0;
      for (int i = 0; i < cinfo.num_components; i++) {
        size += mPlaneWidth[i] * mPlaneHeight[i];
      }
      mResultBuffer.resize(size);
      cinfo.out_color_space = cinfo.jpeg_color_space;
      cinfo.raw_data_out = TRUE;
    }
    cinfo.dct_method = JDCT_ISLOW;
    jpeg_start_decompress(&cinfo);
    if (!decode(&cinfo, static_cast<uint8_t*>(mResultBuffer.data()))) {
      jpeg_destroy_decompress(&cinfo);
      return false;
    }
  } else {
    cinfo.err->output_message((j_common_ptr)&cinfo);
    jpeg_destroy_decompress(&cinfo);
    return false;
  }
  jpeg_finish_decompress(&cinfo);
  jpeg_destroy_decompress(&cinfo);
  return true;
}

bool JpegDecoderHelper::decode(jpeg_decompress_struct* cinfo, uint8_t* dest) {
  switch (cinfo->out_color_space) {
    case JCS_GRAYSCALE:
      [[fallthrough]];
    case JCS_YCbCr:
      mOutFormat = getOutputSamplingFormat(cinfo);
      return decodeToCSYCbCr(cinfo, dest);
#ifdef JCS_ALPHA_EXTENSIONS
    case JCS_EXT_RGBA:
      mOutFormat = UHDR_IMG_FMT_32bppRGBA8888;
      return decodeToCSRGB(cinfo, dest);
#endif
    case JCS_RGB:
      mOutFormat = UHDR_IMG_FMT_24bppRGB888;
      return decodeToCSRGB(cinfo, dest);
    default:
      ALOGE("unrecognized output color space %d", cinfo->out_color_space);
  }
  return false;
}

bool JpegDecoderHelper::decodeToCSRGB(jpeg_decompress_struct* cinfo, uint8_t* dest) {
  JSAMPLE* out = (JSAMPLE*)dest;

  while (cinfo->output_scanline < cinfo->image_height) {
    JDIMENSION read_lines = jpeg_read_scanlines(cinfo, &out, 1);
    if (1 != read_lines) {
      ALOGE("jpeg_read_scanlines returned %d, expected %d", read_lines, 1);
      return false;
    }
#ifdef JCS_ALPHA_EXTENSIONS
    out += cinfo->image_width * 4;
#else
    out += cinfo->image_width * 3;
#endif
  }
  return true;
}

bool JpegDecoderHelper::decodeToCSYCbCr(jpeg_decompress_struct* cinfo, uint8_t* dest) {
  JSAMPROW mcuRows[kMaxNumComponents][4 * DCTSIZE];
  JSAMPROW mcuRowsTmp[kMaxNumComponents][4 * DCTSIZE];
  uint8_t* planes[kMaxNumComponents]{};
  size_t alignedPlaneWidth[kMaxNumComponents]{};
  JSAMPARRAY subImage[kMaxNumComponents];

  for (int i = 0, plane_offset = 0; i < cinfo->num_components; i++) {
    planes[i] = dest + plane_offset;
    plane_offset += mPlaneWidth[i] * mPlaneHeight[i];
    alignedPlaneWidth[i] = ALIGNM(mPlaneWidth[i], DCTSIZE);
    if (mPlaneWidth[i] != alignedPlaneWidth[i]) {
      mPlanesMCURow[i] = std::make_unique<uint8_t[]>(alignedPlaneWidth[i] * DCTSIZE *
                                                     cinfo->comp_info[i].v_samp_factor);
      uint8_t* mem = mPlanesMCURow[i].get();
      for (int j = 0; j < DCTSIZE * cinfo->comp_info[i].v_samp_factor;
           j++, mem += alignedPlaneWidth[i]) {
        mcuRowsTmp[i][j] = mem;
      }
    } else if (mPlaneHeight[i] % DCTSIZE != 0) {
      mPlanesMCURow[i] = std::make_unique<uint8_t[]>(alignedPlaneWidth[i]);
    }
    subImage[i] = mPlaneWidth[i] == alignedPlaneWidth[i] ? mcuRows[i] : mcuRowsTmp[i];
  }

  while (cinfo->output_scanline < cinfo->image_height) {
    JDIMENSION mcu_scanline_start[kMaxNumComponents];

    for (int i = 0; i < cinfo->num_components; i++) {
      mcu_scanline_start[i] =
          std::ceil(((float)cinfo->output_scanline * cinfo->comp_info[i].v_samp_factor) /
                    cinfo->max_v_samp_factor);

      for (int j = 0; j < cinfo->comp_info[i].v_samp_factor * DCTSIZE; j++) {
        JDIMENSION scanline = mcu_scanline_start[i] + j;

        if (scanline < mPlaneHeight[i]) {
          mcuRows[i][j] = planes[i] + scanline * mPlaneWidth[i];
        } else {
          mcuRows[i][j] = mPlanesMCURow[i].get();
        }
      }
    }

    int processed = jpeg_read_raw_data(cinfo, subImage, DCTSIZE * cinfo->max_v_samp_factor);
    if (processed != DCTSIZE * cinfo->max_v_samp_factor) {
      ALOGE("number of scan lines read %d does not equal requested scan lines %d ", processed,
            DCTSIZE * cinfo->max_v_samp_factor);
      return false;
    }

    for (int i = 0; i < cinfo->num_components; i++) {
      if (mPlaneWidth[i] != alignedPlaneWidth[i]) {
        for (int j = 0; j < cinfo->comp_info[i].v_samp_factor * DCTSIZE; j++) {
          JDIMENSION scanline = mcu_scanline_start[i] + j;
          if (scanline < mPlaneHeight[i]) {
            memcpy(mcuRows[i][j], mcuRowsTmp[i][j], mPlaneWidth[i]);
          }
        }
      }
    }
  }
  return true;
}

}  // namespace ultrahdr
