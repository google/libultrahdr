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

#include <cstring>

#include "ultrahdrcommon.h"
#include "ultrahdr.h"
#include "jpegdecoderhelper.h"

using namespace std;

namespace ultrahdr {

const uint32_t kAPP0Marker = JPEG_APP0;      // JFIF
const uint32_t kAPP1Marker = JPEG_APP0 + 1;  // EXIF, XMP
const uint32_t kAPP2Marker = JPEG_APP0 + 2;  // ICC

constexpr uint32_t kICCMarkerHeaderSize = 14;
constexpr uint8_t kICCSig[] = {
    'I', 'C', 'C', '_', 'P', 'R', 'O', 'F', 'I', 'L', 'E', '\0',
};
constexpr uint8_t kXmpNameSpace[] = {
    'h', 't', 't', 'p', ':', '/', '/', 'n', 's', '.', 'a', 'd', 'o', 'b',  'e',
    '.', 'c', 'o', 'm', '/', 'x', 'a', 'p', '/', '1', '.', '0', '/', '\0',
};
constexpr uint8_t kExifIdCode[] = {
    'E', 'x', 'i', 'f', '\0', '\0',
};

struct jpegr_source_mgr : jpeg_source_mgr {
  jpegr_source_mgr(const uint8_t* ptr, int len);
  ~jpegr_source_mgr();

  const uint8_t* mBufferPtr;
  size_t mBufferLength;
};

struct jpegrerror_mgr {
  struct jpeg_error_mgr pub;
  jmp_buf setjmp_buffer;
};

static void jpegr_init_source(j_decompress_ptr cinfo) {
  jpegr_source_mgr* src = static_cast<jpegr_source_mgr*>(cinfo->src);
  src->next_input_byte = static_cast<const JOCTET*>(src->mBufferPtr);
  src->bytes_in_buffer = src->mBufferLength;
}

static boolean jpegr_fill_input_buffer(j_decompress_ptr /* cinfo */) {
  ALOGE("%s : should not get here", __func__);
  return FALSE;
}

static void jpegr_skip_input_data(j_decompress_ptr cinfo, long num_bytes) {
  jpegr_source_mgr* src = static_cast<jpegr_source_mgr*>(cinfo->src);

  if (num_bytes > static_cast<long>(src->bytes_in_buffer)) {
    ALOGE("jpegr_skip_input_data - num_bytes > (long)src->bytes_in_buffer");
  } else {
    src->next_input_byte += num_bytes;
    src->bytes_in_buffer -= num_bytes;
  }
}

static void jpegr_term_source(j_decompress_ptr /*cinfo*/) {}

jpegr_source_mgr::jpegr_source_mgr(const uint8_t* ptr, int len)
    : mBufferPtr(ptr), mBufferLength(len) {
  init_source = jpegr_init_source;
  fill_input_buffer = jpegr_fill_input_buffer;
  skip_input_data = jpegr_skip_input_data;
  resync_to_restart = jpeg_resync_to_restart;
  term_source = jpegr_term_source;
}

jpegr_source_mgr::~jpegr_source_mgr() {}

static void jpegrerror_exit(j_common_ptr cinfo) {
  jpegrerror_mgr* err = reinterpret_cast<jpegrerror_mgr*>(cinfo->err);
  longjmp(err->setjmp_buffer, 1);
}

static void output_message(j_common_ptr cinfo) {
  char buffer[JMSG_LENGTH_MAX];

  /* Create the message */
  (*cinfo->err->format_message)(cinfo, buffer);
  ALOGE("%s\n", buffer);
}

JpegDecoderHelper::JpegDecoderHelper() {}

JpegDecoderHelper::~JpegDecoderHelper() {}

bool JpegDecoderHelper::decompressImage(const void* image, int length, bool decodeToRGBA) {
  if (image == nullptr || length <= 0) {
    ALOGE("Image size can not be handled: %d", length);
    return false;
  }
  mResultBuffer.clear();
  mXMPBuffer.clear();
  return decode(image, length, decodeToRGBA);
}

void* JpegDecoderHelper::getDecompressedImagePtr() { return mResultBuffer.data(); }

size_t JpegDecoderHelper::getDecompressedImageSize() { return mResultBuffer.size(); }

void* JpegDecoderHelper::getXMPPtr() { return mXMPBuffer.data(); }

size_t JpegDecoderHelper::getXMPSize() { return mXMPBuffer.size(); }

void* JpegDecoderHelper::getEXIFPtr() { return mEXIFBuffer.data(); }

size_t JpegDecoderHelper::getEXIFSize() { return mEXIFBuffer.size(); }

void* JpegDecoderHelper::getICCPtr() { return mICCBuffer.data(); }

size_t JpegDecoderHelper::getICCSize() { return mICCBuffer.size(); }

size_t JpegDecoderHelper::getDecompressedImageWidth() { return mWidth; }

size_t JpegDecoderHelper::getDecompressedImageHeight() { return mHeight; }

// Here we only handle the first EXIF package, and in theary EXIF (or JFIF) must be the first
// in the image file.
// We assume that all packages are starting with two bytes marker (eg FF E1 for EXIF package),
// two bytes of package length which is stored in marker->original_length, and the real data
// which is stored in marker->data.
bool JpegDecoderHelper::extractEXIF(const void* image, int length) {
  jpeg_decompress_struct cinfo;
  jpegr_source_mgr mgr(static_cast<const uint8_t*>(image), length);
  jpegrerror_mgr myerr;

  cinfo.err = jpeg_std_error(&myerr.pub);
  myerr.pub.error_exit = jpegrerror_exit;
  myerr.pub.output_message = output_message;

  if (setjmp(myerr.setjmp_buffer)) {
    jpeg_destroy_decompress(&cinfo);
    return false;
  }
  jpeg_create_decompress(&cinfo);

  jpeg_save_markers(&cinfo, kAPP0Marker, 0xFFFF);
  jpeg_save_markers(&cinfo, kAPP1Marker, 0xFFFF);

  cinfo.src = &mgr;
  jpeg_read_header(&cinfo, TRUE);

  size_t pos = 2;  // position after SOI
  for (jpeg_marker_struct* marker = cinfo.marker_list; marker; marker = marker->next) {
    pos += 4;
    pos += marker->original_length;

    if (marker->marker != kAPP1Marker) {
      continue;
    }

    const unsigned int len = marker->data_length;

    if (len > sizeof(kExifIdCode) && !memcmp(marker->data, kExifIdCode, sizeof(kExifIdCode))) {
      mEXIFBuffer.resize(len, 0);
      memcpy(static_cast<void*>(mEXIFBuffer.data()), marker->data, len);
      mExifPos = pos - marker->original_length;
      break;
    }
  }

  jpeg_destroy_decompress(&cinfo);
  return true;
}

bool JpegDecoderHelper::decode(const void* image, int length, bool decodeToRGBA) {
  bool status = true;
  jpeg_decompress_struct cinfo;
  jpegrerror_mgr myerr;
  cinfo.err = jpeg_std_error(&myerr.pub);
  myerr.pub.error_exit = jpegrerror_exit;
  myerr.pub.output_message = output_message;

  if (setjmp(myerr.setjmp_buffer)) {
    jpeg_destroy_decompress(&cinfo);
    return false;
  }

  jpeg_create_decompress(&cinfo);

  jpeg_save_markers(&cinfo, kAPP0Marker, 0xFFFF);
  jpeg_save_markers(&cinfo, kAPP1Marker, 0xFFFF);
  jpeg_save_markers(&cinfo, kAPP2Marker, 0xFFFF);

  jpegr_source_mgr mgr(static_cast<const uint8_t*>(image), length);
  cinfo.src = &mgr;
  if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
    jpeg_destroy_decompress(&cinfo);
    return false;
  }

  // Save XMP data, EXIF data, and ICC data.
  // Here we only handle the first XMP / EXIF / ICC package.
  // We assume that all packages are starting with two bytes marker (eg FF E1 for EXIF package),
  // two bytes of package length which is stored in marker->original_length, and the real data
  // which is stored in marker->data.
  bool exifAppears = false;
  bool xmpAppears = false;
  bool iccAppears = false;
  size_t pos = 2;  // position after SOI
  for (jpeg_marker_struct* marker = cinfo.marker_list;
       marker && !(exifAppears && xmpAppears && iccAppears); marker = marker->next) {
    pos += 4;
    pos += marker->original_length;
    if (marker->marker != kAPP1Marker && marker->marker != kAPP2Marker) {
      continue;
    }
    const unsigned int len = marker->data_length;
    if (!xmpAppears && len > sizeof(kXmpNameSpace) &&
        !memcmp(marker->data, kXmpNameSpace, sizeof(kXmpNameSpace))) {
      mXMPBuffer.resize(len + 1, 0);
      memcpy(static_cast<void*>(mXMPBuffer.data()), marker->data, len);
      xmpAppears = true;
    } else if (!exifAppears && len > sizeof(kExifIdCode) &&
               !memcmp(marker->data, kExifIdCode, sizeof(kExifIdCode))) {
      mEXIFBuffer.resize(len, 0);
      memcpy(static_cast<void*>(mEXIFBuffer.data()), marker->data, len);
      exifAppears = true;
      mExifPos = pos - marker->original_length;
    } else if (!iccAppears && len > sizeof(kICCSig) &&
               !memcmp(marker->data, kICCSig, sizeof(kICCSig))) {
      mICCBuffer.resize(len, 0);
      memcpy(static_cast<void*>(mICCBuffer.data()), marker->data, len);
      iccAppears = true;
    }
  }

  mWidth = cinfo.image_width;
  mHeight = cinfo.image_height;
  if (mWidth > kMaxWidth || mHeight > kMaxHeight) {
    status = false;
    goto CleanUp;
  }

  if (decodeToRGBA) {
    // The primary image is expected to be yuv420 sampling
    if (cinfo.jpeg_color_space != JCS_YCbCr) {
      status = false;
      ALOGE("%s: decodeToRGBA unexpected jpeg color space ", __func__);
      goto CleanUp;
    }
    if (cinfo.comp_info[0].h_samp_factor != 2 || cinfo.comp_info[0].v_samp_factor != 2 ||
        cinfo.comp_info[1].h_samp_factor != 1 || cinfo.comp_info[1].v_samp_factor != 1 ||
        cinfo.comp_info[2].h_samp_factor != 1 || cinfo.comp_info[2].v_samp_factor != 1) {
      status = false;
      ALOGE("%s: decodeToRGBA unexpected primary image sub-sampling", __func__);
      goto CleanUp;
    }
    // 4 bytes per pixel
    mResultBuffer.resize(cinfo.image_width * cinfo.image_height * 4);
    cinfo.out_color_space = JCS_EXT_RGBA;
  } else {
    if (cinfo.jpeg_color_space == JCS_YCbCr) {
      if (cinfo.comp_info[0].h_samp_factor != 2 || cinfo.comp_info[0].v_samp_factor != 2 ||
          cinfo.comp_info[1].h_samp_factor != 1 || cinfo.comp_info[1].v_samp_factor != 1 ||
          cinfo.comp_info[2].h_samp_factor != 1 || cinfo.comp_info[2].v_samp_factor != 1) {
        status = false;
        ALOGE("%s: decoding to YUV only supports 4:2:0 subsampling", __func__);
        goto CleanUp;
      }
      mResultBuffer.resize(cinfo.image_width * cinfo.image_height * 3 / 2, 0);
    } else if (cinfo.jpeg_color_space == JCS_GRAYSCALE) {
      mResultBuffer.resize(cinfo.image_width * cinfo.image_height, 0);
    } else {
      status = false;
      ALOGE("%s: decodeToYUV unexpected jpeg color space", __func__);
      goto CleanUp;
    }
    cinfo.out_color_space = cinfo.jpeg_color_space;
    cinfo.raw_data_out = TRUE;
  }

  cinfo.dct_method = JDCT_ISLOW;
  jpeg_start_decompress(&cinfo);
  if (!decompress(&cinfo, static_cast<const uint8_t*>(mResultBuffer.data()),
                  cinfo.jpeg_color_space == JCS_GRAYSCALE)) {
    status = false;
    goto CleanUp;
  }

CleanUp:
  jpeg_finish_decompress(&cinfo);
  jpeg_destroy_decompress(&cinfo);

  return status;
}

bool JpegDecoderHelper::decompress(jpeg_decompress_struct* cinfo, const uint8_t* dest,
                                   bool isSingleChannel) {
  return isSingleChannel ? decompressSingleChannel(cinfo, dest)
                         : ((cinfo->out_color_space == JCS_EXT_RGBA) ? decompressRGBA(cinfo, dest)
                                                                     : decompressYUV(cinfo, dest));
}

bool JpegDecoderHelper::getCompressedImageParameters(const void* image, int length, size_t* pWidth,
                                                     size_t* pHeight, std::vector<uint8_t>* iccData,
                                                     std::vector<uint8_t>* exifData) {
  jpeg_decompress_struct cinfo;
  jpegrerror_mgr myerr;
  cinfo.err = jpeg_std_error(&myerr.pub);
  myerr.pub.error_exit = jpegrerror_exit;
  myerr.pub.output_message = output_message;

  if (setjmp(myerr.setjmp_buffer)) {
    jpeg_destroy_decompress(&cinfo);
    return false;
  }
  jpeg_create_decompress(&cinfo);

  jpeg_save_markers(&cinfo, kAPP1Marker, 0xFFFF);
  jpeg_save_markers(&cinfo, kAPP2Marker, 0xFFFF);

  jpegr_source_mgr mgr(static_cast<const uint8_t*>(image), length);
  cinfo.src = &mgr;
  if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
    jpeg_destroy_decompress(&cinfo);
    return false;
  }

  if (pWidth != nullptr) {
    *pWidth = cinfo.image_width;
  }
  if (pHeight != nullptr) {
    *pHeight = cinfo.image_height;
  }

  if (iccData != nullptr) {
    for (jpeg_marker_struct* marker = cinfo.marker_list; marker; marker = marker->next) {
      if (marker->marker != kAPP2Marker) {
        continue;
      }
      if (marker->data_length <= kICCMarkerHeaderSize ||
          memcmp(marker->data, kICCSig, sizeof(kICCSig)) != 0) {
        continue;
      }

      iccData->insert(iccData->end(), marker->data, marker->data + marker->data_length);
    }
  }

  if (exifData != nullptr) {
    bool exifAppears = false;
    for (jpeg_marker_struct* marker = cinfo.marker_list; marker && !exifAppears;
         marker = marker->next) {
      if (marker->marker != kAPP1Marker) {
        continue;
      }

      const unsigned int len = marker->data_length;
      if (len >= sizeof(kExifIdCode) && !memcmp(marker->data, kExifIdCode, sizeof(kExifIdCode))) {
        exifData->resize(len, 0);
        memcpy(static_cast<void*>(exifData->data()), marker->data, len);
        exifAppears = true;
      }
    }
  }

  jpeg_destroy_decompress(&cinfo);
  return true;
}

bool JpegDecoderHelper::decompressRGBA(jpeg_decompress_struct* cinfo, const uint8_t* dest) {
  JSAMPLE* out = (JSAMPLE*)dest;

  while (cinfo->output_scanline < cinfo->image_height) {
    if (1 != jpeg_read_scanlines(cinfo, &out, 1)) return false;
    out += cinfo->image_width * 4;
  }
  return true;
}

bool JpegDecoderHelper::decompressYUV(jpeg_decompress_struct* cinfo, const uint8_t* dest) {
  size_t luma_plane_size = cinfo->image_width * cinfo->image_height;
  size_t chroma_plane_size = luma_plane_size / 4;
  uint8_t* y_plane = const_cast<uint8_t*>(dest);
  uint8_t* u_plane = const_cast<uint8_t*>(dest + luma_plane_size);
  uint8_t* v_plane = const_cast<uint8_t*>(dest + luma_plane_size + chroma_plane_size);

  const size_t aligned_width = ALIGNM(cinfo->image_width, kCompressBatchSize);
  const bool is_width_aligned = (aligned_width == cinfo->image_width);
  uint8_t* y_plane_intrm = nullptr;
  uint8_t* u_plane_intrm = nullptr;
  uint8_t* v_plane_intrm = nullptr;

  JSAMPROW y[kCompressBatchSize];
  JSAMPROW cb[kCompressBatchSize / 2];
  JSAMPROW cr[kCompressBatchSize / 2];
  JSAMPARRAY planes[3]{y, cb, cr};
  JSAMPROW y_intrm[kCompressBatchSize];
  JSAMPROW cb_intrm[kCompressBatchSize / 2];
  JSAMPROW cr_intrm[kCompressBatchSize / 2];
  JSAMPARRAY planes_intrm[3]{y_intrm, cb_intrm, cr_intrm};

  if (cinfo->image_height % kCompressBatchSize != 0) {
    mEmpty = std::make_unique<uint8_t[]>(aligned_width);
  }

  if (!is_width_aligned) {
    size_t mcu_row_size = aligned_width * kCompressBatchSize * 3 / 2;
    mBufferIntermediate = std::make_unique<uint8_t[]>(mcu_row_size);
    y_plane_intrm = mBufferIntermediate.get();
    u_plane_intrm = y_plane_intrm + (aligned_width * kCompressBatchSize);
    v_plane_intrm = u_plane_intrm + (aligned_width * kCompressBatchSize) / 4;
    for (int i = 0; i < kCompressBatchSize; ++i) {
      y_intrm[i] = y_plane_intrm + i * aligned_width;
    }
    for (int i = 0; i < kCompressBatchSize / 2; ++i) {
      int offset_intrm = i * (aligned_width / 2);
      cb_intrm[i] = u_plane_intrm + offset_intrm;
      cr_intrm[i] = v_plane_intrm + offset_intrm;
    }
  }

  while (cinfo->output_scanline < cinfo->image_height) {
    size_t scanline_copy = cinfo->output_scanline;
    for (int i = 0; i < kCompressBatchSize; ++i) {
      size_t scanline = cinfo->output_scanline + i;
      if (scanline < cinfo->image_height) {
        y[i] = y_plane + scanline * cinfo->image_width;
      } else {
        y[i] = mEmpty.get();
      }
    }
    // cb, cr only have half scanlines
    for (int i = 0; i < kCompressBatchSize / 2; ++i) {
      size_t scanline = cinfo->output_scanline / 2 + i;
      if (scanline < cinfo->image_height / 2) {
        int offset = scanline * (cinfo->image_width / 2);
        cb[i] = u_plane + offset;
        cr[i] = v_plane + offset;
      } else {
        cb[i] = cr[i] = mEmpty.get();
      }
    }

    int processed =
        jpeg_read_raw_data(cinfo, is_width_aligned ? planes : planes_intrm, kCompressBatchSize);
    if (processed != kCompressBatchSize) {
      ALOGE("Number of processed lines does not equal input lines.");
      return false;
    }
    if (!is_width_aligned) {
      for (int i = 0; i < kCompressBatchSize; ++i) {
        if (scanline_copy + i < cinfo->image_height) {
          memcpy(y[i], y_intrm[i], cinfo->image_width);
        }
      }
      for (int i = 0; i < kCompressBatchSize / 2; ++i) {
        if (((scanline_copy / 2) + i) < (cinfo->image_height / 2)) {
          memcpy(cb[i], cb_intrm[i], cinfo->image_width / 2);
          memcpy(cr[i], cr_intrm[i], cinfo->image_width / 2);
        }
      }
    }
  }
  return true;
}

bool JpegDecoderHelper::decompressSingleChannel(jpeg_decompress_struct* cinfo,
                                                const uint8_t* dest) {
  uint8_t* y_plane = const_cast<uint8_t*>(dest);
  uint8_t* y_plane_intrm = nullptr;

  const size_t aligned_width = ALIGNM(cinfo->image_width, kCompressBatchSize);
  const bool is_width_aligned = (aligned_width == cinfo->image_width);

  JSAMPROW y[kCompressBatchSize];
  JSAMPARRAY planes[1]{y};
  JSAMPROW y_intrm[kCompressBatchSize];
  JSAMPARRAY planes_intrm[1]{y_intrm};

  if (cinfo->image_height % kCompressBatchSize != 0) {
    mEmpty = std::make_unique<uint8_t[]>(aligned_width);
  }

  if (!is_width_aligned) {
    size_t mcu_row_size = aligned_width * kCompressBatchSize;
    mBufferIntermediate = std::make_unique<uint8_t[]>(mcu_row_size);
    y_plane_intrm = mBufferIntermediate.get();
    for (int i = 0; i < kCompressBatchSize; ++i) {
      y_intrm[i] = y_plane_intrm + i * aligned_width;
    }
  }

  while (cinfo->output_scanline < cinfo->image_height) {
    size_t scanline_copy = cinfo->output_scanline;
    for (int i = 0; i < kCompressBatchSize; ++i) {
      size_t scanline = cinfo->output_scanline + i;
      if (scanline < cinfo->image_height) {
        y[i] = y_plane + scanline * cinfo->image_width;
      } else {
        y[i] = mEmpty.get();
      }
    }

    int processed =
        jpeg_read_raw_data(cinfo, is_width_aligned ? planes : planes_intrm, kCompressBatchSize);
    if (processed != kCompressBatchSize / 2) {
      ALOGE("Number of processed lines does not equal input lines.");
      return false;
    }
    if (!is_width_aligned) {
      for (int i = 0; i < kCompressBatchSize; ++i) {
        if (scanline_copy + i < cinfo->image_height) {
          memcpy(y[i], y_intrm[i], cinfo->image_width);
        }
      }
    }
  }
  return true;
}

}  // namespace ultrahdr
