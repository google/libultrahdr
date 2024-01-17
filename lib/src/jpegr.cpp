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

#ifdef _WIN32
#include <Windows.h>
#include <sysinfoapi.h>
#else
#include <unistd.h>
#endif

#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/jpegr.h"
#include "ultrahdr/icc.h"
#include "ultrahdr/multipictureformat.h"

#include "image_io/base/data_segment_data_source.h"
#include "image_io/jpeg/jpeg_info.h"
#include "image_io/jpeg/jpeg_info_builder.h"
#include "image_io/jpeg/jpeg_marker.h"
#include "image_io/jpeg/jpeg_scanner.h"

using namespace std;
using namespace photos_editing_formats::image_io;

namespace ultrahdr {

#define USE_SRGB_INVOETF_LUT 1
#define USE_HLG_OETF_LUT 1
#define USE_PQ_OETF_LUT 1
#define USE_HLG_INVOETF_LUT 1
#define USE_PQ_INVOETF_LUT 1
#define USE_APPLY_GAIN_LUT 1

// JPEG compress quality (0 ~ 100) for gain map
static const int kMapCompressQuality = 85;

// The current JPEGR version that we encode to
const char kJpegrVersion[] = "1.0";

// Map is quarter res / sixteenth size
const size_t kMapDimensionScaleFactor = 4;

// Gain Map width is (image_width / kMapDimensionScaleFactor). If we were to
// compress 420 GainMap in jpeg, then we need at least 2 samples. For Grayscale
// 1 sample is sufficient. We are using 2 here anyways
const int kMinWidth = 2 * kMapDimensionScaleFactor;
const int kMinHeight = 2 * kMapDimensionScaleFactor;

static_assert(sizeof kJpegrVersion <= sizeof(((ultrahdr_metadata_ptr)0)->version),
              "ultrahdr_metadata_struct.version must be at least sizeof kJpegrVersion");

int GetCPUCoreCount() {
  int cpuCoreCount = 1;

#if defined(_WIN32)
  SYSTEM_INFO system_info;
  ZeroMemory(&system_info, sizeof(system_info));
  GetSystemInfo(&system_info);
  cpuCoreCount = (size_t)system_info.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_ONLN)
  cpuCoreCount = sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(_SC_NPROCESSORS_CONF)
  cpuCoreCount = sysconf(_SC_NPROCESSORS_CONF);
#else
#error platform-specific implementation for GetCPUCoreCount() missing.
#endif
  if (cpuCoreCount <= 0) cpuCoreCount = 1;
  return cpuCoreCount;
}

/*
 * MessageWriter implementation for ALOG functions.
 */
class AlogMessageWriter : public MessageWriter {
 public:
  void WriteMessage(const Message& message) override {
    std::string log = GetFormattedMessage(message);
    ALOGD("%s", log.c_str());
  }
};

/*
 * Helper function copies the JPEG image from without EXIF.
 *
 * @param pDest destination of the data to be written.
 * @param pSource source of data being written.
 * @param exif_pos position of the EXIF package, which is aligned with jpegdecoder.getEXIFPos().
 *                 (4 bytes offset to FF sign, the byte after FF E1 XX XX <this byte>).
 * @param exif_size exif size without the initial 4 bytes, aligned with jpegdecoder.getEXIFSize().
 */
static void copyJpegWithoutExif(ultrahdr_compressed_ptr pDest, ultrahdr_compressed_ptr pSource,
                                size_t exif_pos, size_t exif_size) {
  const size_t exif_offset = 4;  // exif_pos has 4 bytes offset to the FF sign
  pDest->length = pSource->length - exif_size - exif_offset;
  pDest->data = new uint8_t[pDest->length];
  pDest->maxLength = pDest->length;
  pDest->colorGamut = pSource->colorGamut;
  memcpy(pDest->data, pSource->data, exif_pos - exif_offset);
  memcpy((uint8_t*)pDest->data + exif_pos - exif_offset,
         (uint8_t*)pSource->data + exif_pos + exif_size, pSource->length - exif_pos - exif_size);
}

status_t JpegR::areInputArgumentsValid(ultrahdr_uncompressed_ptr p010_image_ptr,
                                       ultrahdr_uncompressed_ptr yuv420_image_ptr,
                                       ultrahdr_transfer_function hdr_tf,
                                       ultrahdr_compressed_ptr dest_ptr) {
  if (p010_image_ptr == nullptr || p010_image_ptr->data == nullptr) {
    ALOGE("Received nullptr for input p010 image");
    return ERROR_UHDR_BAD_PTR;
  }
  if (p010_image_ptr->width % 2 != 0 || p010_image_ptr->height % 2 != 0) {
    ALOGE("Image dimensions cannot be odd, image dimensions %zux%zu", p010_image_ptr->width,
          p010_image_ptr->height);
    return ERROR_UHDR_UNSUPPORTED_WIDTH_HEIGHT;
  }
  if (p010_image_ptr->width < kMinWidth || p010_image_ptr->height < kMinHeight) {
    ALOGE("Image dimensions cannot be less than %dx%d, image dimensions %zux%zu", kMinWidth,
          kMinHeight, p010_image_ptr->width, p010_image_ptr->height);
    return ERROR_UHDR_UNSUPPORTED_WIDTH_HEIGHT;
  }
  if (p010_image_ptr->width > kMaxWidth || p010_image_ptr->height > kMaxHeight) {
    ALOGE("Image dimensions cannot be larger than %dx%d, image dimensions %zux%zu", kMaxWidth,
          kMaxHeight, p010_image_ptr->width, p010_image_ptr->height);
    return ERROR_UHDR_UNSUPPORTED_WIDTH_HEIGHT;
  }
  if (p010_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
      p010_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
    ALOGE("Unrecognized p010 color gamut %d", p010_image_ptr->colorGamut);
    return ERROR_UHDR_INVALID_COLORGAMUT;
  }
  if (p010_image_ptr->pixelFormat != ULTRAHDR_PIX_FMT_P010) {
    ALOGE("Invalid pixel format, expected %d, got %d", ULTRAHDR_PIX_FMT_P010,
          p010_image_ptr->pixelFormat);
    return ERROR_UHDR_INVALID_PIXEL_FORMAT;
  }
  if (p010_image_ptr->luma_stride != 0 && p010_image_ptr->luma_stride < p010_image_ptr->width) {
    ALOGE("Luma stride must not be smaller than width, stride=%zu, width=%zu",
          p010_image_ptr->luma_stride, p010_image_ptr->width);
    return ERROR_UHDR_INVALID_STRIDE;
  }
  if (p010_image_ptr->chroma_data != nullptr &&
      p010_image_ptr->chroma_stride < p010_image_ptr->width) {
    ALOGE("Chroma stride must not be smaller than width, stride=%zu, width=%zu",
          p010_image_ptr->chroma_stride, p010_image_ptr->width);
    return ERROR_UHDR_INVALID_STRIDE;
  }
  if (dest_ptr == nullptr || dest_ptr->data == nullptr) {
    ALOGE("Received nullptr for destination");
    return ERROR_UHDR_BAD_PTR;
  }
  if (hdr_tf <= ULTRAHDR_TF_UNSPECIFIED || hdr_tf > ULTRAHDR_TF_MAX || hdr_tf == ULTRAHDR_TF_SRGB) {
    ALOGE("Invalid hdr transfer function %d", hdr_tf);
    return ERROR_UHDR_INVALID_TRANS_FUNC;
  }
  if (yuv420_image_ptr == nullptr) {
    return UHDR_NO_ERROR;
  }
  if (yuv420_image_ptr->data == nullptr) {
    ALOGE("Received nullptr for uncompressed 420 image");
    return ERROR_UHDR_BAD_PTR;
  }
  if (yuv420_image_ptr->luma_stride != 0 &&
      yuv420_image_ptr->luma_stride < yuv420_image_ptr->width) {
    ALOGE("Luma stride must not be smaller than width, stride=%zu, width=%zu",
          yuv420_image_ptr->luma_stride, yuv420_image_ptr->width);
    return ERROR_UHDR_INVALID_STRIDE;
  }
  if (yuv420_image_ptr->chroma_data != nullptr &&
      yuv420_image_ptr->chroma_stride < yuv420_image_ptr->width / 2) {
    ALOGE("Chroma stride must not be smaller than (width / 2), stride=%zu, width=%zu",
          yuv420_image_ptr->chroma_stride, yuv420_image_ptr->width);
    return ERROR_UHDR_INVALID_STRIDE;
  }
  if (p010_image_ptr->width != yuv420_image_ptr->width ||
      p010_image_ptr->height != yuv420_image_ptr->height) {
    ALOGE("Image resolutions mismatch: P010: %zux%zu, YUV420: %zux%zu", p010_image_ptr->width,
          p010_image_ptr->height, yuv420_image_ptr->width, yuv420_image_ptr->height);
    return ERROR_UHDR_RESOLUTION_MISMATCH;
  }
  if (yuv420_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
      yuv420_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
    ALOGE("Unrecognized 420 color gamut %d", yuv420_image_ptr->colorGamut);
    return ERROR_UHDR_INVALID_COLORGAMUT;
  }
  if (yuv420_image_ptr->pixelFormat != ULTRAHDR_PIX_FMT_YUV420) {
    ALOGE("Invalid pixel format, expected %d, got %d", ULTRAHDR_PIX_FMT_YUV420,
          yuv420_image_ptr->pixelFormat);
    return ERROR_UHDR_INVALID_PIXEL_FORMAT;
  }
  return UHDR_NO_ERROR;
}

status_t JpegR::areInputArgumentsValid(ultrahdr_uncompressed_ptr p010_image_ptr,
                                       ultrahdr_uncompressed_ptr yuv420_image_ptr,
                                       ultrahdr_transfer_function hdr_tf,
                                       ultrahdr_compressed_ptr dest_ptr, int quality) {
  if (quality < 0 || quality > 100) {
    ALOGE("quality factor is out side range [0-100], quality factor : %d", quality);
    return ERROR_UHDR_INVALID_QUALITY_FACTOR;
  }
  return areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest_ptr);
}

/* Encode API-0 */
status_t JpegR::encodeJPEGR(ultrahdr_uncompressed_ptr p010_image_ptr,
                            ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest,
                            int quality, ultrahdr_exif_ptr exif) {
  // validate input arguments
  ULTRAHDR_CHECK(areInputArgumentsValid(p010_image_ptr, nullptr, hdr_tf, dest, quality));
  if (exif != nullptr && exif->data == nullptr) {
    ALOGE("received nullptr for exif metadata");
    return ERROR_UHDR_BAD_PTR;
  }

  // clean up input structure for later usage
  ultrahdr_uncompressed_struct p010_image = *p010_image_ptr;
  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
  if (!p010_image.chroma_data) {
    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
    p010_image.chroma_stride = p010_image.luma_stride;
  }

  const size_t yu420_luma_stride = ALIGNM(p010_image.width, JpegEncoderHelper::kCompressBatchSize);
  unique_ptr<uint8_t[]> yuv420_image_data =
      make_unique<uint8_t[]>(yu420_luma_stride * p010_image.height * 3 / 2);
  ultrahdr_uncompressed_struct yuv420_image;
  yuv420_image.data = yuv420_image_data.get();
  yuv420_image.width = p010_image.width;
  yuv420_image.height = p010_image.height;
  yuv420_image.colorGamut = p010_image.colorGamut;
  yuv420_image.pixelFormat = ULTRAHDR_PIX_FMT_YUV420;
  yuv420_image.chroma_data = nullptr;
  yuv420_image.luma_stride = yu420_luma_stride;
  yuv420_image.chroma_stride = yu420_luma_stride >> 1;
  uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
  yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;

  // tone map
  ULTRAHDR_CHECK(toneMap(&p010_image, &yuv420_image));

  // gain map
  ultrahdr_metadata_struct metadata;
  strcpy(metadata.version, kJpegrVersion);
  ultrahdr_uncompressed_struct gainmap_image;
  ULTRAHDR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  ULTRAHDR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
  ultrahdr_compressed_struct compressed_map;
  compressed_map.data = jpeg_enc_obj_gm.getCompressedImagePtr();
  compressed_map.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  compressed_map.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  compressed_map.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;

  std::shared_ptr<DataStruct> icc =
      IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, yuv420_image.colorGamut);

  // convert to Bt601 YUV encoding for JPEG encode
  if (yuv420_image.colorGamut != ULTRAHDR_COLORGAMUT_P3) {
    ULTRAHDR_CHECK(convertYuv(&yuv420_image, yuv420_image.colorGamut, ULTRAHDR_COLORGAMUT_P3));
  }

  // compress 420 image
  JpegEncoderHelper jpeg_enc_obj_yuv420;
  if (!jpeg_enc_obj_yuv420.compressImage(reinterpret_cast<uint8_t*>(yuv420_image.data),
                                         reinterpret_cast<uint8_t*>(yuv420_image.chroma_data),
                                         yuv420_image.width, yuv420_image.height,
                                         yuv420_image.luma_stride, yuv420_image.chroma_stride,
                                         quality, icc->getData(), icc->getLength())) {
    return ERROR_UHDR_ENCODE_ERROR;
  }
  ultrahdr_compressed_struct jpeg;
  jpeg.data = jpeg_enc_obj_yuv420.getCompressedImagePtr();
  jpeg.length = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
  jpeg.maxLength = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
  jpeg.colorGamut = yuv420_image.colorGamut;

  // append gain map, no ICC since JPEG encode already did it
  ULTRAHDR_CHECK(appendGainMap(&jpeg, &compressed_map, exif, /* icc */ nullptr, /* icc size */ 0,
                               &metadata, dest));

  return UHDR_NO_ERROR;
}

/* Encode API-1 */
status_t JpegR::encodeJPEGR(ultrahdr_uncompressed_ptr p010_image_ptr,
                            ultrahdr_uncompressed_ptr yuv420_image_ptr,
                            ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest,
                            int quality, ultrahdr_exif_ptr exif) {
  // validate input arguments
  if (yuv420_image_ptr == nullptr) {
    ALOGE("received nullptr for uncompressed 420 image");
    return ERROR_UHDR_BAD_PTR;
  }
  if (exif != nullptr && exif->data == nullptr) {
    ALOGE("received nullptr for exif metadata");
    return ERROR_UHDR_BAD_PTR;
  }
  ULTRAHDR_CHECK(areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest, quality))

  // clean up input structure for later usage
  ultrahdr_uncompressed_struct p010_image = *p010_image_ptr;
  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
  if (!p010_image.chroma_data) {
    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
    p010_image.chroma_stride = p010_image.luma_stride;
  }
  ultrahdr_uncompressed_struct yuv420_image = *yuv420_image_ptr;
  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
  if (!yuv420_image.chroma_data) {
    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
    yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;
    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
  }

  // gain map
  ultrahdr_metadata_struct metadata;
  strcpy(metadata.version, kJpegrVersion);
  ultrahdr_uncompressed_struct gainmap_image;
  ULTRAHDR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  ULTRAHDR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
  ultrahdr_compressed_struct compressed_map;
  compressed_map.data = jpeg_enc_obj_gm.getCompressedImagePtr();
  compressed_map.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  compressed_map.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  compressed_map.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;

  std::shared_ptr<DataStruct> icc =
      IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, yuv420_image.colorGamut);

  ultrahdr_uncompressed_struct yuv420_bt601_image = yuv420_image;
  unique_ptr<uint8_t[]> yuv_420_bt601_data;
  // Convert to bt601 YUV encoding for JPEG encode
  if (yuv420_image.colorGamut != ULTRAHDR_COLORGAMUT_P3) {
    const size_t yuv_420_bt601_luma_stride =
        ALIGNM(yuv420_image.width, JpegEncoderHelper::kCompressBatchSize);
    yuv_420_bt601_data =
        make_unique<uint8_t[]>(yuv_420_bt601_luma_stride * yuv420_image.height * 3 / 2);
    yuv420_bt601_image.data = yuv_420_bt601_data.get();
    yuv420_bt601_image.colorGamut = yuv420_image.colorGamut;
    yuv420_bt601_image.luma_stride = yuv_420_bt601_luma_stride;
    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_bt601_image.data);
    yuv420_bt601_image.chroma_data = data + yuv_420_bt601_luma_stride * yuv420_image.height;
    yuv420_bt601_image.chroma_stride = yuv_420_bt601_luma_stride >> 1;

    {
      // copy luma
      uint8_t* y_dst = reinterpret_cast<uint8_t*>(yuv420_bt601_image.data);
      uint8_t* y_src = reinterpret_cast<uint8_t*>(yuv420_image.data);
      if (yuv420_bt601_image.luma_stride == yuv420_image.luma_stride) {
        memcpy(y_dst, y_src, yuv420_bt601_image.luma_stride * yuv420_image.height);
      } else {
        for (size_t i = 0; i < yuv420_image.height; i++) {
          memcpy(y_dst, y_src, yuv420_image.width);
          if (yuv420_image.width != yuv420_bt601_image.luma_stride) {
            memset(y_dst + yuv420_image.width, 0,
                   yuv420_bt601_image.luma_stride - yuv420_image.width);
          }
          y_dst += yuv420_bt601_image.luma_stride;
          y_src += yuv420_image.luma_stride;
        }
      }
    }

    if (yuv420_bt601_image.chroma_stride == yuv420_image.chroma_stride) {
      // copy luma
      uint8_t* ch_dst = reinterpret_cast<uint8_t*>(yuv420_bt601_image.chroma_data);
      uint8_t* ch_src = reinterpret_cast<uint8_t*>(yuv420_image.chroma_data);
      memcpy(ch_dst, ch_src, yuv420_bt601_image.chroma_stride * yuv420_image.height);
    } else {
      // copy cb & cr
      uint8_t* cb_dst = reinterpret_cast<uint8_t*>(yuv420_bt601_image.chroma_data);
      uint8_t* cb_src = reinterpret_cast<uint8_t*>(yuv420_image.chroma_data);
      uint8_t* cr_dst = cb_dst + (yuv420_bt601_image.chroma_stride * yuv420_bt601_image.height / 2);
      uint8_t* cr_src = cb_src + (yuv420_image.chroma_stride * yuv420_image.height / 2);
      for (size_t i = 0; i < yuv420_image.height / 2; i++) {
        memcpy(cb_dst, cb_src, yuv420_image.width / 2);
        memcpy(cr_dst, cr_src, yuv420_image.width / 2);
        if (yuv420_bt601_image.width / 2 != yuv420_bt601_image.chroma_stride) {
          memset(cb_dst + yuv420_image.width / 2, 0,
                 yuv420_bt601_image.chroma_stride - yuv420_image.width / 2);
          memset(cr_dst + yuv420_image.width / 2, 0,
                 yuv420_bt601_image.chroma_stride - yuv420_image.width / 2);
        }
        cb_dst += yuv420_bt601_image.chroma_stride;
        cb_src += yuv420_image.chroma_stride;
        cr_dst += yuv420_bt601_image.chroma_stride;
        cr_src += yuv420_image.chroma_stride;
      }
    }
    ULTRAHDR_CHECK(
        convertYuv(&yuv420_bt601_image, yuv420_image.colorGamut, ULTRAHDR_COLORGAMUT_P3));
  }

  // compress 420 image
  JpegEncoderHelper jpeg_enc_obj_yuv420;
  if (!jpeg_enc_obj_yuv420.compressImage(
          reinterpret_cast<uint8_t*>(yuv420_bt601_image.data),
          reinterpret_cast<uint8_t*>(yuv420_bt601_image.chroma_data), yuv420_bt601_image.width,
          yuv420_bt601_image.height, yuv420_bt601_image.luma_stride,
          yuv420_bt601_image.chroma_stride, quality, icc->getData(), icc->getLength())) {
    return ERROR_UHDR_ENCODE_ERROR;
  }

  ultrahdr_compressed_struct jpeg;
  jpeg.data = jpeg_enc_obj_yuv420.getCompressedImagePtr();
  jpeg.length = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
  jpeg.maxLength = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
  jpeg.colorGamut = yuv420_image.colorGamut;

  // append gain map, no ICC since JPEG encode already did it
  ULTRAHDR_CHECK(appendGainMap(&jpeg, &compressed_map, exif, /* icc */ nullptr, /* icc size */ 0,
                               &metadata, dest));
  return UHDR_NO_ERROR;
}

/* Encode API-2 */
status_t JpegR::encodeJPEGR(ultrahdr_uncompressed_ptr p010_image_ptr,
                            ultrahdr_uncompressed_ptr yuv420_image_ptr,
                            ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                            ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest) {
  // validate input arguments
  if (yuv420_image_ptr == nullptr) {
    ALOGE("received nullptr for uncompressed 420 image");
    return ERROR_UHDR_BAD_PTR;
  }
  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed jpeg image");
    return ERROR_UHDR_BAD_PTR;
  }
  ULTRAHDR_CHECK(areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest))

  // clean up input structure for later usage
  ultrahdr_uncompressed_struct p010_image = *p010_image_ptr;
  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
  if (!p010_image.chroma_data) {
    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
    p010_image.chroma_stride = p010_image.luma_stride;
  }
  ultrahdr_uncompressed_struct yuv420_image = *yuv420_image_ptr;
  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
  if (!yuv420_image.chroma_data) {
    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
    yuv420_image.chroma_data = data + yuv420_image.luma_stride * p010_image.height;
    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
  }

  // gain map
  ultrahdr_metadata_struct metadata;
  strcpy(metadata.version, kJpegrVersion);
  ultrahdr_uncompressed_struct gainmap_image;
  ULTRAHDR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  ULTRAHDR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
  ultrahdr_compressed_struct gainmapjpg_image;
  gainmapjpg_image.data = jpeg_enc_obj_gm.getCompressedImagePtr();
  gainmapjpg_image.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  gainmapjpg_image.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  gainmapjpg_image.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;

  return encodeJPEGR(yuv420jpg_image_ptr, &gainmapjpg_image, &metadata, dest);
}

/* Encode API-3 */
status_t JpegR::encodeJPEGR(ultrahdr_uncompressed_ptr p010_image_ptr,
                            ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                            ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest) {
  // validate input arguments
  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed jpeg image");
    return ERROR_UHDR_BAD_PTR;
  }
  ULTRAHDR_CHECK(areInputArgumentsValid(p010_image_ptr, nullptr, hdr_tf, dest))

  // clean up input structure for later usage
  ultrahdr_uncompressed_struct p010_image = *p010_image_ptr;
  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
  if (!p010_image.chroma_data) {
    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
    p010_image.chroma_stride = p010_image.luma_stride;
  }

  // decode input jpeg, gamut is going to be bt601.
  JpegDecoderHelper jpeg_dec_obj_yuv420;
  if (!jpeg_dec_obj_yuv420.decompressImage(yuv420jpg_image_ptr->data,
                                           yuv420jpg_image_ptr->length)) {
    return ERROR_UHDR_DECODE_ERROR;
  }
  ultrahdr_uncompressed_struct yuv420_image{};
  yuv420_image.data = jpeg_dec_obj_yuv420.getDecompressedImagePtr();
  yuv420_image.width = jpeg_dec_obj_yuv420.getDecompressedImageWidth();
  yuv420_image.height = jpeg_dec_obj_yuv420.getDecompressedImageHeight();
  yuv420_image.colorGamut = yuv420jpg_image_ptr->colorGamut;
  yuv420_image.pixelFormat = ULTRAHDR_PIX_FMT_YUV420;
  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
  if (!yuv420_image.chroma_data) {
    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
    yuv420_image.chroma_data = data + yuv420_image.luma_stride * p010_image.height;
    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
  }

  if (p010_image_ptr->width != yuv420_image.width ||
      p010_image_ptr->height != yuv420_image.height) {
    return ERROR_UHDR_RESOLUTION_MISMATCH;
  }

  // gain map
  ultrahdr_metadata_struct metadata;
  strcpy(metadata.version, kJpegrVersion);
  ultrahdr_uncompressed_struct gainmap_image;
  ULTRAHDR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image,
                                 true /* sdr_is_601 */));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  ULTRAHDR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
  ultrahdr_compressed_struct gainmapjpg_image;
  gainmapjpg_image.data = jpeg_enc_obj_gm.getCompressedImagePtr();
  gainmapjpg_image.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  gainmapjpg_image.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  gainmapjpg_image.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;

  return encodeJPEGR(yuv420jpg_image_ptr, &gainmapjpg_image, &metadata, dest);
}

/* Encode API-4 */
status_t JpegR::encodeJPEGR(ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                            ultrahdr_compressed_ptr gainmapjpg_image_ptr,
                            ultrahdr_metadata_ptr metadata, ultrahdr_compressed_ptr dest) {
  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed jpeg image");
    return ERROR_UHDR_BAD_PTR;
  }
  if (gainmapjpg_image_ptr == nullptr || gainmapjpg_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed gain map");
    return ERROR_UHDR_BAD_PTR;
  }
  if (dest == nullptr || dest->data == nullptr) {
    ALOGE("received nullptr for destination");
    return ERROR_UHDR_BAD_PTR;
  }

  // We just want to check if ICC is present, so don't do a full decode. Note,
  // this doesn't verify that the ICC is valid.
  JpegDecoderHelper decoder;
  if (!decoder.getCompressedImageParameters(yuv420jpg_image_ptr->data,
                                            yuv420jpg_image_ptr->length)) {
    return ERROR_UHDR_DECODE_ERROR;
  }

  // Add ICC if not already present.
  if (decoder.getICCSize() > 0) {
    ULTRAHDR_CHECK(appendGainMap(yuv420jpg_image_ptr, gainmapjpg_image_ptr, /* exif */ nullptr,
                                 /* icc */ nullptr, /* icc size */ 0, metadata, dest));
  } else {
    std::shared_ptr<DataStruct> newIcc =
        IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, yuv420jpg_image_ptr->colorGamut);
    ULTRAHDR_CHECK(appendGainMap(yuv420jpg_image_ptr, gainmapjpg_image_ptr, /* exif */ nullptr,
                                 newIcc->getData(), newIcc->getLength(), metadata, dest));
  }

  return UHDR_NO_ERROR;
}

status_t JpegR::getJPEGRInfo(ultrahdr_compressed_ptr jpegr_image_ptr,
                             jr_info_ptr jpegr_image_info_ptr) {
  if (jpegr_image_ptr == nullptr || jpegr_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed jpegr image");
    return ERROR_UHDR_BAD_PTR;
  }
  if (jpegr_image_info_ptr == nullptr) {
    ALOGE("received nullptr for compressed jpegr info struct");
    return ERROR_UHDR_BAD_PTR;
  }

  ultrahdr_compressed_struct primary_image, gainmap_image;
  status_t status = extractPrimaryImageAndGainMap(jpegr_image_ptr, &primary_image, &gainmap_image);
  if (status != UHDR_NO_ERROR && status != ERROR_UHDR_GAIN_MAP_IMAGE_NOT_FOUND) {
    return status;
  }
  status = parseJpegInfo(&primary_image, jpegr_image_info_ptr->primaryImgInfo,
                         &jpegr_image_info_ptr->width, &jpegr_image_info_ptr->height);
  if (status != UHDR_NO_ERROR) {
    return status;
  }
  if (jpegr_image_info_ptr->gainmapImgInfo != nullptr) {
    status = parseJpegInfo(&gainmap_image, jpegr_image_info_ptr->gainmapImgInfo);
    if (status != UHDR_NO_ERROR) {
      return status;
    }
  }

  return status;
}

/* Decode API */
status_t JpegR::decodeJPEGR(ultrahdr_compressed_ptr jpegr_image_ptr, ultrahdr_uncompressed_ptr dest,
                            float max_display_boost, ultrahdr_exif_ptr exif,
                            ultrahdr_output_format output_format,
                            ultrahdr_uncompressed_ptr gainmap_image_ptr,
                            ultrahdr_metadata_ptr metadata) {
  if (jpegr_image_ptr == nullptr || jpegr_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed jpegr image");
    return ERROR_UHDR_BAD_PTR;
  }
  if (dest == nullptr || dest->data == nullptr) {
    ALOGE("received nullptr for dest image");
    return ERROR_UHDR_BAD_PTR;
  }
  if (max_display_boost < 1.0f) {
    ALOGE("received bad value for max_display_boost %f", max_display_boost);
    return ERROR_UHDR_INVALID_DISPLAY_BOOST;
  }
  if (exif != nullptr && exif->data == nullptr) {
    ALOGE("received nullptr address for exif data");
    return ERROR_UHDR_BAD_PTR;
  }
  if (output_format <= ULTRAHDR_OUTPUT_UNSPECIFIED || output_format > ULTRAHDR_OUTPUT_MAX) {
    ALOGE("received bad value for output format %d", output_format);
    return ERROR_UHDR_INVALID_OUTPUT_FORMAT;
  }

  ultrahdr_compressed_struct primary_jpeg_image, gainmap_jpeg_image;
  status_t status =
      extractPrimaryImageAndGainMap(jpegr_image_ptr, &primary_jpeg_image, &gainmap_jpeg_image);
  if (status != UHDR_NO_ERROR) {
    if (output_format != ULTRAHDR_OUTPUT_SDR || status != ERROR_UHDR_GAIN_MAP_IMAGE_NOT_FOUND) {
      ALOGE("received invalid compressed jpegr image");
      return status;
    }
  }

  JpegDecoderHelper jpeg_dec_obj_yuv420;
  if (!jpeg_dec_obj_yuv420.decompressImage(
          primary_jpeg_image.data, primary_jpeg_image.length,
          (output_format == ULTRAHDR_OUTPUT_SDR) ? DECODE_TO_RGBA : DECODE_TO_YCBCR)) {
    return ERROR_UHDR_DECODE_ERROR;
  }

  if (output_format == ULTRAHDR_OUTPUT_SDR) {
    if ((jpeg_dec_obj_yuv420.getDecompressedImageWidth() *
         jpeg_dec_obj_yuv420.getDecompressedImageHeight() * 4) >
        jpeg_dec_obj_yuv420.getDecompressedImageSize()) {
      return ERROR_UHDR_DECODE_ERROR;
    }
  } else {
    if ((jpeg_dec_obj_yuv420.getDecompressedImageWidth() *
         jpeg_dec_obj_yuv420.getDecompressedImageHeight() * 3 / 2) >
        jpeg_dec_obj_yuv420.getDecompressedImageSize()) {
      return ERROR_UHDR_DECODE_ERROR;
    }
  }

  if (exif != nullptr) {
    if (exif->data == nullptr) {
      return ERROR_UHDR_BAD_PTR;
    }
    if (exif->length < jpeg_dec_obj_yuv420.getEXIFSize()) {
      return ERROR_UHDR_BUFFER_TOO_SMALL;
    }
    memcpy(exif->data, jpeg_dec_obj_yuv420.getEXIFPtr(), jpeg_dec_obj_yuv420.getEXIFSize());
    exif->length = jpeg_dec_obj_yuv420.getEXIFSize();
  }

  if (output_format == ULTRAHDR_OUTPUT_SDR) {
    dest->width = jpeg_dec_obj_yuv420.getDecompressedImageWidth();
    dest->height = jpeg_dec_obj_yuv420.getDecompressedImageHeight();
    memcpy(dest->data, jpeg_dec_obj_yuv420.getDecompressedImagePtr(),
           dest->width * dest->height * 4);
    dest->colorGamut = IccHelper::readIccColorGamut(jpeg_dec_obj_yuv420.getICCPtr(),
                                                    jpeg_dec_obj_yuv420.getICCSize());
    dest->pixelFormat = ULTRAHDR_PIX_FMT_RGBA8888;
    dest->chroma_data = nullptr;
    dest->luma_stride = 0;
    dest->chroma_stride = 0;
    return UHDR_NO_ERROR;
  }

  JpegDecoderHelper jpeg_dec_obj_gm;
  if (!jpeg_dec_obj_gm.decompressImage(gainmap_jpeg_image.data, gainmap_jpeg_image.length)) {
    return ERROR_UHDR_DECODE_ERROR;
  }
  if ((jpeg_dec_obj_gm.getDecompressedImageWidth() * jpeg_dec_obj_gm.getDecompressedImageHeight()) >
      jpeg_dec_obj_gm.getDecompressedImageSize()) {
    return ERROR_UHDR_DECODE_ERROR;
  }

  ultrahdr_uncompressed_struct gainmap_image{};
  gainmap_image.data = jpeg_dec_obj_gm.getDecompressedImagePtr();
  gainmap_image.width = jpeg_dec_obj_gm.getDecompressedImageWidth();
  gainmap_image.height = jpeg_dec_obj_gm.getDecompressedImageHeight();

  if (gainmap_image_ptr != nullptr) {
    gainmap_image_ptr->width = gainmap_image.width;
    gainmap_image_ptr->height = gainmap_image.height;
    int size = gainmap_image_ptr->width * gainmap_image_ptr->height;
    gainmap_image_ptr->data = malloc(size);
    memcpy(gainmap_image_ptr->data, gainmap_image.data, size);
    gainmap_image_ptr->colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
    gainmap_image_ptr->pixelFormat = ULTRAHDR_PIX_FMT_MONOCHROME;
    gainmap_image_ptr->chroma_data = nullptr;
    gainmap_image_ptr->luma_stride = 0;
    gainmap_image_ptr->chroma_stride = 0;
  }

  ultrahdr_metadata_struct uhdr_metadata;
  if (!getMetadataFromXMP(static_cast<uint8_t*>(jpeg_dec_obj_gm.getXMPPtr()),
                          jpeg_dec_obj_gm.getXMPSize(), &uhdr_metadata)) {
    return ERROR_UHDR_METADATA_ERROR;
  }

  if (metadata != nullptr) {
    strcpy(metadata->version, uhdr_metadata.version);
    metadata->minContentBoost = uhdr_metadata.minContentBoost;
    metadata->maxContentBoost = uhdr_metadata.maxContentBoost;
    metadata->gamma = uhdr_metadata.gamma;
    metadata->offsetSdr = uhdr_metadata.offsetSdr;
    metadata->offsetHdr = uhdr_metadata.offsetHdr;
    metadata->hdrCapacityMin = uhdr_metadata.hdrCapacityMin;
    metadata->hdrCapacityMax = uhdr_metadata.hdrCapacityMax;
  }

  ultrahdr_uncompressed_struct yuv420_image;
  yuv420_image.data = jpeg_dec_obj_yuv420.getDecompressedImagePtr();
  yuv420_image.width = jpeg_dec_obj_yuv420.getDecompressedImageWidth();
  yuv420_image.height = jpeg_dec_obj_yuv420.getDecompressedImageHeight();
  yuv420_image.colorGamut = IccHelper::readIccColorGamut(jpeg_dec_obj_yuv420.getICCPtr(),
                                                         jpeg_dec_obj_yuv420.getICCSize());
  yuv420_image.pixelFormat = ULTRAHDR_PIX_FMT_YUV420;
  yuv420_image.luma_stride = yuv420_image.width;
  uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
  yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;
  yuv420_image.chroma_stride = yuv420_image.width >> 1;

  ULTRAHDR_CHECK(applyGainMap(&yuv420_image, &gainmap_image, &uhdr_metadata, output_format,
                              max_display_boost, dest));
  return UHDR_NO_ERROR;
}

status_t JpegR::compressGainMap(ultrahdr_uncompressed_ptr gainmap_image_ptr,
                                JpegEncoderHelper* jpeg_enc_obj_ptr) {
  if (gainmap_image_ptr == nullptr || jpeg_enc_obj_ptr == nullptr) {
    return ERROR_UHDR_BAD_PTR;
  }

  // Don't need to convert YUV to Bt601 since single channel
  if (!jpeg_enc_obj_ptr->compressImage(reinterpret_cast<uint8_t*>(gainmap_image_ptr->data), nullptr,
                                       gainmap_image_ptr->width, gainmap_image_ptr->height,
                                       gainmap_image_ptr->luma_stride, 0, kMapCompressQuality,
                                       nullptr, 0)) {
    return ERROR_UHDR_ENCODE_ERROR;
  }

  return UHDR_NO_ERROR;
}

const int kJobSzInRows = 16;
static_assert(kJobSzInRows > 0 && kJobSzInRows % kMapDimensionScaleFactor == 0,
              "align job size to kMapDimensionScaleFactor");

class JobQueue {
 public:
  bool dequeueJob(size_t& rowStart, size_t& rowEnd);
  void enqueueJob(size_t rowStart, size_t rowEnd);
  void markQueueForEnd();
  void reset();

 private:
  bool mQueuedAllJobs = false;
  std::deque<std::tuple<size_t, size_t>> mJobs;
  std::mutex mMutex;
  std::condition_variable mCv;
};

bool JobQueue::dequeueJob(size_t& rowStart, size_t& rowEnd) {
  std::unique_lock<std::mutex> lock{mMutex};
  while (true) {
    if (mJobs.empty()) {
      if (mQueuedAllJobs) {
        return false;
      } else {
        mCv.wait_for(lock, std::chrono::milliseconds(100));
      }
    } else {
      auto it = mJobs.begin();
      rowStart = std::get<0>(*it);
      rowEnd = std::get<1>(*it);
      mJobs.erase(it);
      return true;
    }
  }
  return false;
}

void JobQueue::enqueueJob(size_t rowStart, size_t rowEnd) {
  std::unique_lock<std::mutex> lock{mMutex};
  mJobs.push_back(std::make_tuple(rowStart, rowEnd));
  lock.unlock();
  mCv.notify_one();
}

void JobQueue::markQueueForEnd() {
  std::unique_lock<std::mutex> lock{mMutex};
  mQueuedAllJobs = true;
  lock.unlock();
  mCv.notify_all();
}

void JobQueue::reset() {
  std::unique_lock<std::mutex> lock{mMutex};
  mJobs.clear();
  mQueuedAllJobs = false;
}

status_t JpegR::generateGainMap(ultrahdr_uncompressed_ptr yuv420_image_ptr,
                                ultrahdr_uncompressed_ptr p010_image_ptr,
                                ultrahdr_transfer_function hdr_tf, ultrahdr_metadata_ptr metadata,
                                ultrahdr_uncompressed_ptr dest, bool sdr_is_601) {
  if (yuv420_image_ptr == nullptr || p010_image_ptr == nullptr || metadata == nullptr ||
      dest == nullptr || yuv420_image_ptr->data == nullptr ||
      yuv420_image_ptr->chroma_data == nullptr || p010_image_ptr->data == nullptr ||
      p010_image_ptr->chroma_data == nullptr) {
    return ERROR_UHDR_BAD_PTR;
  }
  if (yuv420_image_ptr->width != p010_image_ptr->width ||
      yuv420_image_ptr->height != p010_image_ptr->height) {
    return ERROR_UHDR_RESOLUTION_MISMATCH;
  }
  if (yuv420_image_ptr->colorGamut == ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
      p010_image_ptr->colorGamut == ULTRAHDR_COLORGAMUT_UNSPECIFIED) {
    return ERROR_UHDR_INVALID_COLORGAMUT;
  }

  size_t image_width = yuv420_image_ptr->width;
  size_t image_height = yuv420_image_ptr->height;
  size_t map_width = image_width / kMapDimensionScaleFactor;
  size_t map_height = image_height / kMapDimensionScaleFactor;

  dest->data = new uint8_t[map_width * map_height];
  dest->width = map_width;
  dest->height = map_height;
  dest->colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  dest->pixelFormat = ULTRAHDR_PIX_FMT_MONOCHROME;
  dest->luma_stride = map_width;
  dest->chroma_data = nullptr;
  dest->chroma_stride = 0;
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(dest->data));

  ColorTransformFn hdrInvOetf = nullptr;
  float hdr_white_nits;
  switch (hdr_tf) {
    case ULTRAHDR_TF_LINEAR:
      hdrInvOetf = identityConversion;
      // Note: this will produce clipping if the input exceeds kHlgMaxNits.
      // TODO: TF LINEAR will be deprecated.
      hdr_white_nits = kHlgMaxNits;
      break;
    case ULTRAHDR_TF_HLG:
#if USE_HLG_INVOETF_LUT
      hdrInvOetf = hlgInvOetfLUT;
#else
      hdrInvOetf = hlgInvOetf;
#endif
      hdr_white_nits = kHlgMaxNits;
      break;
    case ULTRAHDR_TF_PQ:
#if USE_PQ_INVOETF_LUT
      hdrInvOetf = pqInvOetfLUT;
#else
      hdrInvOetf = pqInvOetf;
#endif
      hdr_white_nits = kPqMaxNits;
      break;
    default:
      // Should be impossible to hit after input validation.
      return ERROR_UHDR_INVALID_TRANS_FUNC;
  }

  metadata->maxContentBoost = hdr_white_nits / kSdrWhiteNits;
  metadata->minContentBoost = 1.0f;
  metadata->gamma = 1.0f;
  metadata->offsetSdr = 0.0f;
  metadata->offsetHdr = 0.0f;
  metadata->hdrCapacityMin = 1.0f;
  metadata->hdrCapacityMax = metadata->maxContentBoost;

  float log2MinBoost = log2(metadata->minContentBoost);
  float log2MaxBoost = log2(metadata->maxContentBoost);

  ColorTransformFn hdrGamutConversionFn =
      getHdrConversionFn(yuv420_image_ptr->colorGamut, p010_image_ptr->colorGamut);

  ColorCalculationFn luminanceFn = nullptr;
  ColorTransformFn sdrYuvToRgbFn = nullptr;
  switch (yuv420_image_ptr->colorGamut) {
    case ULTRAHDR_COLORGAMUT_BT709:
      luminanceFn = srgbLuminance;
      sdrYuvToRgbFn = srgbYuvToRgb;
      break;
    case ULTRAHDR_COLORGAMUT_P3:
      luminanceFn = p3Luminance;
      sdrYuvToRgbFn = p3YuvToRgb;
      break;
    case ULTRAHDR_COLORGAMUT_BT2100:
      luminanceFn = bt2100Luminance;
      sdrYuvToRgbFn = bt2100YuvToRgb;
      break;
    case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
      // Should be impossible to hit after input validation.
      return ERROR_UHDR_INVALID_COLORGAMUT;
  }
  if (sdr_is_601) {
    sdrYuvToRgbFn = p3YuvToRgb;
  }

  ColorTransformFn hdrYuvToRgbFn = nullptr;
  switch (p010_image_ptr->colorGamut) {
    case ULTRAHDR_COLORGAMUT_BT709:
      hdrYuvToRgbFn = srgbYuvToRgb;
      break;
    case ULTRAHDR_COLORGAMUT_P3:
      hdrYuvToRgbFn = p3YuvToRgb;
      break;
    case ULTRAHDR_COLORGAMUT_BT2100:
      hdrYuvToRgbFn = bt2100YuvToRgb;
      break;
    case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
      // Should be impossible to hit after input validation.
      return ERROR_UHDR_INVALID_COLORGAMUT;
  }

  const int threads = (std::min)(GetCPUCoreCount(), 4);
  size_t rowStep = threads == 1 ? image_height : kJobSzInRows;
  JobQueue jobQueue;

  std::function<void()> generateMap = [yuv420_image_ptr, p010_image_ptr, metadata, dest, hdrInvOetf,
                                       hdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn,
                                       hdrYuvToRgbFn, hdr_white_nits, log2MinBoost, log2MaxBoost,
                                       &jobQueue]() -> void {
    size_t rowStart, rowEnd;
    while (jobQueue.dequeueJob(rowStart, rowEnd)) {
      for (size_t y = rowStart; y < rowEnd; ++y) {
        for (size_t x = 0; x < dest->width; ++x) {
          Color sdr_yuv_gamma = sampleYuv420(yuv420_image_ptr, kMapDimensionScaleFactor, x, y);
          Color sdr_rgb_gamma = sdrYuvToRgbFn(sdr_yuv_gamma);
          // We are assuming the SDR input is always sRGB transfer.
#if USE_SRGB_INVOETF_LUT
          Color sdr_rgb = srgbInvOetfLUT(sdr_rgb_gamma);
#else
          Color sdr_rgb = srgbInvOetf(sdr_rgb_gamma);
#endif
          float sdr_y_nits = luminanceFn(sdr_rgb) * kSdrWhiteNits;

          Color hdr_yuv_gamma = sampleP010(p010_image_ptr, kMapDimensionScaleFactor, x, y);
          Color hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
          Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
          hdr_rgb = hdrGamutConversionFn(hdr_rgb);
          float hdr_y_nits = luminanceFn(hdr_rgb) * hdr_white_nits;

          size_t pixel_idx = x + y * dest->width;
          reinterpret_cast<uint8_t*>(dest->data)[pixel_idx] =
              encodeGain(sdr_y_nits, hdr_y_nits, metadata, log2MinBoost, log2MaxBoost);
        }
      }
    }
  };

  // generate map
  std::vector<std::thread> workers;
  for (int th = 0; th < threads - 1; th++) {
    workers.push_back(std::thread(generateMap));
  }

  rowStep = (threads == 1 ? image_height : kJobSzInRows) / kMapDimensionScaleFactor;
  for (size_t rowStart = 0; rowStart < map_height;) {
    size_t rowEnd = (std::min)(rowStart + rowStep, map_height);
    jobQueue.enqueueJob(rowStart, rowEnd);
    rowStart = rowEnd;
  }
  jobQueue.markQueueForEnd();
  generateMap();
  std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });

  map_data.release();
  return UHDR_NO_ERROR;
}

status_t JpegR::applyGainMap(ultrahdr_uncompressed_ptr yuv420_image_ptr,
                             ultrahdr_uncompressed_ptr gainmap_image_ptr,
                             ultrahdr_metadata_ptr metadata, ultrahdr_output_format output_format,
                             float max_display_boost, ultrahdr_uncompressed_ptr dest) {
  if (yuv420_image_ptr == nullptr || gainmap_image_ptr == nullptr || metadata == nullptr ||
      dest == nullptr || dest->data == nullptr || yuv420_image_ptr->data == nullptr ||
      yuv420_image_ptr->chroma_data == nullptr || gainmap_image_ptr->data == nullptr) {
    return ERROR_UHDR_BAD_PTR;
  }
  if (strcmp(metadata->version, kJpegrVersion)) {
    ALOGE("Unsupported metadata version, metadata version does not match %s", kJpegrVersion);
    return ERROR_UHDR_BAD_METADATA;
  }
  if (metadata->gamma != 1.0f) {
    ALOGE("Unsupported metadata gamma: %f", metadata->gamma);
    return ERROR_UHDR_BAD_METADATA;
  }
  if (metadata->offsetSdr != 0.0f || metadata->offsetHdr != 0.0f) {
    ALOGE("Unsupported metadata offset sdr, hdr: %f, %f", metadata->offsetSdr, metadata->offsetHdr);
    return ERROR_UHDR_BAD_METADATA;
  }
  if (metadata->hdrCapacityMin != metadata->minContentBoost ||
      metadata->hdrCapacityMax != metadata->maxContentBoost) {
    ALOGE("Unsupported metadata hdr capacity min, max: %f, %f", metadata->hdrCapacityMin,
          metadata->hdrCapacityMax);
    return ERROR_UHDR_BAD_METADATA;
  }

  if (yuv420_image_ptr->width % gainmap_image_ptr->width != 0 ||
      yuv420_image_ptr->height % gainmap_image_ptr->height != 0) {
    ALOGE(
        "gain map dimensions scale factor value is not an integer, primary image resolution is "
        "%zux%zu, received gain map resolution is %zux%zu",
        yuv420_image_ptr->width, yuv420_image_ptr->height, gainmap_image_ptr->width,
        gainmap_image_ptr->height);
    return ERROR_UHDR_UNSUPPORTED_MAP_SCALE_FACTOR;
  }

  if (yuv420_image_ptr->width * gainmap_image_ptr->height !=
      yuv420_image_ptr->height * gainmap_image_ptr->width) {
    ALOGE(
        "gain map dimensions scale factor values for height and width are different, \n primary "
        "image resolution is %zux%zu, received gain map resolution is %zux%zu",
        yuv420_image_ptr->width, yuv420_image_ptr->height, gainmap_image_ptr->width,
        gainmap_image_ptr->height);
    return ERROR_UHDR_UNSUPPORTED_MAP_SCALE_FACTOR;
  }
  // TODO: Currently map_scale_factor is of type size_t, but it could be changed to a float
  // later.
  size_t map_scale_factor = yuv420_image_ptr->width / gainmap_image_ptr->width;

  dest->width = yuv420_image_ptr->width;
  dest->height = yuv420_image_ptr->height;
  dest->colorGamut = yuv420_image_ptr->colorGamut;
  if (output_format == ULTRAHDR_OUTPUT_HDR_LINEAR) {
    dest->pixelFormat = ULTRAHDR_PIX_FMT_RGBAF16;
  } else if (output_format == ULTRAHDR_OUTPUT_HDR_PQ || output_format == ULTRAHDR_OUTPUT_HDR_HLG) {
    dest->pixelFormat = ULTRAHDR_PIX_FMT_RGBA1010102;
  } else {
    dest->pixelFormat = ULTRAHDR_PIX_FMT_UNSPECIFIED;
  }
  dest->chroma_data = nullptr;
  dest->luma_stride = 0;
  dest->chroma_stride = 0;

  ShepardsIDW idwTable(map_scale_factor);
  float display_boost = (std::min)(max_display_boost, metadata->maxContentBoost);
  GainLUT gainLUT(metadata, display_boost);

  JobQueue jobQueue;
  std::function<void()> applyRecMap = [yuv420_image_ptr, gainmap_image_ptr, dest, &jobQueue,
                                       &idwTable, output_format, &gainLUT, display_boost,
                                       map_scale_factor]() -> void {
    size_t width = yuv420_image_ptr->width;

    size_t rowStart, rowEnd;
    while (jobQueue.dequeueJob(rowStart, rowEnd)) {
      for (size_t y = rowStart; y < rowEnd; ++y) {
        for (size_t x = 0; x < width; ++x) {
          Color yuv_gamma_sdr = getYuv420Pixel(yuv420_image_ptr, x, y);
          // Assuming the sdr image is a decoded JPEG, we should always use Rec.601 YUV coefficients
          Color rgb_gamma_sdr = p3YuvToRgb(yuv_gamma_sdr);
          // We are assuming the SDR base image is always sRGB transfer.
#if USE_SRGB_INVOETF_LUT
          Color rgb_sdr = srgbInvOetfLUT(rgb_gamma_sdr);
#else
          Color rgb_sdr = srgbInvOetf(rgb_gamma_sdr);
#endif
          float gain;
          // TODO: If map_scale_factor is guaranteed to be an integer, then remove the following.
          if (map_scale_factor != floorf(map_scale_factor)) {
            gain = sampleMap(gainmap_image_ptr, map_scale_factor, x, y);
          } else {
            gain = sampleMap(gainmap_image_ptr, map_scale_factor, x, y, idwTable);
          }

#if USE_APPLY_GAIN_LUT
          Color rgb_hdr = applyGainLUT(rgb_sdr, gain, gainLUT);
#else
          Color rgb_hdr = applyGain(rgb_sdr, gain, metadata, display_boost);
#endif
          rgb_hdr = rgb_hdr / display_boost;
          size_t pixel_idx = x + y * width;

          switch (output_format) {
            case ULTRAHDR_OUTPUT_HDR_LINEAR: {
              uint64_t rgba_f16 = colorToRgbaF16(rgb_hdr);
              reinterpret_cast<uint64_t*>(dest->data)[pixel_idx] = rgba_f16;
              break;
            }
            case ULTRAHDR_OUTPUT_HDR_HLG: {
#if USE_HLG_OETF_LUT
              ColorTransformFn hdrOetf = hlgOetfLUT;
#else
              ColorTransformFn hdrOetf = hlgOetf;
#endif
              Color rgb_gamma_hdr = hdrOetf(rgb_hdr);
              uint32_t rgba_1010102 = colorToRgba1010102(rgb_gamma_hdr);
              reinterpret_cast<uint32_t*>(dest->data)[pixel_idx] = rgba_1010102;
              break;
            }
            case ULTRAHDR_OUTPUT_HDR_PQ: {
#if USE_PQ_OETF_LUT
              ColorTransformFn hdrOetf = pqOetfLUT;
#else
              ColorTransformFn hdrOetf = pqOetf;
#endif
              Color rgb_gamma_hdr = hdrOetf(rgb_hdr);
              uint32_t rgba_1010102 = colorToRgba1010102(rgb_gamma_hdr);
              reinterpret_cast<uint32_t*>(dest->data)[pixel_idx] = rgba_1010102;
              break;
            }
            default: {
            }
              // Should be impossible to hit after input validation.
          }
        }
      }
    }
  };

  const int threads = (std::min)(GetCPUCoreCount(), 4);
  std::vector<std::thread> workers;
  for (int th = 0; th < threads - 1; th++) {
    workers.push_back(std::thread(applyRecMap));
  }
  const int rowStep = threads == 1 ? yuv420_image_ptr->height : map_scale_factor;
  for (size_t rowStart = 0; rowStart < yuv420_image_ptr->height;) {
    int rowEnd = (std::min)(rowStart + rowStep, yuv420_image_ptr->height);
    jobQueue.enqueueJob(rowStart, rowEnd);
    rowStart = rowEnd;
  }
  jobQueue.markQueueForEnd();
  applyRecMap();
  std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
  return UHDR_NO_ERROR;
}

status_t JpegR::extractPrimaryImageAndGainMap(ultrahdr_compressed_ptr jpegr_image_ptr,
                                              ultrahdr_compressed_ptr primary_jpg_image_ptr,
                                              ultrahdr_compressed_ptr gainmap_jpg_image_ptr) {
  if (jpegr_image_ptr == nullptr) {
    return ERROR_UHDR_BAD_PTR;
  }

  MessageHandler msg_handler;
  msg_handler.SetMessageWriter(make_unique<AlogMessageWriter>(AlogMessageWriter()));
  std::shared_ptr<DataSegment> seg = DataSegment::Create(
      DataRange(0, jpegr_image_ptr->length), static_cast<const uint8_t*>(jpegr_image_ptr->data),
      DataSegment::BufferDispositionPolicy::kDontDelete);
  DataSegmentDataSource data_source(seg);
  JpegInfoBuilder jpeg_info_builder;
  jpeg_info_builder.SetImageLimit(2);
  JpegScanner jpeg_scanner(&msg_handler);
  jpeg_scanner.Run(&data_source, &jpeg_info_builder);
  data_source.Reset();

  if (jpeg_scanner.HasError()) {
    return UHDR_UNKNOWN_ERROR;
  }

  const auto& jpeg_info = jpeg_info_builder.GetInfo();
  const auto& image_ranges = jpeg_info.GetImageRanges();

  if (image_ranges.empty()) {
    return ERROR_UHDR_NO_IMAGES_FOUND;
  }

  if (primary_jpg_image_ptr != nullptr) {
    primary_jpg_image_ptr->data =
        static_cast<uint8_t*>(jpegr_image_ptr->data) + image_ranges[0].GetBegin();
    primary_jpg_image_ptr->length = image_ranges[0].GetLength();
  }

  if (image_ranges.size() == 1) {
    return ERROR_UHDR_GAIN_MAP_IMAGE_NOT_FOUND;
  }

  if (gainmap_jpg_image_ptr != nullptr) {
    gainmap_jpg_image_ptr->data =
        static_cast<uint8_t*>(jpegr_image_ptr->data) + image_ranges[1].GetBegin();
    gainmap_jpg_image_ptr->length = image_ranges[1].GetLength();
  }

  // TODO: choose primary image and gain map image carefully
  if (image_ranges.size() > 2) {
    ALOGW("Number of jpeg images present %d, primary, gain map images may not be correctly chosen",
          (int)image_ranges.size());
  }

  return UHDR_NO_ERROR;
}

status_t JpegR::parseJpegInfo(ultrahdr_compressed_ptr jpeg_image_ptr,
                              j_info_ptr jpeg_image_info_ptr, size_t* img_width,
                              size_t* img_height) {
  JpegDecoderHelper jpeg_dec_obj;
  if (!jpeg_dec_obj.getCompressedImageParameters(jpeg_image_ptr->data, jpeg_image_ptr->length)) {
    return ERROR_UHDR_DECODE_ERROR;
  }
  size_t imgWidth, imgHeight;
  imgWidth = jpeg_dec_obj.getDecompressedImageWidth();
  imgHeight = jpeg_dec_obj.getDecompressedImageHeight();

  if (jpeg_image_info_ptr != nullptr) {
    jpeg_image_info_ptr->width = imgWidth;
    jpeg_image_info_ptr->height = imgHeight;
    jpeg_image_info_ptr->imgData.resize(jpeg_image_ptr->length, 0);
    memcpy(static_cast<void*>(jpeg_image_info_ptr->imgData.data()), jpeg_image_ptr->data,
           jpeg_image_ptr->length);
    if (jpeg_dec_obj.getICCSize() != 0) {
      jpeg_image_info_ptr->iccData.resize(jpeg_dec_obj.getICCSize(), 0);
      memcpy(static_cast<void*>(jpeg_image_info_ptr->iccData.data()), jpeg_dec_obj.getICCPtr(),
             jpeg_dec_obj.getICCSize());
    }
    if (jpeg_dec_obj.getEXIFSize() != 0) {
      jpeg_image_info_ptr->exifData.resize(jpeg_dec_obj.getEXIFSize(), 0);
      memcpy(static_cast<void*>(jpeg_image_info_ptr->exifData.data()), jpeg_dec_obj.getEXIFPtr(),
             jpeg_dec_obj.getEXIFSize());
    }
    if (jpeg_dec_obj.getXMPSize() != 0) {
      jpeg_image_info_ptr->xmpData.resize(jpeg_dec_obj.getXMPSize(), 0);
      memcpy(static_cast<void*>(jpeg_image_info_ptr->xmpData.data()), jpeg_dec_obj.getXMPPtr(),
             jpeg_dec_obj.getXMPSize());
    }
  }
  if (img_width != nullptr && img_height != nullptr) {
    *img_width = imgWidth;
    *img_height = imgHeight;
  }
  return UHDR_NO_ERROR;
}

// JPEG/R structure:
// SOI (ff d8)
//
// (Optional, if EXIF package is from outside (Encode API-0 API-1), or if EXIF package presents
// in the JPEG input (Encode API-2, API-3, API-4))
// APP1 (ff e1)
// 2 bytes of length (2 + length of exif package)
// EXIF package (this includes the first two bytes representing the package length)
//
// (Required, XMP package) APP1 (ff e1)
// 2 bytes of length (2 + 29 + length of xmp package)
// name space ("http://ns.adobe.com/xap/1.0/\0")
// XMP
//
// (Required, MPF package) APP2 (ff e2)
// 2 bytes of length
// MPF
//
// (Required) primary image (without the first two bytes (SOI) and EXIF, may have other packages)
//
// SOI (ff d8)
//
// (Required, XMP package) APP1 (ff e1)
// 2 bytes of length (2 + 29 + length of xmp package)
// name space ("http://ns.adobe.com/xap/1.0/\0")
// XMP
//
// (Required) secondary image (the gain map, without the first two bytes (SOI))
//
// Metadata versions we are using:
// ECMA TR-98 for JFIF marker
// Exif 2.2 spec for EXIF marker
// Adobe XMP spec part 3 for XMP marker
// ICC v4.3 spec for ICC
status_t JpegR::appendGainMap(ultrahdr_compressed_ptr primary_jpg_image_ptr,
                              ultrahdr_compressed_ptr gainmap_jpg_image_ptr,
                              ultrahdr_exif_ptr pExif, void* pIcc, size_t icc_size,
                              ultrahdr_metadata_ptr metadata, ultrahdr_compressed_ptr dest) {
  if (primary_jpg_image_ptr == nullptr || gainmap_jpg_image_ptr == nullptr || metadata == nullptr ||
      dest == nullptr) {
    return ERROR_UHDR_BAD_PTR;
  }
  if (strcmp(metadata->version, kJpegrVersion)) {
    ALOGE("Unsupported metadata version, metadata version does not match %s", kJpegrVersion);
    return ERROR_UHDR_BAD_METADATA;
  }
  if (metadata->maxContentBoost < metadata->minContentBoost) {
    ALOGE("received bad value for content boost min %f, max %f", metadata->minContentBoost,
          metadata->maxContentBoost);
    return ERROR_UHDR_BAD_METADATA;
  }
  if (metadata->hdrCapacityMax < metadata->hdrCapacityMin || metadata->hdrCapacityMin < 1.0f) {
    ALOGE("received bad value for hdr capacity min %f, max %f", metadata->hdrCapacityMin,
          metadata->hdrCapacityMax);
    return ERROR_UHDR_BAD_METADATA;
  }
  if (metadata->offsetSdr < 0.0f || metadata->offsetHdr < 0.0f) {
    ALOGE("received bad value for offset sdr %f, hdr %f", metadata->offsetSdr, metadata->offsetHdr);
    return ERROR_UHDR_BAD_METADATA;
  }
  if (metadata->gamma <= 0.0f) {
    ALOGE("received bad value for gamma %f", metadata->gamma);
    return ERROR_UHDR_BAD_METADATA;
  }

  const string nameSpace = "http://ns.adobe.com/xap/1.0/";
  const int nameSpaceLength = nameSpace.size() + 1;  // need to count the null terminator

  // calculate secondary image length first, because the length will be written into the primary
  // image xmp
  const string xmp_secondary = generateXmpForSecondaryImage(*metadata);
  // xmp_secondary_length = 2 bytes representing the length of the package +
  //  + nameSpaceLength = 29 bytes length
  //  + length of xmp packet = xmp_secondary.size()
  const int xmp_secondary_length = 2 + nameSpaceLength + xmp_secondary.size();
  const int secondary_image_size = 2 /* 2 bytes length of APP1 sign */
                                   + xmp_secondary_length + gainmap_jpg_image_ptr->length;
  // primary image
  const string xmp_primary = generateXmpForPrimaryImage(secondary_image_size, *metadata);
  // same as primary
  const int xmp_primary_length = 2 + nameSpaceLength + xmp_primary.size();

  // Check if EXIF package presents in the JPEG input.
  // If so, extract and remove the EXIF package.
  JpegDecoderHelper decoder;
  if (!decoder.extractEXIF(primary_jpg_image_ptr->data, primary_jpg_image_ptr->length)) {
    return ERROR_UHDR_DECODE_ERROR;
  }
  ultrahdr_exif_struct exif_from_jpg;
  exif_from_jpg.data = nullptr;
  exif_from_jpg.length = 0;
  ultrahdr_compressed_struct new_jpg_image;
  new_jpg_image.data = nullptr;
  new_jpg_image.length = 0;
  new_jpg_image.maxLength = 0;
  new_jpg_image.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  std::unique_ptr<uint8_t[]> dest_data;
  if (decoder.getEXIFPos() >= 0) {
    if (pExif != nullptr) {
      ALOGE("received EXIF from outside while the primary image already contains EXIF");
      return ERROR_UHDR_MULTIPLE_EXIFS_RECEIVED;
    }
    copyJpegWithoutExif(&new_jpg_image, primary_jpg_image_ptr, decoder.getEXIFPos(),
                        decoder.getEXIFSize());
    dest_data.reset(reinterpret_cast<uint8_t*>(new_jpg_image.data));
    exif_from_jpg.data = decoder.getEXIFPtr();
    exif_from_jpg.length = decoder.getEXIFSize();
    pExif = &exif_from_jpg;
  }

  ultrahdr_compressed_ptr final_primary_jpg_image_ptr =
      new_jpg_image.length == 0 ? primary_jpg_image_ptr : &new_jpg_image;

  int pos = 0;
  // Begin primary image
  // Write SOI
  ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
  ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kSOI, 1, pos));

  // Write EXIF
  if (pExif != nullptr) {
    const int length = 2 + pExif->length;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &lengthH, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &lengthL, 1, pos));
    ULTRAHDR_CHECK(Write(dest, pExif->data, pExif->length, pos));
  }

  // Prepare and write XMP
  {
    const int length = xmp_primary_length;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &lengthH, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &lengthL, 1, pos));
    ULTRAHDR_CHECK(Write(dest, (void*)nameSpace.c_str(), nameSpaceLength, pos));
    ULTRAHDR_CHECK(Write(dest, (void*)xmp_primary.c_str(), xmp_primary.size(), pos));
  }

  // Write ICC
  if (pIcc != nullptr && icc_size > 0) {
    const int length = icc_size + 2;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &lengthH, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &lengthL, 1, pos));
    ULTRAHDR_CHECK(Write(dest, pIcc, icc_size, pos));
  }

  // Prepare and write MPF
  {
    const int length = 2 + calculateMpfSize();
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    int primary_image_size = pos + length + final_primary_jpg_image_ptr->length;
    // between APP2 + package size + signature
    // ff e2 00 58 4d 50 46 00
    // 2 + 2 + 4 = 8 (bytes)
    // and ff d8 sign of the secondary image
    int secondary_image_offset = primary_image_size - pos - 8;
    std::shared_ptr<DataStruct> mpf = generateMpf(primary_image_size, 0, /* primary_image_offset */
                                                  secondary_image_size, secondary_image_offset);
    ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &lengthH, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &lengthL, 1, pos));
    ULTRAHDR_CHECK(Write(dest, (void*)mpf->getData(), mpf->getLength(), pos));
  }

  // Write primary image
  ULTRAHDR_CHECK(Write(dest, (uint8_t*)final_primary_jpg_image_ptr->data + 2,
                       final_primary_jpg_image_ptr->length - 2, pos));
  // Finish primary image

  // Begin secondary image (gain map)
  // Write SOI
  ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
  ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kSOI, 1, pos));

  // Prepare and write XMP
  {
    const int length = xmp_secondary_length;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &lengthH, 1, pos));
    ULTRAHDR_CHECK(Write(dest, &lengthL, 1, pos));
    ULTRAHDR_CHECK(Write(dest, (void*)nameSpace.c_str(), nameSpaceLength, pos));
    ULTRAHDR_CHECK(Write(dest, (void*)xmp_secondary.c_str(), xmp_secondary.size(), pos));
  }

  // Write secondary image
  ULTRAHDR_CHECK(Write(dest, (uint8_t*)gainmap_jpg_image_ptr->data + 2,
                       gainmap_jpg_image_ptr->length - 2, pos));

  // Set back length
  dest->length = pos;

  // Done!
  return UHDR_NO_ERROR;
}

status_t JpegR::toneMap(ultrahdr_uncompressed_ptr src, ultrahdr_uncompressed_ptr dest) {
  if (src == nullptr || dest == nullptr) {
    return ERROR_UHDR_BAD_PTR;
  }
  if (src->width != dest->width || src->height != dest->height) {
    return ERROR_UHDR_RESOLUTION_MISMATCH;
  }
  uint16_t* src_y_data = reinterpret_cast<uint16_t*>(src->data);
  uint8_t* dst_y_data = reinterpret_cast<uint8_t*>(dest->data);
  for (size_t y = 0; y < src->height; ++y) {
    uint16_t* src_y_row = src_y_data + y * src->luma_stride;
    uint8_t* dst_y_row = dst_y_data + y * dest->luma_stride;
    for (size_t x = 0; x < src->width; ++x) {
      uint16_t y_uint = src_y_row[x] >> 6;
      dst_y_row[x] = static_cast<uint8_t>((y_uint >> 2) & 0xff);
    }
    if (dest->width != dest->luma_stride) {
      memset(dst_y_row + dest->width, 0, dest->luma_stride - dest->width);
    }
  }
  uint16_t* src_uv_data = reinterpret_cast<uint16_t*>(src->chroma_data);
  uint8_t* dst_u_data = reinterpret_cast<uint8_t*>(dest->chroma_data);
  size_t dst_v_offset = (dest->chroma_stride * dest->height / 2);
  uint8_t* dst_v_data = dst_u_data + dst_v_offset;
  for (size_t y = 0; y < src->height / 2; ++y) {
    uint16_t* src_uv_row = src_uv_data + y * src->chroma_stride;
    uint8_t* dst_u_row = dst_u_data + y * dest->chroma_stride;
    uint8_t* dst_v_row = dst_v_data + y * dest->chroma_stride;
    for (size_t x = 0; x < src->width / 2; ++x) {
      uint16_t u_uint = src_uv_row[x << 1] >> 6;
      uint16_t v_uint = src_uv_row[(x << 1) + 1] >> 6;
      dst_u_row[x] = static_cast<uint8_t>((u_uint >> 2) & 0xff);
      dst_v_row[x] = static_cast<uint8_t>((v_uint >> 2) & 0xff);
    }
    if (dest->width / 2 != dest->chroma_stride) {
      memset(dst_u_row + dest->width / 2, 0, dest->chroma_stride - dest->width / 2);
      memset(dst_v_row + dest->width / 2, 0, dest->chroma_stride - dest->width / 2);
    }
  }
  dest->colorGamut = src->colorGamut;
  return UHDR_NO_ERROR;
}

status_t JpegR::convertYuv(ultrahdr_uncompressed_ptr image, ultrahdr_color_gamut src_encoding,
                           ultrahdr_color_gamut dest_encoding) {
  if (image == nullptr) {
    return ERROR_UHDR_BAD_PTR;
  }
  if (src_encoding == ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
      dest_encoding == ULTRAHDR_COLORGAMUT_UNSPECIFIED) {
    return ERROR_UHDR_INVALID_COLORGAMUT;
  }

  ColorTransformFn conversionFn = nullptr;
  switch (src_encoding) {
    case ULTRAHDR_COLORGAMUT_BT709:
      switch (dest_encoding) {
        case ULTRAHDR_COLORGAMUT_BT709:
          return UHDR_NO_ERROR;
        case ULTRAHDR_COLORGAMUT_P3:
          conversionFn = yuv709To601;
          break;
        case ULTRAHDR_COLORGAMUT_BT2100:
          conversionFn = yuv709To2100;
          break;
        default:
          // Should be impossible to hit after input validation
          return ERROR_UHDR_INVALID_COLORGAMUT;
      }
      break;
    case ULTRAHDR_COLORGAMUT_P3:
      switch (dest_encoding) {
        case ULTRAHDR_COLORGAMUT_BT709:
          conversionFn = yuv601To709;
          break;
        case ULTRAHDR_COLORGAMUT_P3:
          return UHDR_NO_ERROR;
        case ULTRAHDR_COLORGAMUT_BT2100:
          conversionFn = yuv601To2100;
          break;
        default:
          // Should be impossible to hit after input validation
          return ERROR_UHDR_INVALID_COLORGAMUT;
      }
      break;
    case ULTRAHDR_COLORGAMUT_BT2100:
      switch (dest_encoding) {
        case ULTRAHDR_COLORGAMUT_BT709:
          conversionFn = yuv2100To709;
          break;
        case ULTRAHDR_COLORGAMUT_P3:
          conversionFn = yuv2100To601;
          break;
        case ULTRAHDR_COLORGAMUT_BT2100:
          return UHDR_NO_ERROR;
        default:
          // Should be impossible to hit after input validation
          return ERROR_UHDR_INVALID_COLORGAMUT;
      }
      break;
    default:
      // Should be impossible to hit after input validation
      return ERROR_UHDR_INVALID_COLORGAMUT;
  }

  if (conversionFn == nullptr) {
    // Should be impossible to hit after input validation
    return ERROR_UHDR_INVALID_COLORGAMUT;
  }

  for (size_t y = 0; y < image->height / 2; ++y) {
    for (size_t x = 0; x < image->width / 2; ++x) {
      transformYuv420(image, x, y, conversionFn);
    }
  }

  return UHDR_NO_ERROR;
}

}  // namespace ultrahdr
