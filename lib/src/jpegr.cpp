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
#include <windows.h>
#include <sysinfoapi.h>
#else
#include <unistd.h>
#endif

#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

#include "ultrahdr/gainmapmetadata.h"
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

// Gain map metadata
static const bool kWriteXmpMetadata = true;
static const bool kWriteIso21496_1Metadata = false;

// Gain map calculation
static const bool kUseMultiChannelGainMap = false;

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

const string kXmpNameSpace = "http://ns.adobe.com/xap/1.0/";
const string kIsoNameSpace = "urn:iso:std:iso:ts:21496:-1";

/*
 * Helper function copies the JPEG image from without EXIF.
 *
 * @param pDest destination of the data to be written.
 * @param pSource source of data being written.
 * @param exif_pos position of the EXIF package, which is aligned with jpegdecoder.getEXIFPos().
 *                 (4 bytes offset to FF sign, the byte after FF E1 XX XX <this byte>).
 * @param exif_size exif size without the initial 4 bytes, aligned with jpegdecoder.getEXIFSize().
 */
static void copyJpegWithoutExif(jr_compressed_ptr pDest, jr_compressed_ptr pSource, size_t exif_pos,
                                size_t exif_size) {
  const size_t exif_offset = 4;  // exif_pos has 4 bytes offset to the FF sign
  pDest->length = pSource->length - exif_size - exif_offset;
  pDest->data = new uint8_t[pDest->length];
  pDest->maxLength = pDest->length;
  pDest->colorGamut = pSource->colorGamut;
  memcpy(pDest->data, pSource->data, exif_pos - exif_offset);
  memcpy((uint8_t*)pDest->data + exif_pos - exif_offset,
         (uint8_t*)pSource->data + exif_pos + exif_size, pSource->length - exif_pos - exif_size);
}

status_t JpegR::areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
                                       jr_uncompressed_ptr yuv420_image_ptr,
                                       ultrahdr_transfer_function hdr_tf,
                                       jr_compressed_ptr dest_ptr) {
  if (p010_image_ptr == nullptr || p010_image_ptr->data == nullptr) {
    ALOGE("Received nullptr for input p010 image");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (p010_image_ptr->width % 2 != 0 || p010_image_ptr->height % 2 != 0) {
    ALOGE("Image dimensions cannot be odd, image dimensions %zux%zu", p010_image_ptr->width,
          p010_image_ptr->height);
    return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
  }
  if (p010_image_ptr->width < kMinWidth || p010_image_ptr->height < kMinHeight) {
    ALOGE("Image dimensions cannot be less than %dx%d, image dimensions %zux%zu", kMinWidth,
          kMinHeight, p010_image_ptr->width, p010_image_ptr->height);
    return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
  }
  if (p010_image_ptr->width > kMaxWidth || p010_image_ptr->height > kMaxHeight) {
    ALOGE("Image dimensions cannot be larger than %dx%d, image dimensions %zux%zu", kMaxWidth,
          kMaxHeight, p010_image_ptr->width, p010_image_ptr->height);
    return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
  }
  if (p010_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
      p010_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
    ALOGE("Unrecognized p010 color gamut %d", p010_image_ptr->colorGamut);
    return ERROR_JPEGR_INVALID_COLORGAMUT;
  }
  if (p010_image_ptr->luma_stride != 0 && p010_image_ptr->luma_stride < p010_image_ptr->width) {
    ALOGE("Luma stride must not be smaller than width, stride=%zu, width=%zu",
          p010_image_ptr->luma_stride, p010_image_ptr->width);
    return ERROR_JPEGR_INVALID_STRIDE;
  }
  if (p010_image_ptr->chroma_data != nullptr &&
      p010_image_ptr->chroma_stride < p010_image_ptr->width) {
    ALOGE("Chroma stride must not be smaller than width, stride=%zu, width=%zu",
          p010_image_ptr->chroma_stride, p010_image_ptr->width);
    return ERROR_JPEGR_INVALID_STRIDE;
  }
  if (dest_ptr == nullptr || dest_ptr->data == nullptr) {
    ALOGE("Received nullptr for destination");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (hdr_tf <= ULTRAHDR_TF_UNSPECIFIED || hdr_tf > ULTRAHDR_TF_MAX || hdr_tf == ULTRAHDR_TF_SRGB) {
    ALOGE("Invalid hdr transfer function %d", hdr_tf);
    return ERROR_JPEGR_INVALID_TRANS_FUNC;
  }
  if (yuv420_image_ptr == nullptr) {
    return JPEGR_NO_ERROR;
  }
  if (yuv420_image_ptr->data == nullptr) {
    ALOGE("Received nullptr for uncompressed 420 image");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (yuv420_image_ptr->luma_stride != 0 &&
      yuv420_image_ptr->luma_stride < yuv420_image_ptr->width) {
    ALOGE("Luma stride must not be smaller than width, stride=%zu, width=%zu",
          yuv420_image_ptr->luma_stride, yuv420_image_ptr->width);
    return ERROR_JPEGR_INVALID_STRIDE;
  }
  if (yuv420_image_ptr->chroma_data != nullptr &&
      yuv420_image_ptr->chroma_stride < yuv420_image_ptr->width / 2) {
    ALOGE("Chroma stride must not be smaller than (width / 2), stride=%zu, width=%zu",
          yuv420_image_ptr->chroma_stride, yuv420_image_ptr->width);
    return ERROR_JPEGR_INVALID_STRIDE;
  }
  if (p010_image_ptr->width != yuv420_image_ptr->width ||
      p010_image_ptr->height != yuv420_image_ptr->height) {
    ALOGE("Image resolutions mismatch: P010: %zux%zu, YUV420: %zux%zu", p010_image_ptr->width,
          p010_image_ptr->height, yuv420_image_ptr->width, yuv420_image_ptr->height);
    return ERROR_JPEGR_RESOLUTION_MISMATCH;
  }
  if (yuv420_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
      yuv420_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
    ALOGE("Unrecognized 420 color gamut %d", yuv420_image_ptr->colorGamut);
    return ERROR_JPEGR_INVALID_COLORGAMUT;
  }
  return JPEGR_NO_ERROR;
}

status_t JpegR::areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
                                       jr_uncompressed_ptr yuv420_image_ptr,
                                       ultrahdr_transfer_function hdr_tf,
                                       jr_compressed_ptr dest_ptr, int quality) {
  if (quality < 0 || quality > 100) {
    ALOGE("quality factor is out side range [0-100], quality factor : %d", quality);
    return ERROR_JPEGR_INVALID_QUALITY_FACTOR;
  }
  return areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest_ptr);
}

/* Encode API-0 */
status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, ultrahdr_transfer_function hdr_tf,
                            jr_compressed_ptr dest, int quality, jr_exif_ptr exif) {
  // validate input arguments
  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, nullptr, hdr_tf, dest, quality));
  if (exif != nullptr && exif->data == nullptr) {
    ALOGE("received nullptr for exif metadata");
    return ERROR_JPEGR_BAD_PTR;
  }

  // clean up input structure for later usage
  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
  if (!p010_image.chroma_data) {
    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
    p010_image.chroma_stride = p010_image.luma_stride;
  }

  const size_t yu420_luma_stride = ALIGNM(p010_image.width, 16);
  unique_ptr<uint8_t[]> yuv420_image_data =
      make_unique<uint8_t[]>(yu420_luma_stride * p010_image.height * 3 / 2);
  jpegr_uncompressed_struct yuv420_image;
  yuv420_image.data = yuv420_image_data.get();
  yuv420_image.width = p010_image.width;
  yuv420_image.height = p010_image.height;
  yuv420_image.colorGamut = p010_image.colorGamut;
  yuv420_image.chroma_data = nullptr;
  yuv420_image.luma_stride = yu420_luma_stride;
  yuv420_image.chroma_stride = yu420_luma_stride >> 1;
  uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
  yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;

  // tone map
  JPEGR_CHECK(toneMap(&p010_image, &yuv420_image, hdr_tf));

  // gain map
  ultrahdr_metadata_struct metadata;
  metadata.version = kJpegrVersion;
  jpegr_uncompressed_struct gainmap_image;
  JPEGR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  JPEGR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
  jpegr_compressed_struct compressed_map;
  compressed_map.data = jpeg_enc_obj_gm.getCompressedImagePtr();
  compressed_map.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  compressed_map.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  compressed_map.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;

  std::shared_ptr<DataStruct> icc =
      IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, yuv420_image.colorGamut);

  // convert to Bt601 YUV encoding for JPEG encode
  if (yuv420_image.colorGamut != ULTRAHDR_COLORGAMUT_P3) {
    JPEGR_CHECK(convertYuv(&yuv420_image, yuv420_image.colorGamut, ULTRAHDR_COLORGAMUT_P3));
  }

  // compress 420 image
  JpegEncoderHelper jpeg_enc_obj_yuv420;
  const uint8_t* planes[3]{reinterpret_cast<uint8_t*>(yuv420_image.data),
                           reinterpret_cast<uint8_t*>(yuv420_image.chroma_data),
                           reinterpret_cast<uint8_t*>(yuv420_image.chroma_data) +
                               yuv420_image.chroma_stride * yuv420_image.height / 2};
  const size_t strides[3]{yuv420_image.luma_stride, yuv420_image.chroma_stride,
                          yuv420_image.chroma_stride};
  if (!jpeg_enc_obj_yuv420.compressImage(planes, strides, yuv420_image.width, yuv420_image.height,
                                         JpegEncoderHelper::YUV420, quality, icc->getData(),
                                         icc->getLength())) {
    return ERROR_JPEGR_ENCODE_ERROR;
  }
  jpegr_compressed_struct jpeg;
  jpeg.data = jpeg_enc_obj_yuv420.getCompressedImagePtr();
  jpeg.length = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
  jpeg.maxLength = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
  jpeg.colorGamut = yuv420_image.colorGamut;

  // append gain map, no ICC since JPEG encode already did it
  JPEGR_CHECK(appendGainMap(&jpeg, &compressed_map, exif, /* icc */ nullptr, /* icc size */ 0,
                            &metadata, dest));

  return JPEGR_NO_ERROR;
}

/* Encode API-1 */
status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
                            jr_uncompressed_ptr yuv420_image_ptr, ultrahdr_transfer_function hdr_tf,
                            jr_compressed_ptr dest, int quality, jr_exif_ptr exif) {
  // validate input arguments
  if (yuv420_image_ptr == nullptr) {
    ALOGE("received nullptr for uncompressed 420 image");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (exif != nullptr && exif->data == nullptr) {
    ALOGE("received nullptr for exif metadata");
    return ERROR_JPEGR_BAD_PTR;
  }
  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest, quality))

  // clean up input structure for later usage
  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
  if (!p010_image.chroma_data) {
    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
    p010_image.chroma_stride = p010_image.luma_stride;
  }
  jpegr_uncompressed_struct yuv420_image = *yuv420_image_ptr;
  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
  if (!yuv420_image.chroma_data) {
    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
    yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;
    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
  }

  // gain map
  ultrahdr_metadata_struct metadata;
  metadata.version = kJpegrVersion;
  jpegr_uncompressed_struct gainmap_image;
  JPEGR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  JPEGR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
  jpegr_compressed_struct compressed_map;
  compressed_map.data = jpeg_enc_obj_gm.getCompressedImagePtr();
  compressed_map.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  compressed_map.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  compressed_map.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;

  std::shared_ptr<DataStruct> icc =
      IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, yuv420_image.colorGamut);

  jpegr_uncompressed_struct yuv420_bt601_image = yuv420_image;
  unique_ptr<uint8_t[]> yuv_420_bt601_data;
  // Convert to bt601 YUV encoding for JPEG encode
  if (yuv420_image.colorGamut != ULTRAHDR_COLORGAMUT_P3) {
    const size_t yuv_420_bt601_luma_stride = ALIGNM(yuv420_image.width, 16);
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
    JPEGR_CHECK(convertYuv(&yuv420_bt601_image, yuv420_image.colorGamut, ULTRAHDR_COLORGAMUT_P3));
  }

  // compress 420 image
  JpegEncoderHelper jpeg_enc_obj_yuv420;
  const uint8_t* planes[3]{reinterpret_cast<uint8_t*>(yuv420_bt601_image.data),
                           reinterpret_cast<uint8_t*>(yuv420_bt601_image.chroma_data),
                           reinterpret_cast<uint8_t*>(yuv420_bt601_image.chroma_data) +
                               yuv420_bt601_image.chroma_stride * yuv420_bt601_image.height / 2};
  const size_t strides[3]{yuv420_bt601_image.luma_stride, yuv420_bt601_image.chroma_stride,
                          yuv420_bt601_image.chroma_stride};
  if (!jpeg_enc_obj_yuv420.compressImage(planes, strides, yuv420_bt601_image.width,
                                         yuv420_bt601_image.height, JpegEncoderHelper::YUV420,
                                         quality, icc->getData(), icc->getLength())) {
    return ERROR_JPEGR_ENCODE_ERROR;
  }

  jpegr_compressed_struct jpeg;
  jpeg.data = jpeg_enc_obj_yuv420.getCompressedImagePtr();
  jpeg.length = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
  jpeg.maxLength = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
  jpeg.colorGamut = yuv420_image.colorGamut;

  // append gain map, no ICC since JPEG encode already did it
  JPEGR_CHECK(appendGainMap(&jpeg, &compressed_map, exif, /* icc */ nullptr, /* icc size */ 0,
                            &metadata, dest));
  return JPEGR_NO_ERROR;
}

/* Encode API-2 */
status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
                            jr_uncompressed_ptr yuv420_image_ptr,
                            jr_compressed_ptr yuv420jpg_image_ptr,
                            ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest) {
  // validate input arguments
  if (yuv420_image_ptr == nullptr) {
    ALOGE("received nullptr for uncompressed 420 image");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed jpeg image");
    return ERROR_JPEGR_BAD_PTR;
  }
  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest))

  // clean up input structure for later usage
  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
  if (!p010_image.chroma_data) {
    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
    p010_image.chroma_stride = p010_image.luma_stride;
  }
  jpegr_uncompressed_struct yuv420_image = *yuv420_image_ptr;
  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
  if (!yuv420_image.chroma_data) {
    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
    yuv420_image.chroma_data = data + yuv420_image.luma_stride * p010_image.height;
    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
  }

  // gain map
  ultrahdr_metadata_struct metadata;
  metadata.version = kJpegrVersion;
  jpegr_uncompressed_struct gainmap_image;
  JPEGR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  JPEGR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
  jpegr_compressed_struct gainmapjpg_image;
  gainmapjpg_image.data = jpeg_enc_obj_gm.getCompressedImagePtr();
  gainmapjpg_image.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  gainmapjpg_image.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  gainmapjpg_image.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;

  return encodeJPEGR(yuv420jpg_image_ptr, &gainmapjpg_image, &metadata, dest);
}

/* Encode API-3 */
status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
                            jr_compressed_ptr yuv420jpg_image_ptr,
                            ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest) {
  // validate input arguments
  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed jpeg image");
    return ERROR_JPEGR_BAD_PTR;
  }
  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, nullptr, hdr_tf, dest))

  // clean up input structure for later usage
  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
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
    return ERROR_JPEGR_DECODE_ERROR;
  }
  jpegr_uncompressed_struct yuv420_image{};
  yuv420_image.data = jpeg_dec_obj_yuv420.getDecompressedImagePtr();
  yuv420_image.width = jpeg_dec_obj_yuv420.getDecompressedImageWidth();
  yuv420_image.height = jpeg_dec_obj_yuv420.getDecompressedImageHeight();
  if (jpeg_dec_obj_yuv420.getICCSize() > 0) {
    ultrahdr_color_gamut cg = IccHelper::readIccColorGamut(jpeg_dec_obj_yuv420.getICCPtr(),
                                                           jpeg_dec_obj_yuv420.getICCSize());
    if (cg == ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
        (yuv420jpg_image_ptr->colorGamut != ULTRAHDR_COLORGAMUT_UNSPECIFIED &&
         yuv420jpg_image_ptr->colorGamut != cg)) {
      ALOGE("configured color gamut  %d does not match with color gamut specified in icc box %d",
            yuv420jpg_image_ptr->colorGamut, cg);
      return ERROR_JPEGR_INVALID_COLORGAMUT;
    }
    yuv420_image.colorGamut = cg;
  } else {
    if (yuv420jpg_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
        yuv420jpg_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
      ALOGE("Unrecognized 420 color gamut %d", yuv420jpg_image_ptr->colorGamut);
      return ERROR_JPEGR_INVALID_COLORGAMUT;
    }
    yuv420_image.colorGamut = yuv420jpg_image_ptr->colorGamut;
  }
  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
  if (!yuv420_image.chroma_data) {
    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
    yuv420_image.chroma_data = data + yuv420_image.luma_stride * p010_image.height;
    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
  }

  if (p010_image_ptr->width != yuv420_image.width ||
      p010_image_ptr->height != yuv420_image.height) {
    return ERROR_JPEGR_RESOLUTION_MISMATCH;
  }

  // gain map
  ultrahdr_metadata_struct metadata;
  metadata.version = kJpegrVersion;
  jpegr_uncompressed_struct gainmap_image;
  JPEGR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image,
                              true /* sdr_is_601 */));
  std::unique_ptr<uint8_t[]> map_data;
  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  JPEGR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
  jpegr_compressed_struct gainmapjpg_image;
  gainmapjpg_image.data = jpeg_enc_obj_gm.getCompressedImagePtr();
  gainmapjpg_image.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  gainmapjpg_image.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
  gainmapjpg_image.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;

  return encodeJPEGR(yuv420jpg_image_ptr, &gainmapjpg_image, &metadata, dest);
}

/* Encode API-4 */
status_t JpegR::encodeJPEGR(jr_compressed_ptr yuv420jpg_image_ptr,
                            jr_compressed_ptr gainmapjpg_image_ptr, ultrahdr_metadata_ptr metadata,
                            jr_compressed_ptr dest) {
  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed jpeg image");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (gainmapjpg_image_ptr == nullptr || gainmapjpg_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed gain map");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (dest == nullptr || dest->data == nullptr) {
    ALOGE("received nullptr for destination");
    return ERROR_JPEGR_BAD_PTR;
  }

  // We just want to check if ICC is present, so don't do a full decode. Note,
  // this doesn't verify that the ICC is valid.
  JpegDecoderHelper decoder;
  if (!decoder.parseImage(yuv420jpg_image_ptr->data, yuv420jpg_image_ptr->length)) {
    return ERROR_JPEGR_DECODE_ERROR;
  }

  // Add ICC if not already present.
  if (decoder.getICCSize() > 0) {
    JPEGR_CHECK(appendGainMap(yuv420jpg_image_ptr, gainmapjpg_image_ptr, /* exif */ nullptr,
                              /* icc */ nullptr, /* icc size */ 0, metadata, dest));
  } else {
    if (yuv420jpg_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
        yuv420jpg_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
      ALOGE("Unrecognized 420 color gamut %d", yuv420jpg_image_ptr->colorGamut);
      return ERROR_JPEGR_INVALID_COLORGAMUT;
    }
    std::shared_ptr<DataStruct> newIcc =
        IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, yuv420jpg_image_ptr->colorGamut);
    JPEGR_CHECK(appendGainMap(yuv420jpg_image_ptr, gainmapjpg_image_ptr, /* exif */ nullptr,
                              newIcc->getData(), newIcc->getLength(), metadata, dest));
  }

  return JPEGR_NO_ERROR;
}

status_t JpegR::getJPEGRInfo(jr_compressed_ptr jpegr_image_ptr, jr_info_ptr jpegr_image_info_ptr) {
  if (jpegr_image_ptr == nullptr || jpegr_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed jpegr image");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (jpegr_image_info_ptr == nullptr) {
    ALOGE("received nullptr for compressed jpegr info struct");
    return ERROR_JPEGR_BAD_PTR;
  }

  jpegr_compressed_struct primary_image, gainmap_image;
  JPEGR_CHECK(extractPrimaryImageAndGainMap(jpegr_image_ptr, &primary_image, &gainmap_image))

  JPEGR_CHECK(parseJpegInfo(&primary_image, jpegr_image_info_ptr->primaryImgInfo,
                            &jpegr_image_info_ptr->width, &jpegr_image_info_ptr->height))
  if (jpegr_image_info_ptr->gainmapImgInfo != nullptr) {
    JPEGR_CHECK(parseJpegInfo(&gainmap_image, jpegr_image_info_ptr->gainmapImgInfo))
  }

  return JPEGR_NO_ERROR;
}

/* Decode API */
status_t JpegR::decodeJPEGR(jr_compressed_ptr jpegr_image_ptr, jr_uncompressed_ptr dest,
                            float max_display_boost, jr_exif_ptr exif,
                            ultrahdr_output_format output_format,
                            jr_uncompressed_ptr gainmap_image_ptr, ultrahdr_metadata_ptr metadata) {
  if (jpegr_image_ptr == nullptr || jpegr_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed jpegr image");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (dest == nullptr || dest->data == nullptr) {
    ALOGE("received nullptr for dest image");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (max_display_boost < 1.0f) {
    ALOGE("received bad value for max_display_boost %f", max_display_boost);
    return ERROR_JPEGR_INVALID_DISPLAY_BOOST;
  }
  if (exif != nullptr && exif->data == nullptr) {
    ALOGE("received nullptr address for exif data");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (gainmap_image_ptr != nullptr && gainmap_image_ptr->data == nullptr) {
    ALOGE("received nullptr address for gainmap data");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (output_format <= ULTRAHDR_OUTPUT_UNSPECIFIED || output_format > ULTRAHDR_OUTPUT_MAX) {
    ALOGE("received bad value for output format %d", output_format);
    return ERROR_JPEGR_INVALID_OUTPUT_FORMAT;
  }

  jpegr_compressed_struct primary_jpeg_image, gainmap_jpeg_image;
  JPEGR_CHECK(
      extractPrimaryImageAndGainMap(jpegr_image_ptr, &primary_jpeg_image, &gainmap_jpeg_image))

  JpegDecoderHelper jpeg_dec_obj_yuv420;
  if (!jpeg_dec_obj_yuv420.decompressImage(
          primary_jpeg_image.data, primary_jpeg_image.length,
          (output_format == ULTRAHDR_OUTPUT_SDR) ? DECODE_TO_RGB_CS : DECODE_TO_YCBCR_CS)) {
    return ERROR_JPEGR_DECODE_ERROR;
  }

  if (output_format == ULTRAHDR_OUTPUT_SDR) {
#ifdef JCS_ALPHA_EXTENSIONS
    if ((jpeg_dec_obj_yuv420.getDecompressedImageWidth() *
         jpeg_dec_obj_yuv420.getDecompressedImageHeight() * 4) >
        jpeg_dec_obj_yuv420.getDecompressedImageSize()) {
      return ERROR_JPEGR_DECODE_ERROR;
    }
#else
    if ((jpeg_dec_obj_yuv420.getDecompressedImageWidth() *
         jpeg_dec_obj_yuv420.getDecompressedImageHeight() * 3) >
        jpeg_dec_obj_yuv420.getDecompressedImageSize()) {
      return ERROR_JPEGR_DECODE_ERROR;
    }
#endif
  } else {
    if ((jpeg_dec_obj_yuv420.getDecompressedImageWidth() *
         jpeg_dec_obj_yuv420.getDecompressedImageHeight() * 3 / 2) >
        jpeg_dec_obj_yuv420.getDecompressedImageSize()) {
      return ERROR_JPEGR_DECODE_ERROR;
    }
  }

  if (exif != nullptr) {
    if (exif->length < jpeg_dec_obj_yuv420.getEXIFSize()) {
      return ERROR_JPEGR_BUFFER_TOO_SMALL;
    }
    memcpy(exif->data, jpeg_dec_obj_yuv420.getEXIFPtr(), jpeg_dec_obj_yuv420.getEXIFSize());
    exif->length = jpeg_dec_obj_yuv420.getEXIFSize();
  }

  JpegDecoderHelper jpeg_dec_obj_gm;
  jpegr_uncompressed_struct gainmap_image;
  if (gainmap_image_ptr != nullptr || output_format != ULTRAHDR_OUTPUT_SDR) {
    if (!jpeg_dec_obj_gm.decompressImage(gainmap_jpeg_image.data, gainmap_jpeg_image.length,
                                         DECODE_STREAM)) {
      return ERROR_JPEGR_DECODE_ERROR;
    }
    if (jpeg_dec_obj_gm.getDecompressedImageFormat() == JpegDecoderHelper::GRAYSCALE) {
      gainmap_image.pixelFormat = ULTRAHDR_PIX_FMT_MONOCHROME;
    } else if (jpeg_dec_obj_gm.getDecompressedImageFormat() == JpegDecoderHelper::RGB) {
      gainmap_image.pixelFormat = ULTRAHDR_PIX_FMT_RGB888;
    } else if (jpeg_dec_obj_gm.getDecompressedImageFormat() == JpegDecoderHelper::RGBA) {
      gainmap_image.pixelFormat = ULTRAHDR_PIX_FMT_RGBA8888;
    } else {
      return ERROR_JPEGR_GAIN_MAP_SIZE_ERROR;
    }
    gainmap_image.data = jpeg_dec_obj_gm.getDecompressedImagePtr();
    gainmap_image.width = jpeg_dec_obj_gm.getDecompressedImageWidth();
    gainmap_image.height = jpeg_dec_obj_gm.getDecompressedImageHeight();

    if (gainmap_image_ptr != nullptr) {
      gainmap_image_ptr->width = gainmap_image.width;
      gainmap_image_ptr->height = gainmap_image.height;
      gainmap_image_ptr->pixelFormat = gainmap_image.pixelFormat;
      memcpy(gainmap_image_ptr->data, gainmap_image.data,
             gainmap_image_ptr->width * gainmap_image_ptr->height);
    }
  }

  ultrahdr_metadata_struct uhdr_metadata;
  if (metadata != nullptr || output_format != ULTRAHDR_OUTPUT_SDR) {
    uint8_t* iso_ptr = static_cast<uint8_t*>(jpeg_dec_obj_gm.getIsoMetadataPtr());
    if (iso_ptr != nullptr) {
      size_t iso_size = jpeg_dec_obj_gm.getIsoMetadataSize();
      if (iso_size < kIsoNameSpace.size() + 1) {
        return ERROR_JPEGR_METADATA_ERROR;
      }
      gain_map_metadata decodedMetadata;
      std::vector<uint8_t> iso_vec;
      for (size_t i = kIsoNameSpace.size() + 1; i < iso_size; i++) {
        iso_vec.push_back(iso_ptr[i]);
      }

      JPEGR_CHECK(gain_map_metadata::decodeGainmapMetadata(iso_vec, &decodedMetadata));
      JPEGR_CHECK(
          gain_map_metadata::gainmapMetadataFractionToFloat(&decodedMetadata, &uhdr_metadata));
    } else {
      if (!getMetadataFromXMP(static_cast<uint8_t*>(jpeg_dec_obj_gm.getXMPPtr()),
                              jpeg_dec_obj_gm.getXMPSize(), &uhdr_metadata)) {
        return ERROR_JPEGR_METADATA_ERROR;
      }
    }
    if (metadata != nullptr) {
      metadata->version = uhdr_metadata.version;
      metadata->minContentBoost = uhdr_metadata.minContentBoost;
      metadata->maxContentBoost = uhdr_metadata.maxContentBoost;
      metadata->gamma = uhdr_metadata.gamma;
      metadata->offsetSdr = uhdr_metadata.offsetSdr;
      metadata->offsetHdr = uhdr_metadata.offsetHdr;
      metadata->hdrCapacityMin = uhdr_metadata.hdrCapacityMin;
      metadata->hdrCapacityMax = uhdr_metadata.hdrCapacityMax;
    }
  }

  if (output_format == ULTRAHDR_OUTPUT_SDR) {
    dest->width = jpeg_dec_obj_yuv420.getDecompressedImageWidth();
    dest->height = jpeg_dec_obj_yuv420.getDecompressedImageHeight();
#ifdef JCS_ALPHA_EXTENSIONS
    memcpy(dest->data, jpeg_dec_obj_yuv420.getDecompressedImagePtr(),
           dest->width * dest->height * 4);
#else
    uint32_t* pixelDst = static_cast<uint32_t*>(dest->data);
    uint8_t* pixelSrc = static_cast<uint8_t*>(jpeg_dec_obj_yuv420.getDecompressedImagePtr());
    for (int i = 0; i < dest->width * dest->height; i++) {
      *pixelDst = pixelSrc[0] | (pixelSrc[1] << 8) | (pixelSrc[2] << 16) | (0xff << 24);
      pixelSrc += 3;
      pixelDst += 1;
    }
#endif
    dest->colorGamut = IccHelper::readIccColorGamut(jpeg_dec_obj_yuv420.getICCPtr(),
                                                    jpeg_dec_obj_yuv420.getICCSize());
    return JPEGR_NO_ERROR;
  }

  jpegr_uncompressed_struct yuv420_image;
  yuv420_image.data = jpeg_dec_obj_yuv420.getDecompressedImagePtr();
  yuv420_image.width = jpeg_dec_obj_yuv420.getDecompressedImageWidth();
  yuv420_image.height = jpeg_dec_obj_yuv420.getDecompressedImageHeight();
  yuv420_image.colorGamut = IccHelper::readIccColorGamut(jpeg_dec_obj_yuv420.getICCPtr(),
                                                         jpeg_dec_obj_yuv420.getICCSize());
  yuv420_image.luma_stride = yuv420_image.width;
  uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
  yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;
  yuv420_image.chroma_stride = yuv420_image.width >> 1;

  JPEGR_CHECK(applyGainMap(&yuv420_image, &gainmap_image, &uhdr_metadata, output_format,
                           max_display_boost, dest));
  return JPEGR_NO_ERROR;
}

status_t JpegR::compressGainMap(jr_uncompressed_ptr gainmap_image_ptr,
                                JpegEncoderHelper* jpeg_enc_obj_ptr) {
  if (gainmap_image_ptr == nullptr || jpeg_enc_obj_ptr == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }

  const uint8_t* planes[]{reinterpret_cast<uint8_t*>(gainmap_image_ptr->data)};
  if (kUseMultiChannelGainMap) {
    const size_t strides[]{gainmap_image_ptr->width * 3};
    if (!jpeg_enc_obj_ptr->compressImage(planes, strides, gainmap_image_ptr->width,
                                         gainmap_image_ptr->height, JpegEncoderHelper::RGB,
                                         kMapCompressQuality, nullptr, 0)) {
      return ERROR_JPEGR_ENCODE_ERROR;
    }
  } else {
    const size_t strides[]{gainmap_image_ptr->width};
    // Don't need to convert YUV to Bt601 since single channel
    if (!jpeg_enc_obj_ptr->compressImage(planes, strides, gainmap_image_ptr->width,
                                         gainmap_image_ptr->height, JpegEncoderHelper::GRAYSCALE,
                                         kMapCompressQuality, nullptr, 0)) {
      return ERROR_JPEGR_ENCODE_ERROR;
    }
  }

  return JPEGR_NO_ERROR;
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

status_t JpegR::generateGainMap(jr_uncompressed_ptr yuv420_image_ptr,
                                jr_uncompressed_ptr p010_image_ptr,
                                ultrahdr_transfer_function hdr_tf, ultrahdr_metadata_ptr metadata,
                                jr_uncompressed_ptr dest, bool sdr_is_601) {
  /*if (kUseMultiChannelGainMap) {
    static_assert(kWriteIso21496_1Metadata && !kWriteXmpMetadata,
                  "Multi-channel gain map now is only supported for ISO 21496-1 metadata");
  }*/

  int gainMapChannelCount = kUseMultiChannelGainMap ? 3 : 1;

  if (yuv420_image_ptr == nullptr || p010_image_ptr == nullptr || metadata == nullptr ||
      dest == nullptr || yuv420_image_ptr->data == nullptr ||
      yuv420_image_ptr->chroma_data == nullptr || p010_image_ptr->data == nullptr ||
      p010_image_ptr->chroma_data == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }
  if (yuv420_image_ptr->width != p010_image_ptr->width ||
      yuv420_image_ptr->height != p010_image_ptr->height) {
    return ERROR_JPEGR_RESOLUTION_MISMATCH;
  }
  if (yuv420_image_ptr->colorGamut == ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
      p010_image_ptr->colorGamut == ULTRAHDR_COLORGAMUT_UNSPECIFIED) {
    return ERROR_JPEGR_INVALID_COLORGAMUT;
  }

  size_t image_width = yuv420_image_ptr->width;
  size_t image_height = yuv420_image_ptr->height;
  size_t map_width = image_width / kMapDimensionScaleFactor;
  size_t map_height = image_height / kMapDimensionScaleFactor;

  dest->data = new uint8_t[map_width * map_height * gainMapChannelCount];
  dest->width = map_width;
  dest->height = map_height;
  dest->colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
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
      return ERROR_JPEGR_INVALID_TRANS_FUNC;
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
      return ERROR_JPEGR_INVALID_COLORGAMUT;
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
      return ERROR_JPEGR_INVALID_COLORGAMUT;
  }

  const int threads = (std::min)(GetCPUCoreCount(), 4);
  size_t rowStep = threads == 1 ? image_height : kJobSzInRows;
  JobQueue jobQueue;
  std::function<void()> generateMap;

  if (kUseMultiChannelGainMap) {
    generateMap = [yuv420_image_ptr, p010_image_ptr, metadata, dest, hdrInvOetf,
                   hdrGamutConversionFn, sdrYuvToRgbFn, gainMapChannelCount, hdrYuvToRgbFn,
                   hdr_white_nits, log2MinBoost, log2MaxBoost, &jobQueue]() -> void {
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
            Color sdr_rgb_nits = sdr_rgb * kSdrWhiteNits;

            Color hdr_yuv_gamma = sampleP010(p010_image_ptr, kMapDimensionScaleFactor, x, y);
            Color hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
            Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
            hdr_rgb = hdrGamutConversionFn(hdr_rgb);
            Color hdr_rgb_nits = hdr_rgb * hdr_white_nits;

            size_t pixel_idx = (x + y * dest->width) * gainMapChannelCount;

            // R
            reinterpret_cast<uint8_t*>(dest->data)[pixel_idx] =
                encodeGain(sdr_rgb_nits.r, hdr_rgb_nits.r, metadata, log2MinBoost, log2MaxBoost);
            // G
            reinterpret_cast<uint8_t*>(dest->data)[pixel_idx + 1] =
                encodeGain(sdr_rgb_nits.g, hdr_rgb_nits.g, metadata, log2MinBoost, log2MaxBoost);
            // B
            reinterpret_cast<uint8_t*>(dest->data)[pixel_idx + 2] =
                encodeGain(sdr_rgb_nits.b, hdr_rgb_nits.b, metadata, log2MinBoost, log2MaxBoost);
          }
        }
      }
    };
  } else {
    generateMap = [yuv420_image_ptr, p010_image_ptr, metadata, dest, hdrInvOetf,
                   hdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn, hdr_white_nits,
                   log2MinBoost, log2MaxBoost, &jobQueue]() -> void {
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
  }

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

  return JPEGR_NO_ERROR;
}

status_t JpegR::applyGainMap(jr_uncompressed_ptr yuv420_image_ptr,
                             jr_uncompressed_ptr gainmap_image_ptr, ultrahdr_metadata_ptr metadata,
                             ultrahdr_output_format output_format, float max_display_boost,
                             jr_uncompressed_ptr dest) {
  if (yuv420_image_ptr == nullptr || gainmap_image_ptr == nullptr || metadata == nullptr ||
      dest == nullptr || yuv420_image_ptr->data == nullptr ||
      yuv420_image_ptr->chroma_data == nullptr || gainmap_image_ptr->data == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }
  if (metadata->version.compare(kJpegrVersion)) {
    ALOGE("Unsupported metadata version: %s", metadata->version.c_str());
    return ERROR_JPEGR_BAD_METADATA;
  }
  if (metadata->gamma != 1.0f) {
    ALOGE("Unsupported metadata gamma: %f", metadata->gamma);
    return ERROR_JPEGR_BAD_METADATA;
  }
  if (metadata->offsetSdr != 0.0f || metadata->offsetHdr != 0.0f) {
    ALOGE("Unsupported metadata offset sdr, hdr: %f, %f", metadata->offsetSdr, metadata->offsetHdr);
    return ERROR_JPEGR_BAD_METADATA;
  }
  if (metadata->hdrCapacityMin != metadata->minContentBoost ||
      metadata->hdrCapacityMax != metadata->maxContentBoost) {
    ALOGE("Unsupported metadata hdr capacity min, max: %f, %f", metadata->hdrCapacityMin,
          metadata->hdrCapacityMax);
    return ERROR_JPEGR_BAD_METADATA;
  }

  if (yuv420_image_ptr->width % gainmap_image_ptr->width != 0 ||
      yuv420_image_ptr->height % gainmap_image_ptr->height != 0) {
    ALOGE(
        "gain map dimensions scale factor value is not an integer, primary image resolution is "
        "%zux%zu, received gain map resolution is %zux%zu",
        yuv420_image_ptr->width, yuv420_image_ptr->height, gainmap_image_ptr->width,
        gainmap_image_ptr->height);
    return ERROR_JPEGR_UNSUPPORTED_MAP_SCALE_FACTOR;
  }

  if (yuv420_image_ptr->width * gainmap_image_ptr->height !=
      yuv420_image_ptr->height * gainmap_image_ptr->width) {
    ALOGE(
        "gain map dimensions scale factor values for height and width are different, \n primary "
        "image resolution is %zux%zu, received gain map resolution is %zux%zu",
        yuv420_image_ptr->width, yuv420_image_ptr->height, gainmap_image_ptr->width,
        gainmap_image_ptr->height);
    return ERROR_JPEGR_UNSUPPORTED_MAP_SCALE_FACTOR;
  }
  // TODO: Currently map_scale_factor is of type size_t, but it could be changed to a float
  // later.
  size_t map_scale_factor = yuv420_image_ptr->width / gainmap_image_ptr->width;

  dest->width = yuv420_image_ptr->width;
  dest->height = yuv420_image_ptr->height;
  dest->colorGamut = yuv420_image_ptr->colorGamut;
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
          Color rgb_hdr;
          if (gainmap_image_ptr->pixelFormat == ULTRAHDR_PIX_FMT_MONOCHROME) {
            float gain;
            // TODO: If map_scale_factor is guaranteed to be an integer, then remove the following.
            if (map_scale_factor != floorf(map_scale_factor)) {
              gain = sampleMap(gainmap_image_ptr, map_scale_factor, x, y);
            } else {
              gain = sampleMap(gainmap_image_ptr, map_scale_factor, x, y, idwTable);
            }

#if USE_APPLY_GAIN_LUT
            rgb_hdr = applyGainLUT(rgb_sdr, gain, gainLUT);
#else
            rgb_hdr = applyGain(rgb_sdr, gain, metadata, display_boost);
#endif
          } else {
            Color gain;
            // TODO: If map_scale_factor is guaranteed to be an integer, then remove the following.
            if (map_scale_factor != floorf(map_scale_factor)) {
              gain = sampleMap3Channel(gainmap_image_ptr, map_scale_factor, x, y,
                                       gainmap_image_ptr->pixelFormat == ULTRAHDR_PIX_FMT_RGBA8888);
            } else {
              gain = sampleMap3Channel(gainmap_image_ptr, map_scale_factor, x, y, idwTable,
                                       gainmap_image_ptr->pixelFormat == ULTRAHDR_PIX_FMT_RGBA8888);
            }

#if USE_APPLY_GAIN_LUT
            rgb_hdr = applyGainLUT(rgb_sdr, gain, gainLUT);
#else
            rgb_hdr = applyGain(rgb_sdr, gain, metadata, display_boost);
#endif
          }

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
  return JPEGR_NO_ERROR;
}

status_t JpegR::extractPrimaryImageAndGainMap(jr_compressed_ptr jpegr_image_ptr,
                                              jr_compressed_ptr primary_jpg_image_ptr,
                                              jr_compressed_ptr gainmap_jpg_image_ptr) {
  if (jpegr_image_ptr == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
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
    return JPEGR_UNKNOWN_ERROR;
  }

  const auto& jpeg_info = jpeg_info_builder.GetInfo();
  const auto& image_ranges = jpeg_info.GetImageRanges();

  if (image_ranges.empty()) {
    return ERROR_JPEGR_NO_IMAGES_FOUND;
  }

  if (primary_jpg_image_ptr != nullptr) {
    primary_jpg_image_ptr->data =
        static_cast<uint8_t*>(jpegr_image_ptr->data) + image_ranges[0].GetBegin();
    primary_jpg_image_ptr->length = image_ranges[0].GetLength();
  }

  if (image_ranges.size() == 1) {
    return ERROR_JPEGR_GAIN_MAP_IMAGE_NOT_FOUND;
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

  return JPEGR_NO_ERROR;
}

status_t JpegR::parseJpegInfo(jr_compressed_ptr jpeg_image_ptr, j_info_ptr jpeg_image_info_ptr,
                              size_t* img_width, size_t* img_height) {
  JpegDecoderHelper jpeg_dec_obj;
  if (!jpeg_dec_obj.parseImage(jpeg_image_ptr->data, jpeg_image_ptr->length)) {
    return ERROR_JPEGR_DECODE_ERROR;
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
  return JPEGR_NO_ERROR;
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
// (Required, ISO 21496-1 metadata, version only) APP2 (ff e2)
// 2 bytes of length
// name space (""urn:iso:std:iso:ts:21496:-1\0")
// 2 bytes minimum_version: (00 00)
// 2 bytes writer_version: (00 00)
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
// (Required, ISO 21496-1 metadata) APP2 (ff e2)
// 2 bytes of length
// name space (""urn:iso:std:iso:ts:21496:-1\0")
// metadata
//
// (Required) secondary image (the gain map, without the first two bytes (SOI))
//
// Metadata versions we are using:
// ECMA TR-98 for JFIF marker
// Exif 2.2 spec for EXIF marker
// Adobe XMP spec part 3 for XMP marker
// ICC v4.3 spec for ICC
status_t JpegR::appendGainMap(jr_compressed_ptr primary_jpg_image_ptr,
                              jr_compressed_ptr gainmap_jpg_image_ptr, jr_exif_ptr pExif,
                              void* pIcc, size_t icc_size, ultrahdr_metadata_ptr metadata,
                              jr_compressed_ptr dest) {
  static_assert(kWriteXmpMetadata || kWriteIso21496_1Metadata,
                "Must write gain map metadata in XMP format, or iso 21496-1 format, or both.");
  if (primary_jpg_image_ptr == nullptr || gainmap_jpg_image_ptr == nullptr || metadata == nullptr ||
      dest == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }
  if (metadata->version.compare("1.0")) {
    ALOGE("received bad value for version: %s", metadata->version.c_str());
    return ERROR_JPEGR_BAD_METADATA;
  }
  if (metadata->maxContentBoost < metadata->minContentBoost) {
    ALOGE("received bad value for content boost min %f, max %f", metadata->minContentBoost,
          metadata->maxContentBoost);
    return ERROR_JPEGR_BAD_METADATA;
  }
  if (metadata->hdrCapacityMax < metadata->hdrCapacityMin || metadata->hdrCapacityMin < 1.0f) {
    ALOGE("received bad value for hdr capacity min %f, max %f", metadata->hdrCapacityMin,
          metadata->hdrCapacityMax);
    return ERROR_JPEGR_BAD_METADATA;
  }
  if (metadata->offsetSdr < 0.0f || metadata->offsetHdr < 0.0f) {
    ALOGE("received bad value for offset sdr %f, hdr %f", metadata->offsetSdr, metadata->offsetHdr);
    return ERROR_JPEGR_BAD_METADATA;
  }
  if (metadata->gamma <= 0.0f) {
    ALOGE("received bad value for gamma %f", metadata->gamma);
    return ERROR_JPEGR_BAD_METADATA;
  }

  const int xmpNameSpaceLength = kXmpNameSpace.size() + 1;  // need to count the null terminator
  const int isoNameSpaceLength = kIsoNameSpace.size() + 1;  // need to count the null terminator

  /////////////////////////////////////////////////////////////////////////////////////////////////
  // calculate secondary image length first, because the length will be written into the primary //
  // image xmp                                                                                   //
  /////////////////////////////////////////////////////////////////////////////////////////////////
  // XMP
  const string xmp_secondary = generateXmpForSecondaryImage(*metadata);
  // xmp_secondary_length = 2 bytes representing the length of the package +
  //  + xmpNameSpaceLength = 29 bytes length
  //  + length of xmp packet = xmp_secondary.size()
  const int xmp_secondary_length = 2 + xmpNameSpaceLength + xmp_secondary.size();
  // ISO
  gain_map_metadata iso_secondary_metadata;
  std::vector<uint8_t> iso_secondary_data;
  gain_map_metadata::gainmapMetadataFloatToFraction(metadata, &iso_secondary_metadata);

  gain_map_metadata::encodeGainmapMetadata(&iso_secondary_metadata, iso_secondary_data);

  // iso_secondary_length = 2 bytes representing the length of the package +
  //  + isoNameSpaceLength = 28 bytes length
  //  + length of iso metadata packet = iso_secondary_data.size()
  const int iso_secondary_length = 2 + isoNameSpaceLength + iso_secondary_data.size();

  int secondary_image_size = 2 /* 2 bytes length of APP1 sign */ + gainmap_jpg_image_ptr->length;
  if (kWriteXmpMetadata) {
    secondary_image_size += xmp_secondary_length;
  }
  if (kWriteIso21496_1Metadata) {
    secondary_image_size += iso_secondary_length;
  }

  // Check if EXIF package presents in the JPEG input.
  // If so, extract and remove the EXIF package.
  JpegDecoderHelper decoder;
  if (!decoder.parseImage(primary_jpg_image_ptr->data, primary_jpg_image_ptr->length)) {
    return ERROR_JPEGR_DECODE_ERROR;
  }
  jpegr_exif_struct exif_from_jpg;
  exif_from_jpg.data = nullptr;
  exif_from_jpg.length = 0;
  jpegr_compressed_struct new_jpg_image;
  new_jpg_image.data = nullptr;
  new_jpg_image.length = 0;
  new_jpg_image.maxLength = 0;
  new_jpg_image.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  std::unique_ptr<uint8_t[]> dest_data;
  if (decoder.getEXIFPos() >= 0) {
    if (pExif != nullptr) {
      ALOGE("received EXIF from outside while the primary image already contains EXIF");
      return ERROR_JPEGR_MULTIPLE_EXIFS_RECEIVED;
    }
    copyJpegWithoutExif(&new_jpg_image, primary_jpg_image_ptr, decoder.getEXIFPos(),
                        decoder.getEXIFSize());
    dest_data.reset(reinterpret_cast<uint8_t*>(new_jpg_image.data));
    exif_from_jpg.data = decoder.getEXIFPtr();
    exif_from_jpg.length = decoder.getEXIFSize();
    pExif = &exif_from_jpg;
  }

  jr_compressed_ptr final_primary_jpg_image_ptr =
      new_jpg_image.length == 0 ? primary_jpg_image_ptr : &new_jpg_image;

  int pos = 0;
  // Begin primary image
  // Write SOI
  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kSOI, 1, pos));

  // Write EXIF
  if (pExif != nullptr) {
    const int length = 2 + pExif->length;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
    JPEGR_CHECK(Write(dest, pExif->data, pExif->length, pos));
  }

  // Prepare and write XMP
  if (kWriteXmpMetadata) {
    const string xmp_primary = generateXmpForPrimaryImage(secondary_image_size, *metadata);
    const int length = 2 + xmpNameSpaceLength + xmp_primary.size();
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
    JPEGR_CHECK(Write(dest, (void*)kXmpNameSpace.c_str(), xmpNameSpaceLength, pos));
    JPEGR_CHECK(Write(dest, (void*)xmp_primary.c_str(), xmp_primary.size(), pos));
  }

  // Write ICC
  if (pIcc != nullptr && icc_size > 0) {
    const int length = icc_size + 2;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
    JPEGR_CHECK(Write(dest, pIcc, icc_size, pos));
  }

  // Prepare and write ISO 21496-1 metadata
  if (kWriteIso21496_1Metadata) {
    const int length = 2 + isoNameSpaceLength + 4;
    uint8_t zero = 0;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
    JPEGR_CHECK(Write(dest, (void*)kIsoNameSpace.c_str(), isoNameSpaceLength, pos));
    JPEGR_CHECK(Write(dest, &zero, 1, pos));
    JPEGR_CHECK(Write(dest, &zero, 1, pos));  // 2 bytes minimum_version: (00 00)
    JPEGR_CHECK(Write(dest, &zero, 1, pos));
    JPEGR_CHECK(Write(dest, &zero, 1, pos));  // 2 bytes writer_version: (00 00)
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
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
    JPEGR_CHECK(Write(dest, (void*)mpf->getData(), mpf->getLength(), pos));
  }

  // Write primary image
  JPEGR_CHECK(Write(dest, (uint8_t*)final_primary_jpg_image_ptr->data + 2,
                    final_primary_jpg_image_ptr->length - 2, pos));
  // Finish primary image

  // Begin secondary image (gain map)
  // Write SOI
  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kSOI, 1, pos));

  // Prepare and write XMP
  if (kWriteXmpMetadata) {
    const int length = xmp_secondary_length;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
    JPEGR_CHECK(Write(dest, (void*)kXmpNameSpace.c_str(), xmpNameSpaceLength, pos));
    JPEGR_CHECK(Write(dest, (void*)xmp_secondary.c_str(), xmp_secondary.size(), pos));
  }

  // Prepare and write ISO 21496-1 metadata
  if (kWriteIso21496_1Metadata) {
    const int length = iso_secondary_length;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
    JPEGR_CHECK(Write(dest, (void*)kIsoNameSpace.c_str(), isoNameSpaceLength, pos));
    JPEGR_CHECK(Write(dest, (void*)iso_secondary_data.data(), iso_secondary_data.size(), pos));
  }

  // Write secondary image
  JPEGR_CHECK(Write(dest, (uint8_t*)gainmap_jpg_image_ptr->data + 2,
                    gainmap_jpg_image_ptr->length - 2, pos));

  // Set back length
  dest->length = pos;

  // Done!
  return JPEGR_NO_ERROR;
}

status_t JpegR::convertYuv(jr_uncompressed_ptr image, ultrahdr_color_gamut src_encoding,
                           ultrahdr_color_gamut dest_encoding) {
  if (image == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }
  if (src_encoding == ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
      dest_encoding == ULTRAHDR_COLORGAMUT_UNSPECIFIED) {
    return ERROR_JPEGR_INVALID_COLORGAMUT;
  }

  const std::array<float, 9>* coeffs_ptr = nullptr;
  switch (src_encoding) {
    case ULTRAHDR_COLORGAMUT_BT709:
      switch (dest_encoding) {
        case ULTRAHDR_COLORGAMUT_BT709:
          return JPEGR_NO_ERROR;
        case ULTRAHDR_COLORGAMUT_P3:
          coeffs_ptr = &kYuvBt709ToBt601;
          break;
        case ULTRAHDR_COLORGAMUT_BT2100:
          coeffs_ptr = &kYuvBt709ToBt2100;
          break;
        default:
          // Should be impossible to hit after input validation
          return ERROR_JPEGR_INVALID_COLORGAMUT;
      }
      break;
    case ULTRAHDR_COLORGAMUT_P3:
      switch (dest_encoding) {
        case ULTRAHDR_COLORGAMUT_BT709:
          coeffs_ptr = &kYuvBt601ToBt709;
          break;
        case ULTRAHDR_COLORGAMUT_P3:
          return JPEGR_NO_ERROR;
        case ULTRAHDR_COLORGAMUT_BT2100:
          coeffs_ptr = &kYuvBt601ToBt2100;
          break;
        default:
          // Should be impossible to hit after input validation
          return ERROR_JPEGR_INVALID_COLORGAMUT;
      }
      break;
    case ULTRAHDR_COLORGAMUT_BT2100:
      switch (dest_encoding) {
        case ULTRAHDR_COLORGAMUT_BT709:
          coeffs_ptr = &kYuvBt2100ToBt709;
          break;
        case ULTRAHDR_COLORGAMUT_P3:
          coeffs_ptr = &kYuvBt2100ToBt601;
          break;
        case ULTRAHDR_COLORGAMUT_BT2100:
          return JPEGR_NO_ERROR;
        default:
          // Should be impossible to hit after input validation
          return ERROR_JPEGR_INVALID_COLORGAMUT;
      }
      break;
    default:
      // Should be impossible to hit after input validation
      return ERROR_JPEGR_INVALID_COLORGAMUT;
  }

  if (coeffs_ptr == nullptr) {
    // Should be impossible to hit after input validation
    return ERROR_JPEGR_INVALID_COLORGAMUT;
  }

  transformYuv420(image, *coeffs_ptr);
  return JPEGR_NO_ERROR;
}

namespace {
float ReinhardMap(float y_hdr, float headroom) {
  float out = 1.0 + y_hdr / (headroom * headroom);
  out /= 1.0 + y_hdr;
  return out * y_hdr;
}
}  // namespace

GlobalTonemapOutputs hlgGlobalTonemap(const std::array<float, 3>& rgb_in, float headroom) {
  constexpr float kRgbToYBt2020[3] = {0.2627f, 0.6780f, 0.0593f};
  constexpr float kOotfGamma = 1.2f;

  // Apply OOTF and Scale to Headroom to get HDR values that are referenced to
  // SDR white. The range [0.0, 1.0] is linearly stretched to [0.0, headroom]
  // after the OOTF.
  const float y_in =
      rgb_in[0] * kRgbToYBt2020[0] + rgb_in[1] * kRgbToYBt2020[1] + rgb_in[2] * kRgbToYBt2020[2];
  const float y_ootf_div_y_in = std::pow(y_in, kOotfGamma - 1.0f);
  std::array<float, 3> rgb_hdr;
  std::transform(rgb_in.begin(), rgb_in.end(), rgb_hdr.begin(),
                 [&](float x) { return x * headroom * y_ootf_div_y_in; });

  // Apply a tone mapping to compress the range [0, headroom] to [0, 1] by
  // keeping the shadows the same and crushing the highlights.
  float max_hdr = *std::max_element(rgb_hdr.begin(), rgb_hdr.end());
  float max_sdr = ReinhardMap(max_hdr, headroom);
  std::array<float, 3> rgb_sdr;
  std::transform(rgb_hdr.begin(), rgb_hdr.end(), rgb_sdr.begin(), [&](float x) {
    if (x > 0.0f) {
      return x * max_sdr / max_hdr;
    }
    return 0.0f;
  });

  GlobalTonemapOutputs tonemap_outputs;
  tonemap_outputs.rgb_out = rgb_sdr;
  tonemap_outputs.y_hdr = max_hdr;
  tonemap_outputs.y_sdr = max_sdr;
  return tonemap_outputs;
}

uint8_t ScaleTo8Bit(float value) {
  constexpr float kMaxValFloat = 255.0f;
  constexpr int kMaxValInt = 255;
  return std::clamp(static_cast<int>(std::round(value * kMaxValFloat)), 0, kMaxValInt);
}

status_t JpegR::toneMap(jr_uncompressed_ptr src, jr_uncompressed_ptr dest,
                        ultrahdr_transfer_function hdr_tf) {
  if (src == nullptr || dest == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }
  if (src->width != dest->width || src->height != dest->height) {
    return ERROR_JPEGR_RESOLUTION_MISMATCH;
  }

  dest->colorGamut = ULTRAHDR_COLORGAMUT_P3;

  size_t width = src->width;
  size_t height = src->height;

  ColorTransformFn hdrYuvToRgbFn = nullptr;
  switch (src->colorGamut) {
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
      return ERROR_JPEGR_INVALID_COLORGAMUT;
  }

  ColorTransformFn hdrInvOetf = nullptr;
  switch (hdr_tf) {
    case ULTRAHDR_TF_HLG:
#if USE_HLG_INVOETF_LUT
      hdrInvOetf = hlgInvOetfLUT;
#else
      hdrInvOetf = hlgInvOetf;
#endif
      break;
    case ULTRAHDR_TF_PQ:
#if USE_PQ_INVOETF_LUT
      hdrInvOetf = pqInvOetfLUT;
#else
      hdrInvOetf = pqInvOetf;
#endif
      break;
    default:
      // Should be impossible to hit after input validation.
      return ERROR_JPEGR_INVALID_TRANS_FUNC;
  }

  ColorTransformFn hdrGamutConversionFn = getHdrConversionFn(dest->colorGamut, src->colorGamut);

  size_t luma_stride = dest->luma_stride == 0 ? dest->width : dest->luma_stride;
  size_t chroma_stride = dest->chroma_stride == 0 ? luma_stride / 2 : dest->chroma_stride;
  if (dest->chroma_data == nullptr) {
    uint8_t* data = reinterpret_cast<uint8_t*>(dest->data);
    dest->chroma_data = data + luma_stride * dest->height;
  }
  uint8_t* luma_data = reinterpret_cast<uint8_t*>(dest->data);
  uint8_t* chroma_data = reinterpret_cast<uint8_t*>(dest->chroma_data);

  float u_max = 0.0f;

  for (unsigned y = 0; y < height; y += 2) {
    for (unsigned x = 0; x < width; x += 2) {
      // We assume the input is P010, and output is YUV420
      float sdr_u_gamma = 0.0f;
      float sdr_v_gamma = 0.0f;
      for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
          Color hdr_yuv_gamma = getP010Pixel(src, x + j, y + i);
          Color hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);

          Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);

          GlobalTonemapOutputs tonemap_outputs =
              hlgGlobalTonemap({hdr_rgb.r, hdr_rgb.g, hdr_rgb.b}, kHlgHeadroom);
          Color sdr_rgb_linear_bt2100 = {{{tonemap_outputs.rgb_out[0], tonemap_outputs.rgb_out[1],
                                           tonemap_outputs.rgb_out[2]}}};
          Color sdr_rgb = hdrGamutConversionFn(sdr_rgb_linear_bt2100);

          // Hard clip out-of-gamut values;
          sdr_rgb = clampPixelFloat(sdr_rgb);

          Color sdr_rgb_gamma = srgbOetf(sdr_rgb);
          Color sdr_yuv_gamma = srgbRgbToYuv(sdr_rgb_gamma);

          sdr_yuv_gamma += {{{0.0f, 0.5f, 0.5f}}};

          if (u_max < hdr_yuv_gamma.u) {
            u_max = hdr_yuv_gamma.u;
          }

          size_t out_y_idx = (y + i) * luma_stride + x + j;
          luma_data[out_y_idx] = ScaleTo8Bit(sdr_yuv_gamma.y);

          sdr_u_gamma += sdr_yuv_gamma.u * 0.25f;
          sdr_v_gamma += sdr_yuv_gamma.v * 0.25f;
        }
      }
      size_t out_chroma_idx = x / 2 + (y / 2) * chroma_stride;
      size_t offset_cr = chroma_stride * (dest->height / 2);
      chroma_data[out_chroma_idx] = ScaleTo8Bit(sdr_u_gamma);
      chroma_data[out_chroma_idx + offset_cr] = ScaleTo8Bit(sdr_v_gamma);
    }
  }

  return JPEGR_NO_ERROR;
}

}  // namespace ultrahdr
