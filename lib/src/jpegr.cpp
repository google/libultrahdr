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

// Default gamma value for gain map
static const float kGainMapGammaDefault = 1.0f;

// Gain map metadata
static const bool kWriteXmpMetadata = true;
static const bool kWriteIso21496_1Metadata = false;

static const string kXmpNameSpace = "http://ns.adobe.com/xap/1.0/";
static const string kIsoNameSpace = "urn:iso:std:iso:ts:21496:-1";

static_assert(kWriteXmpMetadata || kWriteIso21496_1Metadata,
              "Must write gain map metadata in XMP format, or iso 21496-1 format, or both.");

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

JpegR::JpegR(size_t mapDimensionScaleFactor, int mapCompressQuality, bool useMultiChannelGainMap) {
  mMapDimensionScaleFactor = mapDimensionScaleFactor;
  mMapCompressQuality = mapCompressQuality;
  mUseMultiChannelGainMap = useMultiChannelGainMap;
}

/*
 * Helper function copies the JPEG image from without EXIF.
 *
 * @param pDest destination of the data to be written.
 * @param pSource source of data being written.
 * @param exif_pos position of the EXIF package, which is aligned with jpegdecoder.getEXIFPos().
 *                 (4 bytes offset to FF sign, the byte after FF E1 XX XX <this byte>).
 * @param exif_size exif size without the initial 4 bytes, aligned with jpegdecoder.getEXIFSize().
 */
static void copyJpegWithoutExif(uhdr_compressed_image_t* pDest, uhdr_compressed_image_t* pSource,
                                size_t exif_pos, size_t exif_size) {
  const size_t exif_offset = 4;  // exif_pos has 4 bytes offset to the FF sign
  pDest->data_sz = pSource->data_sz - exif_size - exif_offset;
  pDest->data = new uint8_t[pDest->data_sz];
  pDest->capacity = pDest->data_sz;
  pDest->cg = pSource->cg;
  pDest->ct = pSource->ct;
  pDest->range = pSource->range;
  memcpy(pDest->data, pSource->data, exif_pos - exif_offset);
  memcpy((uint8_t*)pDest->data + exif_pos - exif_offset,
         (uint8_t*)pSource->data + exif_pos + exif_size, pSource->data_sz - exif_pos - exif_size);
}

/* Encode API-0 */
uhdr_error_info_t JpegR::encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_compressed_image_t* dest,
                                     int quality, uhdr_mem_block_t* exif) {
  std::unique_ptr<uhdr_raw_image_ext_t> sdr_intent = std::make_unique<uhdr_raw_image_ext_t>(
      UHDR_IMG_FMT_12bppYCbCr420, UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED,
      hdr_intent->w, hdr_intent->h, 64);

  // tone map
  UHDR_ERR_CHECK(toneMap(hdr_intent, sdr_intent.get()));

  // generate gain map
  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
  UHDR_ERR_CHECK(generateGainMap(sdr_intent.get(), hdr_intent, &metadata, gainmap,
                                 /* sdr_is_601 */ false,
                                 /* use_luminance */ false));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  UHDR_ERR_CHECK(compressGainMap(gainmap.get(), &jpeg_enc_obj_gm));
  uhdr_compressed_image_t gainmap_compressed = jpeg_enc_obj_gm.getCompressedImage();

  std::shared_ptr<DataStruct> icc = IccHelper::writeIccProfile(UHDR_CT_SRGB, sdr_intent->cg);

  // compress sdr image
  JpegEncoderHelper jpeg_enc_obj_sdr;
  UHDR_ERR_CHECK(
      jpeg_enc_obj_sdr.compressImage(sdr_intent.get(), quality, icc->getData(), icc->getLength()));
  uhdr_compressed_image_t sdr_intent_compressed = jpeg_enc_obj_sdr.getCompressedImage();
  sdr_intent_compressed.cg = sdr_intent->cg;

  // append gain map, no ICC since JPEG encode already did it
  UHDR_ERR_CHECK(appendGainMap(&sdr_intent_compressed, &gainmap_compressed, exif, /* icc */ nullptr,
                               /* icc size */ 0, &metadata, dest));
  return g_no_error;
}

/* Encode API-1 */
uhdr_error_info_t JpegR::encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent,
                                     uhdr_compressed_image_t* dest, int quality,
                                     uhdr_mem_block_t* exif) {
  // generate gain map
  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
  UHDR_ERR_CHECK(generateGainMap(sdr_intent, hdr_intent, &metadata, gainmap));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  UHDR_ERR_CHECK(compressGainMap(gainmap.get(), &jpeg_enc_obj_gm));
  uhdr_compressed_image_t gainmap_compressed = jpeg_enc_obj_gm.getCompressedImage();

  std::shared_ptr<DataStruct> icc = IccHelper::writeIccProfile(UHDR_CT_SRGB, sdr_intent->cg);

  // convert to bt601 YUV encoding for JPEG encode
#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
  UHDR_ERR_CHECK(convertYuv_neon(sdr_intent, sdr_intent->cg, UHDR_CG_DISPLAY_P3));
#else
  UHDR_ERR_CHECK(convertYuv(sdr_intent, sdr_intent->cg, UHDR_CG_DISPLAY_P3));
#endif

  // compress sdr image
  JpegEncoderHelper jpeg_enc_obj_sdr;
  UHDR_ERR_CHECK(
      jpeg_enc_obj_sdr.compressImage(sdr_intent, quality, icc->getData(), icc->getLength()));
  uhdr_compressed_image_t sdr_intent_compressed = jpeg_enc_obj_sdr.getCompressedImage();
  sdr_intent_compressed.cg = sdr_intent->cg;

  // append gain map, no ICC since JPEG encode already did it
  UHDR_ERR_CHECK(appendGainMap(&sdr_intent_compressed, &gainmap_compressed, exif, /* icc */ nullptr,
                               /* icc size */ 0, &metadata, dest));
  return g_no_error;
}

/* Encode API-2 */
uhdr_error_info_t JpegR::encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent,
                                     uhdr_compressed_image_t* sdr_intent_compressed,
                                     uhdr_compressed_image_t* dest) {
  // generate gain map
  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
  UHDR_ERR_CHECK(generateGainMap(sdr_intent, hdr_intent, &metadata, gainmap));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  UHDR_ERR_CHECK(compressGainMap(gainmap.get(), &jpeg_enc_obj_gm));
  uhdr_compressed_image_t gainmap_compressed = jpeg_enc_obj_gm.getCompressedImage();

  return encodeJPEGR(sdr_intent_compressed, &gainmap_compressed, &metadata, dest);
}

/* Encode API-3 */
uhdr_error_info_t JpegR::encodeJPEGR(uhdr_raw_image_t* hdr_intent,
                                     uhdr_compressed_image_t* sdr_intent_compressed,
                                     uhdr_compressed_image_t* dest) {
  // decode input jpeg, gamut is going to be bt601.
  JpegDecoderHelper jpeg_dec_obj_sdr;
  UHDR_ERR_CHECK(jpeg_dec_obj_sdr.decompressImage(sdr_intent_compressed->data,
                                                  sdr_intent_compressed->data_sz));

  uhdr_raw_image_t sdr_intent = jpeg_dec_obj_sdr.getDecompressedImage();
  if (jpeg_dec_obj_sdr.getICCSize() > 0) {
    uhdr_color_gamut_t cg =
        IccHelper::readIccColorGamut(jpeg_dec_obj_sdr.getICCPtr(), jpeg_dec_obj_sdr.getICCSize());
    if (cg == UHDR_CG_UNSPECIFIED ||
        (sdr_intent_compressed->cg != UHDR_CG_UNSPECIFIED && sdr_intent_compressed->cg != cg)) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "configured color gamut %d does not match with color gamut specified in icc box %d",
               sdr_intent_compressed->cg, cg);
      return status;
    }
    sdr_intent.cg = cg;
  } else {
    if (sdr_intent_compressed->cg <= UHDR_CG_UNSPECIFIED ||
        sdr_intent_compressed->cg > UHDR_CG_BT_2100) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "Unrecognized 420 color gamut %d",
               sdr_intent_compressed->cg);
      return status;
    }
    sdr_intent.cg = sdr_intent_compressed->cg;
  }

  if (hdr_intent->w != sdr_intent.w || hdr_intent->h != sdr_intent.h) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "sdr intent resolution %dx%d and hdr intent resolution %dx%d do not match",
             sdr_intent.w, sdr_intent.h, hdr_intent->w, hdr_intent->h);
    return status;
  }

  // generate gain map
  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
  UHDR_ERR_CHECK(
      generateGainMap(&sdr_intent, hdr_intent, &metadata, gainmap, true /* sdr_is_601 */));

  // compress gain map
  JpegEncoderHelper jpeg_enc_obj_gm;
  UHDR_ERR_CHECK(compressGainMap(gainmap.get(), &jpeg_enc_obj_gm));
  uhdr_compressed_image_t gainmap_compressed = jpeg_enc_obj_gm.getCompressedImage();

  return encodeJPEGR(sdr_intent_compressed, &gainmap_compressed, &metadata, dest);
}

/* Encode API-4 */
uhdr_error_info_t JpegR::encodeJPEGR(uhdr_compressed_image_t* base_img_compressed,
                                     uhdr_compressed_image_t* gainmap_img_compressed,
                                     uhdr_gainmap_metadata_ext_t* metadata,
                                     uhdr_compressed_image_t* dest) {
  // We just want to check if ICC is present, so don't do a full decode. Note,
  // this doesn't verify that the ICC is valid.
  JpegDecoderHelper decoder;
  UHDR_ERR_CHECK(decoder.parseImage(base_img_compressed->data, base_img_compressed->data_sz));

  // Add ICC if not already present.
  if (decoder.getICCSize() > 0) {
    UHDR_ERR_CHECK(appendGainMap(base_img_compressed, gainmap_img_compressed, /* exif */ nullptr,
                                 /* icc */ nullptr, /* icc size */ 0, metadata, dest));
  } else {
    if (base_img_compressed->cg <= UHDR_CG_UNSPECIFIED ||
        base_img_compressed->cg > UHDR_CG_BT_2100) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "Unrecognized 420 color gamut %d",
               base_img_compressed->cg);
      return status;
    }
    std::shared_ptr<DataStruct> newIcc =
        IccHelper::writeIccProfile(UHDR_CT_SRGB, base_img_compressed->cg);
    UHDR_ERR_CHECK(appendGainMap(base_img_compressed, gainmap_img_compressed, /* exif */ nullptr,
                                 newIcc->getData(), newIcc->getLength(), metadata, dest));
  }

  return g_no_error;
}

uhdr_error_info_t JpegR::convertYuv(uhdr_raw_image_t* image, uhdr_color_gamut_t src_encoding,
                                    uhdr_color_gamut_t dst_encoding) {
  const std::array<float, 9>* coeffs_ptr = nullptr;
  uhdr_error_info_t status = g_no_error;

  switch (src_encoding) {
    case UHDR_CG_BT_709:
      switch (dst_encoding) {
        case UHDR_CG_BT_709:
          return status;
        case UHDR_CG_DISPLAY_P3:
          coeffs_ptr = &kYuvBt709ToBt601;
          break;
        case UHDR_CG_BT_2100:
          coeffs_ptr = &kYuvBt709ToBt2100;
          break;
        default:
          status.error_code = UHDR_CODEC_INVALID_PARAM;
          status.has_detail = 1;
          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
                   dst_encoding);
          return status;
      }
      break;
    case UHDR_CG_DISPLAY_P3:
      switch (dst_encoding) {
        case UHDR_CG_BT_709:
          coeffs_ptr = &kYuvBt601ToBt709;
          break;
        case UHDR_CG_DISPLAY_P3:
          return status;
        case UHDR_CG_BT_2100:
          coeffs_ptr = &kYuvBt601ToBt2100;
          break;
        default:
          status.error_code = UHDR_CODEC_INVALID_PARAM;
          status.has_detail = 1;
          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
                   dst_encoding);
          return status;
      }
      break;
    case UHDR_CG_BT_2100:
      switch (dst_encoding) {
        case UHDR_CG_BT_709:
          coeffs_ptr = &kYuvBt2100ToBt709;
          break;
        case UHDR_CG_DISPLAY_P3:
          coeffs_ptr = &kYuvBt2100ToBt601;
          break;
        case UHDR_CG_BT_2100:
          return status;
        default:
          status.error_code = UHDR_CODEC_INVALID_PARAM;
          status.has_detail = 1;
          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
                   dst_encoding);
          return status;
      }
      break;
    default:
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "Unrecognized src color gamut %d",
               src_encoding);
      return status;
  }

  transformYuv420(image, *coeffs_ptr);

  return status;
}

uhdr_error_info_t JpegR::compressGainMap(uhdr_raw_image_t* gainmap_img,
                                         JpegEncoderHelper* jpeg_enc_obj) {
  return jpeg_enc_obj->compressImage(gainmap_img, mMapCompressQuality, nullptr, 0);
}

uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* hdr_intent,
                                         uhdr_gainmap_metadata_ext_t* gainmap_metadata,
                                         std::unique_ptr<uhdr_raw_image_ext_t>& gainmap_img,
                                         bool sdr_is_601, bool use_luminance) {
  uhdr_error_info_t status = g_no_error;

  if (sdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCr444 &&
      sdr_intent->fmt != UHDR_IMG_FMT_16bppYCbCr422 &&
      sdr_intent->fmt != UHDR_IMG_FMT_12bppYCbCr420) {
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "generate gainmap method expects sdr intent color format to be one of "
             "{UHDR_IMG_FMT_24bppYCbCr444, UHDR_IMG_FMT_16bppYCbCr422, "
             "UHDR_IMG_FMT_12bppYCbCr420}. Received %d",
             sdr_intent->fmt);
    return status;
  }
  if (hdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCrP010) {
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "generate gainmap method expects hdr intent color format to be one of "
             "{UHDR_IMG_FMT_24bppYCbCrP010}. Received %d",
             hdr_intent->fmt);
    return status;
  }

  /*if (mUseMultiChannelGainMap) {
    if (!kWriteIso21496_1Metadata || kWriteXmpMetadata) {
      status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "Multi-channel gain map is only supported for ISO 21496-1 metadata");
      return status;
    }
  }*/

  ColorTransformFn hdrInvOetf = getInverseOetf(hdr_intent->ct);
  if (hdrInvOetf == nullptr) {
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "No implementation available for converting transfer characteristics %d to linear",
             hdr_intent->ct);
    return status;
  }

  float hdr_white_nits = getMaxDisplayMasteringLuminance(hdr_intent->ct);
  if (hdr_white_nits == -1.0f) {
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "Did not receive valid maxCLL for display with transfer characteristics %d",
             hdr_intent->ct);
    return status;
  }

  gainmap_metadata->max_content_boost = hdr_white_nits / kSdrWhiteNits;
  gainmap_metadata->min_content_boost = 1.0f;
  gainmap_metadata->gamma = kGainMapGammaDefault;
  gainmap_metadata->offset_sdr = 0.0f;
  gainmap_metadata->offset_hdr = 0.0f;
  gainmap_metadata->hdr_capacity_min = 1.0f;
  gainmap_metadata->hdr_capacity_max = gainmap_metadata->max_content_boost;

  float log2MinBoost = log2(gainmap_metadata->min_content_boost);
  float log2MaxBoost = log2(gainmap_metadata->max_content_boost);

  ColorTransformFn hdrGamutConversionFn = getGamutConversionFn(sdr_intent->cg, hdr_intent->cg);
  if (hdrGamutConversionFn == nullptr) {
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "No implementation available for gamut conversion from %d to %d", hdr_intent->cg,
             sdr_intent->cg);
    return status;
  }

  ColorTransformFn sdrYuvToRgbFn = getYuvToRgbFn(sdr_intent->cg);
  if (sdrYuvToRgbFn == nullptr) {
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "No implementation available for converting yuv to rgb for color gamut %d",
             sdr_intent->cg);
    return status;
  }

  ColorTransformFn hdrYuvToRgbFn = getYuvToRgbFn(hdr_intent->cg);
  if (hdrYuvToRgbFn == nullptr) {
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "No implementation available for converting yuv to rgb for color gamut %d",
             hdr_intent->cg);
    return status;
  }

  ColorCalculationFn luminanceFn = getLuminanceFn(sdr_intent->cg);
  if (luminanceFn == nullptr) {
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "No implementation available for computing luminance for color gamut %d",
             sdr_intent->cg);
    return status;
  }

  samplePixelFn sdr_sample_pixel_fn = nullptr;
  switch (sdr_intent->fmt) {
    case UHDR_IMG_FMT_24bppYCbCr444:
      sdr_sample_pixel_fn = sampleYuv444;
      break;
    case UHDR_IMG_FMT_16bppYCbCr422:
      sdr_sample_pixel_fn = sampleYuv422;
      break;
    case UHDR_IMG_FMT_12bppYCbCr420:
      sdr_sample_pixel_fn = sampleYuv420;
      break;
    default:
      status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "Unsupported sdr intent color format in apply gainmap %d", sdr_intent->fmt);
      return status;
  }

  if (sdr_is_601) {
    sdrYuvToRgbFn = p3YuvToRgb;
  }

  size_t image_width = sdr_intent->w;
  size_t image_height = sdr_intent->h;
  size_t map_width = image_width / mMapDimensionScaleFactor;
  size_t map_height = image_height / mMapDimensionScaleFactor;
  if (map_width == 0 || map_height == 0) {
    int scaleFactor = (std::min)(image_width, image_height);
    scaleFactor = (scaleFactor >= DCTSIZE) ? (scaleFactor / DCTSIZE) : 1;
    ALOGW(
        "configured gainmap scale factor is resulting in gainmap width and/or height to be zero, "
        "image width %d, image height %d, scale factor %d. Modiyfing gainmap scale factor to %d ",
        (int)image_width, (int)image_height, (int)mMapDimensionScaleFactor, scaleFactor);
    setMapDimensionScaleFactor(scaleFactor);
    map_width = image_width / mMapDimensionScaleFactor;
    map_height = image_height / mMapDimensionScaleFactor;
  }

  gainmap_img = std::make_unique<uhdr_raw_image_ext_t>(
      mUseMultiChannelGainMap ? UHDR_IMG_FMT_24bppRGB888 : UHDR_IMG_FMT_8bppYCbCr400,
      UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, map_width, map_height, 64);
  uhdr_raw_image_ext_t* dest = gainmap_img.get();

  const int threads = (std::min)(GetCPUCoreCount(), 4);
  const int jobSizeInRows = 1;
  size_t rowStep = threads == 1 ? map_height : jobSizeInRows;
  JobQueue jobQueue;
  std::function<void()> generateMap =
      [this, sdr_intent, hdr_intent, gainmap_metadata, dest, hdrInvOetf, hdrGamutConversionFn,
       luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn, sdr_sample_pixel_fn, hdr_white_nits, log2MinBoost,
       log2MaxBoost, use_luminance, &jobQueue]() -> void {
    size_t rowStart, rowEnd;
    while (jobQueue.dequeueJob(rowStart, rowEnd)) {
      for (size_t y = rowStart; y < rowEnd; ++y) {
        for (size_t x = 0; x < dest->w; ++x) {
          Color sdr_yuv_gamma = sdr_sample_pixel_fn(sdr_intent, mMapDimensionScaleFactor, x, y);
          Color sdr_rgb_gamma = sdrYuvToRgbFn(sdr_yuv_gamma);
          // We are assuming the SDR input is always sRGB transfer.
#if USE_SRGB_INVOETF_LUT
          Color sdr_rgb = srgbInvOetfLUT(sdr_rgb_gamma);
#else
          Color sdr_rgb = srgbInvOetf(sdr_rgb_gamma);
#endif

          Color hdr_yuv_gamma = sampleP010(hdr_intent, mMapDimensionScaleFactor, x, y);
          Color hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
          Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
          hdr_rgb = hdrGamutConversionFn(hdr_rgb);

          if (mUseMultiChannelGainMap) {
            Color sdr_rgb_nits = sdr_rgb * kSdrWhiteNits;
            Color hdr_rgb_nits = hdr_rgb * hdr_white_nits;
            size_t pixel_idx = (x + y * dest->stride[UHDR_PLANE_PACKED]) * 3;

            reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] = encodeGain(
                sdr_rgb_nits.r, hdr_rgb_nits.r, gainmap_metadata, log2MinBoost, log2MaxBoost);
            reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx + 1] = encodeGain(
                sdr_rgb_nits.g, hdr_rgb_nits.g, gainmap_metadata, log2MinBoost, log2MaxBoost);
            reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx + 2] = encodeGain(
                sdr_rgb_nits.b, hdr_rgb_nits.b, gainmap_metadata, log2MinBoost, log2MaxBoost);
          } else {
            float sdr_y_nits;
            float hdr_y_nits;
            if (use_luminance) {
              sdr_y_nits = luminanceFn(sdr_rgb) * kSdrWhiteNits;
              hdr_y_nits = luminanceFn(hdr_rgb) * hdr_white_nits;
            } else {
              sdr_y_nits = fmax(sdr_rgb.r, fmax(sdr_rgb.g, sdr_rgb.b)) * kSdrWhiteNits;
              hdr_y_nits = fmax(hdr_rgb.r, fmax(hdr_rgb.g, hdr_rgb.b)) * hdr_white_nits;
            }

            size_t pixel_idx = x + y * dest->stride[UHDR_PLANE_Y];

            reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_Y])[pixel_idx] =
                encodeGain(sdr_y_nits, hdr_y_nits, gainmap_metadata, log2MinBoost, log2MaxBoost);
          }
        }
      }
    }
  };

  // generate map
  std::vector<std::thread> workers;
  for (int th = 0; th < threads - 1; th++) {
    workers.push_back(std::thread(generateMap));
  }

  for (size_t rowStart = 0; rowStart < map_height;) {
    size_t rowEnd = (std::min)(rowStart + rowStep, map_height);
    jobQueue.enqueueJob(rowStart, rowEnd);
    rowStart = rowEnd;
  }
  jobQueue.markQueueForEnd();
  generateMap();
  std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });

  return status;
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
uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compressed,
                                       uhdr_compressed_image_t* gainmap_compressed,
                                       uhdr_mem_block_t* pExif, void* pIcc, size_t icc_size,
                                       uhdr_gainmap_metadata_ext_t* metadata,
                                       uhdr_compressed_image_t* dest) {
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
  uhdr_gainmap_metadata_frac iso_secondary_metadata;
  std::vector<uint8_t> iso_secondary_data;
  UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(
      metadata, &iso_secondary_metadata));

  UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&iso_secondary_metadata,
                                                                   iso_secondary_data));

  // iso_secondary_length = 2 bytes representing the length of the package +
  //  + isoNameSpaceLength = 28 bytes length
  //  + length of iso metadata packet = iso_secondary_data.size()
  const int iso_secondary_length = 2 + isoNameSpaceLength + iso_secondary_data.size();

  int secondary_image_size = 2 /* 2 bytes length of APP1 sign */ + gainmap_compressed->data_sz;
  if (kWriteXmpMetadata) {
    secondary_image_size += xmp_secondary_length;
  }
  if (kWriteIso21496_1Metadata) {
    secondary_image_size += iso_secondary_length;
  }

  // Check if EXIF package presents in the JPEG input.
  // If so, extract and remove the EXIF package.
  JpegDecoderHelper decoder;
  UHDR_ERR_CHECK(decoder.parseImage(sdr_intent_compressed->data, sdr_intent_compressed->data_sz));

  uhdr_mem_block_t exif_from_jpg;
  exif_from_jpg.data = nullptr;
  exif_from_jpg.data_sz = 0;

  uhdr_compressed_image_t new_jpg_image;
  new_jpg_image.data = nullptr;
  new_jpg_image.data_sz = 0;
  new_jpg_image.capacity = 0;
  new_jpg_image.cg = UHDR_CG_UNSPECIFIED;
  new_jpg_image.ct = UHDR_CT_UNSPECIFIED;
  new_jpg_image.range = UHDR_CR_UNSPECIFIED;

  std::unique_ptr<uint8_t[]> dest_data;
  if (decoder.getEXIFPos() >= 0) {
    if (pExif != nullptr) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "received exif from uhdr_enc_set_exif_data() while the base image intent already "
               "contains exif, unsure which one to use");
      return status;
    }
    copyJpegWithoutExif(&new_jpg_image, sdr_intent_compressed, decoder.getEXIFPos(),
                        decoder.getEXIFSize());
    dest_data.reset(reinterpret_cast<uint8_t*>(new_jpg_image.data));
    exif_from_jpg.data = decoder.getEXIFPtr();
    exif_from_jpg.data_sz = decoder.getEXIFSize();
    pExif = &exif_from_jpg;
  }

  uhdr_compressed_image_t* final_primary_jpg_image_ptr =
      new_jpg_image.data_sz == 0 ? sdr_intent_compressed : &new_jpg_image;

  int pos = 0;
  // Begin primary image
  // Write SOI
  UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
  UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kSOI, 1, pos));

  // Write EXIF
  if (pExif != nullptr) {
    const int length = 2 + pExif->data_sz;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
    UHDR_ERR_CHECK(Write(dest, pExif->data, pExif->data_sz, pos));
  }

  // Prepare and write XMP
  if (kWriteXmpMetadata) {
    const string xmp_primary = generateXmpForPrimaryImage(secondary_image_size, *metadata);
    const int length = 2 + xmpNameSpaceLength + xmp_primary.size();
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
    UHDR_ERR_CHECK(Write(dest, (void*)kXmpNameSpace.c_str(), xmpNameSpaceLength, pos));
    UHDR_ERR_CHECK(Write(dest, (void*)xmp_primary.c_str(), xmp_primary.size(), pos));
  }

  // Write ICC
  if (pIcc != nullptr && icc_size > 0) {
    const int length = icc_size + 2;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
    UHDR_ERR_CHECK(Write(dest, pIcc, icc_size, pos));
  }

  // Prepare and write ISO 21496-1 metadata
  if (kWriteIso21496_1Metadata) {
    const int length = 2 + isoNameSpaceLength + 4;
    uint8_t zero = 0;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
    UHDR_ERR_CHECK(Write(dest, (void*)kIsoNameSpace.c_str(), isoNameSpaceLength, pos));
    UHDR_ERR_CHECK(Write(dest, &zero, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &zero, 1, pos));  // 2 bytes minimum_version: (00 00)
    UHDR_ERR_CHECK(Write(dest, &zero, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &zero, 1, pos));  // 2 bytes writer_version: (00 00)
  }

  // Prepare and write MPF
  {
    const int length = 2 + calculateMpfSize();
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    int primary_image_size = pos + length + final_primary_jpg_image_ptr->data_sz;
    // between APP2 + package size + signature
    // ff e2 00 58 4d 50 46 00
    // 2 + 2 + 4 = 8 (bytes)
    // and ff d8 sign of the secondary image
    int secondary_image_offset = primary_image_size - pos - 8;
    std::shared_ptr<DataStruct> mpf = generateMpf(primary_image_size, 0, /* primary_image_offset */
                                                  secondary_image_size, secondary_image_offset);
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
    UHDR_ERR_CHECK(Write(dest, (void*)mpf->getData(), mpf->getLength(), pos));
  }

  // Write primary image
  UHDR_ERR_CHECK(Write(dest, (uint8_t*)final_primary_jpg_image_ptr->data + 2,
                       final_primary_jpg_image_ptr->data_sz - 2, pos));
  // Finish primary image

  // Begin secondary image (gain map)
  // Write SOI
  UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
  UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kSOI, 1, pos));

  // Prepare and write XMP
  if (kWriteXmpMetadata) {
    const int length = xmp_secondary_length;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
    UHDR_ERR_CHECK(Write(dest, (void*)kXmpNameSpace.c_str(), xmpNameSpaceLength, pos));
    UHDR_ERR_CHECK(Write(dest, (void*)xmp_secondary.c_str(), xmp_secondary.size(), pos));
  }

  // Prepare and write ISO 21496-1 metadata
  if (kWriteIso21496_1Metadata) {
    const int length = iso_secondary_length;
    const uint8_t lengthH = ((length >> 8) & 0xff);
    const uint8_t lengthL = (length & 0xff);
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
    UHDR_ERR_CHECK(Write(dest, (void*)kIsoNameSpace.c_str(), isoNameSpaceLength, pos));
    UHDR_ERR_CHECK(Write(dest, (void*)iso_secondary_data.data(), iso_secondary_data.size(), pos));
  }

  // Write secondary image
  UHDR_ERR_CHECK(
      Write(dest, (uint8_t*)gainmap_compressed->data + 2, gainmap_compressed->data_sz - 2, pos));

  // Set back length
  dest->data_sz = pos;

  // Done!
  return g_no_error;
}

uhdr_error_info_t JpegR::getJPEGRInfo(uhdr_compressed_image_t* uhdr_compressed_img,
                                      jr_info_ptr uhdr_image_info) {
  uhdr_compressed_image_t primary_image, gainmap;

  UHDR_ERR_CHECK(extractPrimaryImageAndGainMap(uhdr_compressed_img, &primary_image, &gainmap))

  UHDR_ERR_CHECK(parseJpegInfo(&primary_image, uhdr_image_info->primaryImgInfo,
                               &uhdr_image_info->width, &uhdr_image_info->height))
  if (uhdr_image_info->gainmapImgInfo != nullptr) {
    UHDR_ERR_CHECK(parseJpegInfo(&gainmap, uhdr_image_info->gainmapImgInfo))
  }

  return g_no_error;
}

uhdr_error_info_t JpegR::parseGainMapMetadata(uint8_t* iso_data, int iso_size, uint8_t* xmp_data,
                                              int xmp_size,
                                              uhdr_gainmap_metadata_ext_t* uhdr_metadata) {
  if (iso_size > 0) {
    if (iso_size < (int)kIsoNameSpace.size() + 1) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_ERROR;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "iso block size needs to be atleast %d but got %d", (int)kIsoNameSpace.size() + 1,
               iso_size);
      return status;
    }
    uhdr_gainmap_metadata_frac decodedMetadata;
    std::vector<uint8_t> iso_vec;
    for (int i = (int)kIsoNameSpace.size() + 1; i < iso_size; i++) {
      iso_vec.push_back(iso_data[i]);
    }

    UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::decodeGainmapMetadata(iso_vec, &decodedMetadata));
    UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&decodedMetadata,
                                                                              uhdr_metadata));
  } else if (xmp_size > 0) {
    UHDR_ERR_CHECK(getMetadataFromXMP(xmp_data, xmp_size, uhdr_metadata));
  } else {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "received no valid buffer to parse gainmap metadata");
    return status;
  }

  return g_no_error;
}

/* Decode API */
uhdr_error_info_t JpegR::decodeJPEGR(uhdr_compressed_image_t* uhdr_compressed_img,
                                     uhdr_raw_image_t* dest, float max_display_boost,
                                     uhdr_color_transfer_t output_ct, uhdr_img_fmt_t output_format,
                                     uhdr_raw_image_t* gainmap_img,
                                     uhdr_gainmap_metadata_t* gainmap_metadata) {
  uhdr_compressed_image_t primary_jpeg_image, gainmap_jpeg_image;
  UHDR_ERR_CHECK(
      extractPrimaryImageAndGainMap(uhdr_compressed_img, &primary_jpeg_image, &gainmap_jpeg_image))

  JpegDecoderHelper jpeg_dec_obj_sdr;
  UHDR_ERR_CHECK(jpeg_dec_obj_sdr.decompressImage(
      primary_jpeg_image.data, primary_jpeg_image.data_sz,
      (output_ct == UHDR_CT_SRGB) ? DECODE_TO_RGB_CS : DECODE_TO_YCBCR_CS));

  JpegDecoderHelper jpeg_dec_obj_gm;
  uhdr_raw_image_t gainmap;
  if (gainmap_img != nullptr || output_ct != UHDR_CT_SRGB) {
    UHDR_ERR_CHECK(jpeg_dec_obj_gm.decompressImage(gainmap_jpeg_image.data,
                                                   gainmap_jpeg_image.data_sz, DECODE_STREAM));
    gainmap = jpeg_dec_obj_gm.getDecompressedImage();
    if (gainmap_img != nullptr) {
      UHDR_ERR_CHECK(copy_raw_image(&gainmap, gainmap_img));
    }
  }

  uhdr_gainmap_metadata_ext_t uhdr_metadata;
  if (gainmap_metadata != nullptr || output_ct != UHDR_CT_SRGB) {
    UHDR_ERR_CHECK(parseGainMapMetadata(static_cast<uint8_t*>(jpeg_dec_obj_gm.getIsoMetadataPtr()),
                                        jpeg_dec_obj_gm.getIsoMetadataSize(),
                                        static_cast<uint8_t*>(jpeg_dec_obj_gm.getXMPPtr()),
                                        jpeg_dec_obj_gm.getXMPSize(), &uhdr_metadata))
    if (gainmap_metadata != nullptr) {
      gainmap_metadata->min_content_boost = uhdr_metadata.min_content_boost;
      gainmap_metadata->max_content_boost = uhdr_metadata.max_content_boost;
      gainmap_metadata->gamma = uhdr_metadata.gamma;
      gainmap_metadata->offset_sdr = uhdr_metadata.offset_sdr;
      gainmap_metadata->offset_hdr = uhdr_metadata.offset_hdr;
      gainmap_metadata->hdr_capacity_min = uhdr_metadata.hdr_capacity_min;
      gainmap_metadata->hdr_capacity_max = uhdr_metadata.hdr_capacity_max;
    }
  }

  uhdr_raw_image_t sdr_intent = jpeg_dec_obj_sdr.getDecompressedImage();
  sdr_intent.cg =
      IccHelper::readIccColorGamut(jpeg_dec_obj_sdr.getICCPtr(), jpeg_dec_obj_sdr.getICCSize());
  if (output_ct == UHDR_CT_SRGB) {
    UHDR_ERR_CHECK(copy_raw_image(&sdr_intent, dest));
    return g_no_error;
  }

  UHDR_ERR_CHECK(applyGainMap(&sdr_intent, &gainmap, &uhdr_metadata, output_ct, output_format,
                              max_display_boost, dest));

  return g_no_error;
}

uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
                                      uhdr_gainmap_metadata_ext_t* gainmap_metadata,
                                      uhdr_color_transfer_t output_ct,
                                      [[maybe_unused]] uhdr_img_fmt_t output_format,
                                      float max_display_boost, uhdr_raw_image_t* dest) {
  if (gainmap_metadata->version.compare(kJpegrVersion)) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "Unsupported gainmap metadata, version. Expected %s, Got %s", kJpegrVersion,
             gainmap_metadata->version.c_str());
    return status;
  }
  if (gainmap_metadata->offset_sdr != 0.0f) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "Unsupported gainmap metadata, offset_sdr. Expected %f, Got %f", 0.0f,
             gainmap_metadata->offset_sdr);
    return status;
  }
  if (gainmap_metadata->offset_hdr != 0.0f) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "Unsupported gainmap metadata, offset_hdr. Expected %f, Got %f", 0.0f,
             gainmap_metadata->offset_hdr);
    return status;
  }
  if (gainmap_metadata->hdr_capacity_min != gainmap_metadata->min_content_boost) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "Unsupported gainmap metadata, min_content_boost. Min content boost is expected to be "
             "same as hdr capacity min. Min content boost %f, Hdr Capacity min %f",
             gainmap_metadata->min_content_boost, gainmap_metadata->hdr_capacity_min);
    return status;
  }
  if (gainmap_metadata->hdr_capacity_max != gainmap_metadata->max_content_boost) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "Unsupported gainmap metadata, max_content_boost. Max content boost is expected to be "
             "same as hdr capacity max. Max content boost %f, Hdr Capacity max %f",
             gainmap_metadata->max_content_boost, gainmap_metadata->hdr_capacity_max);
    return status;
  }
  if (sdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCr444 &&
      sdr_intent->fmt != UHDR_IMG_FMT_16bppYCbCr422 &&
      sdr_intent->fmt != UHDR_IMG_FMT_12bppYCbCr420) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "apply gainmap method expects base image color format to be one of "
             "{UHDR_IMG_FMT_24bppYCbCr444, UHDR_IMG_FMT_16bppYCbCr422, "
             "UHDR_IMG_FMT_12bppYCbCr420}. Received %d",
             sdr_intent->fmt);
    return status;
  }
  if (gainmap_img->fmt != UHDR_IMG_FMT_8bppYCbCr400 &&
      gainmap_img->fmt != UHDR_IMG_FMT_24bppRGB888 &&
      gainmap_img->fmt != UHDR_IMG_FMT_32bppRGBA8888) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "apply gainmap method expects gainmap image color format to be one of "
             "{UHDR_IMG_FMT_8bppYCbCr400, UHDR_IMG_FMT_24bppRGB888, UHDR_IMG_FMT_32bppRGBA8888}. "
             "Received %d",
             gainmap_img->fmt);
    return status;
  }

  {
    float primary_aspect_ratio = (float)sdr_intent->w / sdr_intent->h;
    float gainmap_aspect_ratio = (float)gainmap_img->w / gainmap_img->h;
    float delta_aspect_ratio = fabs(primary_aspect_ratio - gainmap_aspect_ratio);
    // Allow 1% delta
    const float delta_tolerance = 0.01;
    if (delta_aspect_ratio / primary_aspect_ratio > delta_tolerance) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
      status.has_detail = 1;
      snprintf(
          status.detail, sizeof status.detail,
          "gain map dimensions scale factor values for height and width are different, \n primary "
          "image resolution is %ux%u, received gain map resolution is %ux%u",
          sdr_intent->w, sdr_intent->h, gainmap_img->w, gainmap_img->h);
      return status;
    }
  }

  float map_scale_factor = (float)sdr_intent->w / gainmap_img->w;

  dest->cg = sdr_intent->cg;
  // Table will only be used when map scale factor is integer.
  ShepardsIDW idwTable(static_cast<int>(map_scale_factor));
  float display_boost = (std::min)(max_display_boost, gainmap_metadata->max_content_boost);
  GainLUT gainLUT(gainmap_metadata, display_boost);

  getPixelFn get_pixel_fn = nullptr;
  switch (sdr_intent->fmt) {
    case UHDR_IMG_FMT_24bppYCbCr444:
      get_pixel_fn = getYuv444Pixel;
      break;
    case UHDR_IMG_FMT_16bppYCbCr422:
      get_pixel_fn = getYuv422Pixel;
      break;
    case UHDR_IMG_FMT_12bppYCbCr420:
      get_pixel_fn = getYuv420Pixel;
      break;
    default: {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "Unsupported sdr intent color format in apply gainmap %d", sdr_intent->fmt);
      return status;
    }
  }

  JobQueue jobQueue;
  std::function<void()> applyRecMap = [sdr_intent, gainmap_img, dest, &jobQueue, &idwTable,
                                       output_ct, &gainLUT, display_boost, map_scale_factor,
                                       get_pixel_fn]() -> void {
    size_t width = sdr_intent->w;

    size_t rowStart, rowEnd;
    while (jobQueue.dequeueJob(rowStart, rowEnd)) {
      for (size_t y = rowStart; y < rowEnd; ++y) {
        for (size_t x = 0; x < width; ++x) {
          Color yuv_gamma_sdr = get_pixel_fn(sdr_intent, x, y);
          // Assuming the sdr image is a decoded JPEG, we should always use Rec.601 YUV coefficients
          Color rgb_gamma_sdr = p3YuvToRgb(yuv_gamma_sdr);
          // We are assuming the SDR base image is always sRGB transfer.
#if USE_SRGB_INVOETF_LUT
          Color rgb_sdr = srgbInvOetfLUT(rgb_gamma_sdr);
#else
          Color rgb_sdr = srgbInvOetf(rgb_gamma_sdr);
#endif
          Color rgb_hdr;
          if (gainmap_img->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
            float gain;

            if (map_scale_factor != floorf(map_scale_factor)) {
              gain = sampleMap(gainmap_img, map_scale_factor, x, y);
            } else {
              gain = sampleMap(gainmap_img, map_scale_factor, x, y, idwTable);
            }

#if USE_APPLY_GAIN_LUT
            rgb_hdr = applyGainLUT(rgb_sdr, gain, gainLUT);
#else
            rgb_hdr = applyGain(rgb_sdr, gain, metadata, display_boost);
#endif
          } else {
            Color gain;

            if (map_scale_factor != floorf(map_scale_factor)) {
              gain = sampleMap3Channel(gainmap_img, map_scale_factor, x, y,
                                       gainmap_img->fmt == UHDR_IMG_FMT_32bppRGBA8888);
            } else {
              gain = sampleMap3Channel(gainmap_img, map_scale_factor, x, y, idwTable,
                                       gainmap_img->fmt == UHDR_IMG_FMT_32bppRGBA8888);
            }

#if USE_APPLY_GAIN_LUT
            rgb_hdr = applyGainLUT(rgb_sdr, gain, gainLUT);
#else
            rgb_hdr = applyGain(rgb_sdr, gain, metadata, display_boost);
#endif
          }

          rgb_hdr = rgb_hdr / display_boost;
          size_t pixel_idx = x + y * dest->stride[UHDR_PLANE_PACKED];

          switch (output_ct) {
            case UHDR_CT_LINEAR: {
              uint64_t rgba_f16 = colorToRgbaF16(rgb_hdr);
              reinterpret_cast<uint64_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] = rgba_f16;
              break;
            }
            case UHDR_CT_HLG: {
#if USE_HLG_OETF_LUT
              ColorTransformFn hdrOetf = hlgOetfLUT;
#else
              ColorTransformFn hdrOetf = hlgOetf;
#endif
              Color rgb_gamma_hdr = hdrOetf(rgb_hdr);
              uint32_t rgba_1010102 = colorToRgba1010102(rgb_gamma_hdr);
              reinterpret_cast<uint32_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] =
                  rgba_1010102;
              break;
            }
            case UHDR_CT_PQ: {
#if USE_PQ_OETF_LUT
              ColorTransformFn hdrOetf = pqOetfLUT;
#else
              ColorTransformFn hdrOetf = pqOetf;
#endif
              Color rgb_gamma_hdr = hdrOetf(rgb_hdr);
              uint32_t rgba_1010102 = colorToRgba1010102(rgb_gamma_hdr);
              reinterpret_cast<uint32_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] =
                  rgba_1010102;
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
  const int rowStep = threads == 1 ? sdr_intent->h : map_scale_factor;
  for (size_t rowStart = 0; rowStart < sdr_intent->h;) {
    int rowEnd = (std::min)(rowStart + rowStep, (size_t)sdr_intent->h);
    jobQueue.enqueueJob(rowStart, rowEnd);
    rowStart = rowEnd;
  }
  jobQueue.markQueueForEnd();
  applyRecMap();
  std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
  return g_no_error;
}

uhdr_error_info_t JpegR::extractPrimaryImageAndGainMap(uhdr_compressed_image_t* jpegr_image,
                                                       uhdr_compressed_image_t* primary_image,
                                                       uhdr_compressed_image_t* gainmap_image) {
  MessageHandler msg_handler;
  msg_handler.SetMessageWriter(make_unique<AlogMessageWriter>(AlogMessageWriter()));

  std::shared_ptr<DataSegment> seg = DataSegment::Create(
      DataRange(0, jpegr_image->data_sz), static_cast<const uint8_t*>(jpegr_image->data),
      DataSegment::BufferDispositionPolicy::kDontDelete);
  DataSegmentDataSource data_source(seg);

  JpegInfoBuilder jpeg_info_builder;
  jpeg_info_builder.SetImageLimit(2);

  JpegScanner jpeg_scanner(&msg_handler);
  jpeg_scanner.Run(&data_source, &jpeg_info_builder);
  data_source.Reset();

  if (jpeg_scanner.HasError()) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_ERROR;
    status.has_detail = 1;
    auto messages = msg_handler.GetMessages();
    std::string append{};
    for (auto message : messages) append += message.GetText();
    snprintf(status.detail, sizeof status.detail, "%s", append.c_str());
    return status;
  }

  const auto& jpeg_info = jpeg_info_builder.GetInfo();
  const auto& image_ranges = jpeg_info.GetImageRanges();

  if (image_ranges.empty()) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "input uhdr image does not any valid images");
    return status;
  }

  if (primary_image != nullptr) {
    primary_image->data = static_cast<uint8_t*>(jpegr_image->data) + image_ranges[0].GetBegin();
    primary_image->data_sz = image_ranges[0].GetLength();
  }

  if (image_ranges.size() == 1) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "input uhdr image does not contain gainmap image");
    return status;
  }

  if (gainmap_image != nullptr) {
    gainmap_image->data = static_cast<uint8_t*>(jpegr_image->data) + image_ranges[1].GetBegin();
    gainmap_image->data_sz = image_ranges[1].GetLength();
  }

  // TODO: choose primary image and gain map image carefully
  if (image_ranges.size() > 2) {
    ALOGW("Number of jpeg images present %d, primary, gain map images may not be correctly chosen",
          (int)image_ranges.size());
  }

  return g_no_error;
}

uhdr_error_info_t JpegR::parseJpegInfo(uhdr_compressed_image_t* jpeg_image, j_info_ptr image_info,
                                       size_t* img_width, size_t* img_height) {
  JpegDecoderHelper jpeg_dec_obj;
  UHDR_ERR_CHECK(jpeg_dec_obj.parseImage(jpeg_image->data, jpeg_image->data_sz))
  size_t imgWidth, imgHeight, numComponents;
  imgWidth = jpeg_dec_obj.getDecompressedImageWidth();
  imgHeight = jpeg_dec_obj.getDecompressedImageHeight();
  numComponents = jpeg_dec_obj.getNumComponentsInImage();

  if (image_info != nullptr) {
    image_info->width = imgWidth;
    image_info->height = imgHeight;
    image_info->numComponents = numComponents;
    image_info->imgData.resize(jpeg_image->data_sz, 0);
    memcpy(static_cast<void*>(image_info->imgData.data()), jpeg_image->data, jpeg_image->data_sz);
    if (jpeg_dec_obj.getICCSize() != 0) {
      image_info->iccData.resize(jpeg_dec_obj.getICCSize(), 0);
      memcpy(static_cast<void*>(image_info->iccData.data()), jpeg_dec_obj.getICCPtr(),
             jpeg_dec_obj.getICCSize());
    }
    if (jpeg_dec_obj.getEXIFSize() != 0) {
      image_info->exifData.resize(jpeg_dec_obj.getEXIFSize(), 0);
      memcpy(static_cast<void*>(image_info->exifData.data()), jpeg_dec_obj.getEXIFPtr(),
             jpeg_dec_obj.getEXIFSize());
    }
    if (jpeg_dec_obj.getXMPSize() != 0) {
      image_info->xmpData.resize(jpeg_dec_obj.getXMPSize(), 0);
      memcpy(static_cast<void*>(image_info->xmpData.data()), jpeg_dec_obj.getXMPPtr(),
             jpeg_dec_obj.getXMPSize());
    }
    if (jpeg_dec_obj.getIsoMetadataSize() != 0) {
      image_info->isoData.resize(jpeg_dec_obj.getIsoMetadataSize(), 0);
      memcpy(static_cast<void*>(image_info->isoData.data()), jpeg_dec_obj.getIsoMetadataPtr(),
             jpeg_dec_obj.getIsoMetadataSize());
    }
  }
  if (img_width != nullptr && img_height != nullptr) {
    *img_width = imgWidth;
    *img_height = imgHeight;
  }
  return g_no_error;
}

static float ReinhardMap(float y_hdr, float headroom) {
  float out = 1.0 + y_hdr / (headroom * headroom);
  out /= 1.0 + y_hdr;
  return out * y_hdr;
}

GlobalTonemapOutputs globalTonemap(const std::array<float, 3>& rgb_in, float headroom) {
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

uhdr_error_info_t JpegR::toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent) {
  if (sdr_intent->fmt != UHDR_IMG_FMT_12bppYCbCr420) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "tonemap method expects sdr intent color format to be one of "
             "{UHDR_IMG_FMT_12bppYCbCr420}. Received %d",
             sdr_intent->fmt);
    return status;
  }
  if (hdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCrP010) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "tonemap method expects hdr intent color format to be one of "
             "{UHDR_IMG_FMT_24bppYCbCrP010}. Received %d",
             hdr_intent->fmt);
    return status;
  }

  ColorTransformFn hdrYuvToRgbFn = getYuvToRgbFn(hdr_intent->cg);
  if (hdrYuvToRgbFn == nullptr) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "No implementation available for converting yuv to rgb for color gamut %d",
             hdr_intent->cg);
    return status;
  }

  ColorTransformFn hdrInvOetf = getInverseOetf(hdr_intent->ct);
  if (hdrInvOetf == nullptr) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "No implementation available for converting transfer characteristics %d to linear",
             hdr_intent->ct);
    return status;
  }

  float hdr_white_nits = getMaxDisplayMasteringLuminance(hdr_intent->ct);
  if (hdr_white_nits == -1.0f) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "Did not receive valid maxCLL for display with transfer characteristics %d",
             hdr_intent->ct);
    return status;
  }

  sdr_intent->cg = UHDR_CG_DISPLAY_P3;
  sdr_intent->ct = UHDR_CT_SRGB;
  sdr_intent->range = UHDR_CR_FULL_RANGE;

  ColorTransformFn hdrGamutConversionFn = getGamutConversionFn(sdr_intent->cg, hdr_intent->cg);
  uint8_t* luma_data = reinterpret_cast<uint8_t*>(sdr_intent->planes[UHDR_PLANE_Y]);
  uint8_t* cb_data = reinterpret_cast<uint8_t*>(sdr_intent->planes[UHDR_PLANE_U]);
  uint8_t* cr_data = reinterpret_cast<uint8_t*>(sdr_intent->planes[UHDR_PLANE_V]);
  size_t luma_stride = sdr_intent->stride[UHDR_PLANE_Y];
  size_t cb_stride = sdr_intent->stride[UHDR_PLANE_U];
  size_t cr_stride = sdr_intent->stride[UHDR_PLANE_V];
  size_t height = hdr_intent->h;
  const int threads = (std::min)(GetCPUCoreCount(), 4);
  const int jobSizeInRows = 2;  // 420 subsampling
  size_t rowStep = threads == 1 ? height : jobSizeInRows;
  JobQueue jobQueue;
  std::function<void()> toneMapInternal;

  toneMapInternal = [hdr_intent, luma_data, cb_data, cr_data, hdrInvOetf, hdrGamutConversionFn,
                     hdrYuvToRgbFn, luma_stride, cb_stride, cr_stride, hdr_white_nits,
                     &jobQueue]() -> void {
    size_t rowStart, rowEnd;
    while (jobQueue.dequeueJob(rowStart, rowEnd)) {
      for (size_t y = rowStart; y < rowEnd; y += 2) {
        for (size_t x = 0; x < hdr_intent->w; x += 2) {
          // We assume the input is P010, and output is YUV420
          float sdr_u_gamma = 0.0f;
          float sdr_v_gamma = 0.0f;

          for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
              Color hdr_yuv_gamma = getP010Pixel(hdr_intent, x + j, y + i);
              Color hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
              Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);

              GlobalTonemapOutputs tonemap_outputs =
                  globalTonemap({hdr_rgb.r, hdr_rgb.g, hdr_rgb.b}, hdr_white_nits / kSdrWhiteNits);
              Color sdr_rgb_linear_bt2100 = {
                  {{tonemap_outputs.rgb_out[0], tonemap_outputs.rgb_out[1],
                    tonemap_outputs.rgb_out[2]}}};
              Color sdr_rgb = hdrGamutConversionFn(sdr_rgb_linear_bt2100);

              // Hard clip out-of-gamut values;
              sdr_rgb = clampPixelFloat(sdr_rgb);

              Color sdr_rgb_gamma = srgbOetf(sdr_rgb);
              Color sdr_yuv_gamma = p3RgbToYuv(sdr_rgb_gamma);

              sdr_yuv_gamma += {{{0.0f, 0.5f, 0.5f}}};

              size_t out_y_idx = (y + i) * luma_stride + x + j;
              luma_data[out_y_idx] = ScaleTo8Bit(sdr_yuv_gamma.y);

              sdr_u_gamma += sdr_yuv_gamma.u;
              sdr_v_gamma += sdr_yuv_gamma.v;
            }
          }
          sdr_u_gamma *= 0.25f;
          sdr_v_gamma *= 0.25f;
          cb_data[x / 2 + (y / 2) * cb_stride] = ScaleTo8Bit(sdr_u_gamma);
          cr_data[x / 2 + (y / 2) * cr_stride] = ScaleTo8Bit(sdr_v_gamma);
        }
      }
    }
  };

  // tone map
  std::vector<std::thread> workers;
  for (int th = 0; th < threads - 1; th++) {
    workers.push_back(std::thread(toneMapInternal));
  }

  for (size_t rowStart = 0; rowStart < height;) {
    size_t rowEnd = (std::min)(rowStart + rowStep, height);
    jobQueue.enqueueJob(rowStart, rowEnd);
    rowStart = rowEnd;
  }
  jobQueue.markQueueForEnd();
  toneMapInternal();
  std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });

  return g_no_error;
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

uhdr_color_transfer_t map_legacy_ct_to_ct(ultrahdr::ultrahdr_transfer_function ct) {
  switch (ct) {
    case ultrahdr::ULTRAHDR_TF_HLG:
      return UHDR_CT_HLG;
    case ultrahdr::ULTRAHDR_TF_PQ:
      return UHDR_CT_PQ;
    case ultrahdr::ULTRAHDR_TF_LINEAR:
      return UHDR_CT_LINEAR;
    case ultrahdr::ULTRAHDR_TF_SRGB:
      return UHDR_CT_SRGB;
    default:
      return UHDR_CT_UNSPECIFIED;
  }
}

uhdr_color_gamut_t map_legacy_cg_to_cg(ultrahdr::ultrahdr_color_gamut cg) {
  switch (cg) {
    case ultrahdr::ULTRAHDR_COLORGAMUT_BT2100:
      return UHDR_CG_BT_2100;
    case ultrahdr::ULTRAHDR_COLORGAMUT_BT709:
      return UHDR_CG_BT_709;
    case ultrahdr::ULTRAHDR_COLORGAMUT_P3:
      return UHDR_CG_DISPLAY_P3;
    default:
      return UHDR_CG_UNSPECIFIED;
  }
}

ultrahdr::ultrahdr_color_gamut map_cg_to_legacy_cg(uhdr_color_gamut_t cg) {
  switch (cg) {
    case UHDR_CG_BT_2100:
      return ultrahdr::ULTRAHDR_COLORGAMUT_BT2100;
    case UHDR_CG_BT_709:
      return ultrahdr::ULTRAHDR_COLORGAMUT_BT709;
    case UHDR_CG_DISPLAY_P3:
      return ultrahdr::ULTRAHDR_COLORGAMUT_P3;
    default:
      return ultrahdr::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  }
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

  uhdr_raw_image_t hdr_intent;
  hdr_intent.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
  hdr_intent.cg = map_legacy_cg_to_cg(p010_image.colorGamut);
  hdr_intent.ct = map_legacy_ct_to_ct(hdr_tf);
  hdr_intent.range = p010_image.colorRange;
  hdr_intent.w = p010_image.width;
  hdr_intent.h = p010_image.height;
  hdr_intent.planes[UHDR_PLANE_Y] = p010_image.data;
  hdr_intent.stride[UHDR_PLANE_Y] = p010_image.luma_stride;
  hdr_intent.planes[UHDR_PLANE_UV] = p010_image.chroma_data;
  hdr_intent.stride[UHDR_PLANE_UV] = p010_image.chroma_stride;
  hdr_intent.planes[UHDR_PLANE_V] = nullptr;
  hdr_intent.stride[UHDR_PLANE_V] = 0;

  uhdr_compressed_image_t output;
  output.data = dest->data;
  output.data_sz = 0;
  output.capacity = dest->maxLength;
  output.cg = UHDR_CG_UNSPECIFIED;
  output.ct = UHDR_CT_UNSPECIFIED;
  output.range = UHDR_CR_UNSPECIFIED;

  uhdr_mem_block_t exifBlock;
  if (exif) {
    exifBlock.data = exif->data;
    exifBlock.data_sz = exifBlock.capacity = exif->length;
  }

  auto result = encodeJPEGR(&hdr_intent, &output, quality, exif ? &exifBlock : nullptr);
  if (result.error_code == UHDR_CODEC_OK) {
    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
    dest->length = output.data_sz;
  }

  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
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
  uhdr_raw_image_t hdr_intent;
  hdr_intent.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
  hdr_intent.cg = map_legacy_cg_to_cg(p010_image.colorGamut);
  hdr_intent.ct = map_legacy_ct_to_ct(hdr_tf);
  hdr_intent.range = p010_image.colorRange;
  hdr_intent.w = p010_image.width;
  hdr_intent.h = p010_image.height;
  hdr_intent.planes[UHDR_PLANE_Y] = p010_image.data;
  hdr_intent.stride[UHDR_PLANE_Y] = p010_image.luma_stride;
  hdr_intent.planes[UHDR_PLANE_UV] = p010_image.chroma_data;
  hdr_intent.stride[UHDR_PLANE_UV] = p010_image.chroma_stride;
  hdr_intent.planes[UHDR_PLANE_V] = nullptr;
  hdr_intent.stride[UHDR_PLANE_V] = 0;

  jpegr_uncompressed_struct yuv420_image = *yuv420_image_ptr;
  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
  if (!yuv420_image.chroma_data) {
    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
    yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;
    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
  }
  uhdr_raw_image_t sdrRawImg;
  sdrRawImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
  sdrRawImg.cg = map_legacy_cg_to_cg(yuv420_image.colorGamut);
  sdrRawImg.ct = UHDR_CT_SRGB;
  sdrRawImg.range = yuv420_image.colorRange;
  sdrRawImg.w = yuv420_image.width;
  sdrRawImg.h = yuv420_image.height;
  sdrRawImg.planes[UHDR_PLANE_Y] = yuv420_image.data;
  sdrRawImg.stride[UHDR_PLANE_Y] = yuv420_image.luma_stride;
  sdrRawImg.planes[UHDR_PLANE_U] = yuv420_image.chroma_data;
  sdrRawImg.stride[UHDR_PLANE_U] = yuv420_image.chroma_stride;
  uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.chroma_data);
  data += (yuv420_image.height * yuv420_image.chroma_stride) / 2;
  sdrRawImg.planes[UHDR_PLANE_V] = data;
  sdrRawImg.stride[UHDR_PLANE_V] = yuv420_image.chroma_stride;
  auto sdr_intent = convert_raw_input_to_ycbcr(&sdrRawImg);

  uhdr_compressed_image_t output;
  output.data = dest->data;
  output.data_sz = 0;
  output.capacity = dest->maxLength;
  output.cg = UHDR_CG_UNSPECIFIED;
  output.ct = UHDR_CT_UNSPECIFIED;
  output.range = UHDR_CR_UNSPECIFIED;

  uhdr_mem_block_t exifBlock;
  if (exif) {
    exifBlock.data = exif->data;
    exifBlock.data_sz = exifBlock.capacity = exif->length;
  }

  auto result =
      encodeJPEGR(&hdr_intent, sdr_intent.get(), &output, quality, exif ? &exifBlock : nullptr);
  if (result.error_code == UHDR_CODEC_OK) {
    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
    dest->length = output.data_sz;
  }

  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
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
  uhdr_raw_image_t hdr_intent;
  hdr_intent.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
  hdr_intent.cg = map_legacy_cg_to_cg(p010_image.colorGamut);
  hdr_intent.ct = map_legacy_ct_to_ct(hdr_tf);
  hdr_intent.range = p010_image.colorRange;
  hdr_intent.w = p010_image.width;
  hdr_intent.h = p010_image.height;
  hdr_intent.planes[UHDR_PLANE_Y] = p010_image.data;
  hdr_intent.stride[UHDR_PLANE_Y] = p010_image.luma_stride;
  hdr_intent.planes[UHDR_PLANE_UV] = p010_image.chroma_data;
  hdr_intent.stride[UHDR_PLANE_UV] = p010_image.chroma_stride;
  hdr_intent.planes[UHDR_PLANE_V] = nullptr;
  hdr_intent.stride[UHDR_PLANE_V] = 0;

  jpegr_uncompressed_struct yuv420_image = *yuv420_image_ptr;
  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
  if (!yuv420_image.chroma_data) {
    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
    yuv420_image.chroma_data = data + yuv420_image.luma_stride * p010_image.height;
    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
  }
  uhdr_raw_image_t sdrRawImg;
  sdrRawImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
  sdrRawImg.cg = map_legacy_cg_to_cg(yuv420_image.colorGamut);
  sdrRawImg.ct = UHDR_CT_SRGB;
  sdrRawImg.range = yuv420_image.colorRange;
  sdrRawImg.w = yuv420_image.width;
  sdrRawImg.h = yuv420_image.height;
  sdrRawImg.planes[UHDR_PLANE_Y] = yuv420_image.data;
  sdrRawImg.stride[UHDR_PLANE_Y] = yuv420_image.luma_stride;
  sdrRawImg.planes[UHDR_PLANE_U] = yuv420_image.chroma_data;
  sdrRawImg.stride[UHDR_PLANE_U] = yuv420_image.chroma_stride;
  uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.chroma_data);
  data += (yuv420_image.height * yuv420_image.chroma_stride) / 2;
  sdrRawImg.planes[UHDR_PLANE_V] = data;
  sdrRawImg.stride[UHDR_PLANE_V] = yuv420_image.chroma_stride;
  auto sdr_intent = convert_raw_input_to_ycbcr(&sdrRawImg);

  uhdr_compressed_image_t input;
  input.data = yuv420jpg_image_ptr->data;
  input.data_sz = yuv420jpg_image_ptr->length;
  input.capacity = yuv420jpg_image_ptr->maxLength;
  input.cg = map_legacy_cg_to_cg(yuv420jpg_image_ptr->colorGamut);
  input.ct = UHDR_CT_UNSPECIFIED;
  input.range = UHDR_CR_UNSPECIFIED;

  uhdr_compressed_image_t output;
  output.data = dest->data;
  output.data_sz = 0;
  output.capacity = dest->maxLength;
  output.cg = UHDR_CG_UNSPECIFIED;
  output.ct = UHDR_CT_UNSPECIFIED;
  output.range = UHDR_CR_UNSPECIFIED;

  auto result = encodeJPEGR(&hdr_intent, sdr_intent.get(), &input, &output);
  if (result.error_code == UHDR_CODEC_OK) {
    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
    dest->length = output.data_sz;
  }

  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
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
  uhdr_raw_image_t hdr_intent;
  hdr_intent.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
  hdr_intent.cg = map_legacy_cg_to_cg(p010_image.colorGamut);
  hdr_intent.ct = map_legacy_ct_to_ct(hdr_tf);
  hdr_intent.range = p010_image.colorRange;
  hdr_intent.w = p010_image.width;
  hdr_intent.h = p010_image.height;
  hdr_intent.planes[UHDR_PLANE_Y] = p010_image.data;
  hdr_intent.stride[UHDR_PLANE_Y] = p010_image.luma_stride;
  hdr_intent.planes[UHDR_PLANE_UV] = p010_image.chroma_data;
  hdr_intent.stride[UHDR_PLANE_UV] = p010_image.chroma_stride;
  hdr_intent.planes[UHDR_PLANE_V] = nullptr;
  hdr_intent.stride[UHDR_PLANE_V] = 0;

  uhdr_compressed_image_t input;
  input.data = yuv420jpg_image_ptr->data;
  input.data_sz = yuv420jpg_image_ptr->length;
  input.capacity = yuv420jpg_image_ptr->maxLength;
  input.cg = map_legacy_cg_to_cg(yuv420jpg_image_ptr->colorGamut);
  input.ct = UHDR_CT_UNSPECIFIED;
  input.range = UHDR_CR_UNSPECIFIED;

  uhdr_compressed_image_t output;
  output.data = dest->data;
  output.data_sz = 0;
  output.capacity = dest->maxLength;
  output.cg = UHDR_CG_UNSPECIFIED;
  output.ct = UHDR_CT_UNSPECIFIED;
  output.range = UHDR_CR_UNSPECIFIED;

  auto result = encodeJPEGR(&hdr_intent, &input, &output);
  if (result.error_code == UHDR_CODEC_OK) {
    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
    dest->length = output.data_sz;
  }

  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
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

  uhdr_compressed_image_t input;
  input.data = yuv420jpg_image_ptr->data;
  input.data_sz = yuv420jpg_image_ptr->length;
  input.capacity = yuv420jpg_image_ptr->maxLength;
  input.cg = map_legacy_cg_to_cg(yuv420jpg_image_ptr->colorGamut);
  input.ct = UHDR_CT_UNSPECIFIED;
  input.range = UHDR_CR_UNSPECIFIED;

  uhdr_compressed_image_t gainmap;
  gainmap.data = yuv420jpg_image_ptr->data;
  gainmap.data_sz = yuv420jpg_image_ptr->length;
  gainmap.capacity = yuv420jpg_image_ptr->maxLength;
  gainmap.cg = UHDR_CG_UNSPECIFIED;
  gainmap.ct = UHDR_CT_UNSPECIFIED;
  gainmap.range = UHDR_CR_UNSPECIFIED;

  uhdr_compressed_image_t output;
  output.data = dest->data;
  output.data_sz = 0;
  output.capacity = dest->maxLength;
  output.cg = UHDR_CG_UNSPECIFIED;
  output.ct = UHDR_CT_UNSPECIFIED;
  output.range = UHDR_CR_UNSPECIFIED;

  uhdr_gainmap_metadata_ext_t meta;
  meta.version = metadata->version;
  meta.hdr_capacity_max = metadata->hdrCapacityMax;
  meta.hdr_capacity_min = metadata->hdrCapacityMin;
  meta.gamma = metadata->gamma;
  meta.offset_sdr = metadata->offsetSdr;
  meta.offset_hdr = metadata->offsetHdr;
  meta.max_content_boost = metadata->maxContentBoost;
  meta.min_content_boost = metadata->minContentBoost;

  auto result = encodeJPEGR(&input, &gainmap, &meta, &output);
  if (result.error_code == UHDR_CODEC_OK) {
    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
    dest->length = output.data_sz;
  }

  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
}

/* Decode API */
status_t JpegR::getJPEGRInfo(jr_compressed_ptr jpegr_image_ptr, jr_info_ptr jpegr_image_info_ptr) {
  if (jpegr_image_ptr == nullptr || jpegr_image_ptr->data == nullptr) {
    ALOGE("received nullptr for compressed jpegr image");
    return ERROR_JPEGR_BAD_PTR;
  }
  if (jpegr_image_info_ptr == nullptr) {
    ALOGE("received nullptr for compressed jpegr info struct");
    return ERROR_JPEGR_BAD_PTR;
  }

  uhdr_compressed_image_t input;
  input.data = jpegr_image_ptr->data;
  input.data_sz = jpegr_image_ptr->length;
  input.capacity = jpegr_image_ptr->maxLength;
  input.cg = map_legacy_cg_to_cg(jpegr_image_ptr->colorGamut);
  input.ct = UHDR_CT_UNSPECIFIED;
  input.range = UHDR_CR_UNSPECIFIED;

  auto result = getJPEGRInfo(&input, jpegr_image_info_ptr);

  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
}

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

  uhdr_color_transfer_t ct;
  uhdr_img_fmt fmt;
  if (output_format == ULTRAHDR_OUTPUT_HDR_HLG) {
    fmt = UHDR_IMG_FMT_32bppRGBA1010102;
    ct = UHDR_CT_HLG;
  } else if (output_format == ULTRAHDR_OUTPUT_HDR_PQ) {
    fmt = UHDR_IMG_FMT_32bppRGBA1010102;
    ct = UHDR_CT_PQ;
  } else if (output_format == ULTRAHDR_OUTPUT_HDR_LINEAR) {
    fmt = UHDR_IMG_FMT_64bppRGBAHalfFloat;
    ct = UHDR_CT_LINEAR;
  } else if (output_format == ULTRAHDR_OUTPUT_SDR) {
    fmt = UHDR_IMG_FMT_32bppRGBA8888;
    ct = UHDR_CT_SRGB;
  }

  uhdr_compressed_image_t input;
  input.data = jpegr_image_ptr->data;
  input.data_sz = jpegr_image_ptr->length;
  input.capacity = jpegr_image_ptr->maxLength;
  input.cg = map_legacy_cg_to_cg(jpegr_image_ptr->colorGamut);
  input.ct = UHDR_CT_UNSPECIFIED;
  input.range = UHDR_CR_UNSPECIFIED;

  jpeg_info_struct primary_image;
  jpeg_info_struct gainmap_image;
  jpegr_info_struct jpegr_info;
  jpegr_info.primaryImgInfo = &primary_image;
  jpegr_info.gainmapImgInfo = &gainmap_image;
  if (getJPEGRInfo(&input, &jpegr_info).error_code != UHDR_CODEC_OK) return JPEGR_UNKNOWN_ERROR;

  if (exif != nullptr) {
    if (exif->length < primary_image.exifData.size()) {
      return ERROR_JPEGR_BUFFER_TOO_SMALL;
    }
    memcpy(exif->data, primary_image.exifData.data(), primary_image.exifData.size());
    exif->length = primary_image.exifData.size();
  }

  uhdr_raw_image_t output;
  output.fmt = fmt;
  output.cg = UHDR_CG_UNSPECIFIED;
  output.ct = UHDR_CT_UNSPECIFIED;
  output.range = UHDR_CR_UNSPECIFIED;
  output.w = jpegr_info.width;
  output.h = jpegr_info.height;
  output.planes[UHDR_PLANE_PACKED] = dest->data;
  output.stride[UHDR_PLANE_PACKED] = jpegr_info.width;
  output.planes[UHDR_PLANE_U] = nullptr;
  output.stride[UHDR_PLANE_U] = 0;
  output.planes[UHDR_PLANE_V] = nullptr;
  output.stride[UHDR_PLANE_V] = 0;

  uhdr_raw_image_t output_gm;
  if (gainmap_image_ptr) {
    output.fmt =
        gainmap_image.numComponents == 1 ? UHDR_IMG_FMT_8bppYCbCr400 : UHDR_IMG_FMT_24bppRGB888;
    output.cg = UHDR_CG_UNSPECIFIED;
    output.ct = UHDR_CT_UNSPECIFIED;
    output.range = UHDR_CR_UNSPECIFIED;
    output.w = gainmap_image.width;
    output.h = gainmap_image.height;
    output.planes[UHDR_PLANE_PACKED] = gainmap_image_ptr->data;
    output.stride[UHDR_PLANE_PACKED] = gainmap_image.width;
    output.planes[UHDR_PLANE_U] = nullptr;
    output.stride[UHDR_PLANE_U] = 0;
    output.planes[UHDR_PLANE_V] = nullptr;
    output.stride[UHDR_PLANE_V] = 0;
  }

  uhdr_gainmap_metadata_ext_t meta;
  auto result = decodeJPEGR(&input, &output, max_display_boost, ct, fmt,
                            gainmap_image_ptr ? &output_gm : nullptr, metadata ? &meta : nullptr);

  if (result.error_code == UHDR_CODEC_OK) {
    dest->width = output.w;
    dest->height = output.h;
    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
    dest->colorRange = output.range;
    dest->pixelFormat = output.fmt;
    dest->chroma_data = nullptr;
    if (gainmap_image_ptr) {
      gainmap_image_ptr->width = output_gm.w;
      gainmap_image_ptr->height = output_gm.h;
      gainmap_image_ptr->colorGamut = map_cg_to_legacy_cg(output_gm.cg);
      gainmap_image_ptr->colorRange = output_gm.range;
      gainmap_image_ptr->pixelFormat = output_gm.fmt;
      gainmap_image_ptr->chroma_data = nullptr;
    }
    if (metadata) {
      metadata->version = meta.version;
      metadata->hdrCapacityMax = meta.hdr_capacity_max;
      metadata->hdrCapacityMin = meta.hdr_capacity_min;
      metadata->gamma = meta.gamma;
      metadata->offsetSdr = meta.offset_sdr;
      metadata->offsetHdr = meta.offset_hdr;
      metadata->maxContentBoost = meta.max_content_boost;
      metadata->minContentBoost = meta.min_content_boost;
    }
  }

  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
}

}  // namespace ultrahdr
