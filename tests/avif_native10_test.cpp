/*
 * Copyright 2024 The Android Open Source Project
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

#if defined(__has_include)
#if __has_include("testing/base/public/gunit.h")
#include "testing/base/public/gunit.h"
#else
#include <gtest/gtest.h>
#endif
#else
#include <gtest/gtest.h>
#endif

#include <cfloat>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "ultrahdr/avifultrahdr.h"
#include "ultrahdr/gainmapmath.h"

#if defined(UHDR_ENABLE_HEIF)
#include "libheif/heif.h"
#endif

namespace ultrahdr {

#if defined(UHDR_ENABLE_HEIF)

namespace {

constexpr int kWidth = 16;
constexpr int kHeight = 16;
constexpr int kRectangularWidth = 18;
constexpr int kRectangularHeight = 10;
constexpr size_t kOutputCapacity = 4u * 1024u * 1024u;
constexpr uint16_t kP010PaddingSample = 0xffff;

bool isEncoderUnavailable(const uhdr_error_info_t& status) {
  return status.error_code != UHDR_CODEC_OK && status.has_detail &&
         (strstr(status.detail, "Unsupported file-type") != nullptr ||
          strstr(status.detail, "No encoder") != nullptr);
}

struct P010Image {
  P010Image(unsigned int width = kWidth, unsigned int height = kHeight, bool padded = false,
            uhdr_color_gamut_t cg = UHDR_CG_BT_2100, uhdr_color_transfer_t ct = UHDR_CT_HLG,
            uhdr_color_range_t range = UHDR_CR_FULL_RANGE, uint16_t chroma_u = 256,
            uint16_t chroma_v = 768)
      : width(width),
        height(height),
        luma_stride(width + (padded ? 4 : 0)),
        chroma_stride(width + (padded ? 4 : 0)),
        luma(static_cast<size_t>(luma_stride) * height),
        chroma(static_cast<size_t>(chroma_stride) * (height / 2)) {
    std::fill(luma.begin(), luma.end(), kP010PaddingSample);
    std::fill(chroma.begin(), chroma.end(), kP010PaddingSample);
    raw.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
    raw.cg = cg;
    raw.ct = ct;
    raw.range = range;
    raw.w = width;
    raw.h = height;
    raw.planes[UHDR_PLANE_Y] = luma.data();
    raw.planes[UHDR_PLANE_UV] = chroma.data();
    raw.stride[UHDR_PLANE_Y] = luma_stride;
    raw.stride[UHDR_PLANE_UV] = chroma_stride;

    for (unsigned int y = 0; y < height; ++y) {
      for (unsigned int x = 0; x < width; ++x) {
        // Use nontrivial 10-bit values so a native path has useful low bits to preserve.
        const uint16_t value = static_cast<uint16_t>(96 + ((x * 37 + y * 19) % 800));
        luma[static_cast<size_t>(y) * luma_stride + x] = value << 6;
      }
    }
    for (unsigned int y = 0; y < height / 2; ++y) {
      for (unsigned int x = 0; x < width; x += 2) {
        const size_t index = static_cast<size_t>(y) * chroma_stride + x;
        chroma[index] = chroma_u << 6;
        chroma[index + 1] = chroma_v << 6;
      }
    }
  }

  uhdr_raw_image_t raw{};
  unsigned int width;
  unsigned int height;
  unsigned int luma_stride;
  unsigned int chroma_stride;
  std::vector<uint16_t> luma;
  std::vector<uint16_t> chroma;
};

struct Rgba1010102Image {
  Rgba1010102Image(unsigned int width = kWidth, unsigned int height = kHeight)
      : width(width),
        height(height),
        raw(UHDR_IMG_FMT_32bppRGBA1010102, UHDR_CG_BT_2100, UHDR_CT_HLG,
            UHDR_CR_FULL_RANGE, width, height, 64) {
    uint32_t* pixels = static_cast<uint32_t*>(raw.planes[UHDR_PLANE_PACKED]);
    for (unsigned int y = 0; y < height; ++y) {
      for (unsigned int x = 0; x < width; ++x) {
        const uint32_t r = static_cast<uint32_t>(128 + ((x * 31 + y * 17) % 700));
        const uint32_t g = static_cast<uint32_t>(96 + ((x * 23 + y * 29) % 720));
        const uint32_t b = static_cast<uint32_t>(64 + ((x * 19 + y * 37) % 760));
        const Color color = {{{static_cast<float>(r) / 1023.0f, static_cast<float>(g) / 1023.0f,
                              static_cast<float>(b) / 1023.0f}}};
        pixels[static_cast<size_t>(y) * raw.stride[UHDR_PLANE_PACKED] + x] =
            colorToRgba1010102(color);
      }
    }
  }

  unsigned int width;
  unsigned int height;
  uhdr_raw_image_ext_t raw;
};

struct Rgba8888Image {
  Rgba8888Image(unsigned int width = kWidth, unsigned int height = kHeight)
      : width(width),
        height(height),
        raw(UHDR_IMG_FMT_32bppRGBA8888, UHDR_CG_BT_709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
            width, height, 64) {
    uint32_t* pixels = static_cast<uint32_t*>(raw.planes[UHDR_PLANE_PACKED]);
    for (unsigned int y = 0; y < height; ++y) {
      for (unsigned int x = 0; x < width; ++x) {
        const uint32_t r = static_cast<uint32_t>(32 + (x * 13 + y * 3) % 192);
        const uint32_t g = static_cast<uint32_t>(24 + (x * 5 + y * 11) % 208);
        const uint32_t b = static_cast<uint32_t>(16 + (x * 7 + y * 17) % 224);
        pixels[static_cast<size_t>(y) * raw.stride[UHDR_PLANE_PACKED] + x] =
            r | (g << 8) | (b << 16) | (0xffu << 24);
      }
    }
  }

  unsigned int width;
  unsigned int height;
  uhdr_raw_image_ext_t raw;
};

struct Yuv44410Image {
  Yuv44410Image(unsigned int width = kWidth, unsigned int height = kHeight,
                uhdr_color_gamut_t cg = UHDR_CG_BT_709)
      : width(width),
        height(height),
        raw(UHDR_IMG_FMT_30bppYCbCr444, cg, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE, width, height, 64) {
    uint16_t* y = static_cast<uint16_t*>(raw.planes[UHDR_PLANE_Y]);
    uint16_t* u = static_cast<uint16_t*>(raw.planes[UHDR_PLANE_U]);
    uint16_t* v = static_cast<uint16_t*>(raw.planes[UHDR_PLANE_V]);
    for (unsigned int row = 0; row < height; ++row) {
      for (unsigned int column = 0; column < width; ++column) {
        const size_t index = static_cast<size_t>(row) * raw.stride[UHDR_PLANE_Y] + column;
        y[index] = static_cast<uint16_t>(256 + ((column * 29 + row * 13) % 512));
        u[index] = static_cast<uint16_t>(384 + ((column * 11 + row * 7) % 256));
        v[index] = static_cast<uint16_t>(640 - ((column * 5 + row * 17) % 256));
      }
    }
  }

  unsigned int width;
  unsigned int height;
  uhdr_raw_image_ext_t raw;
};

struct RgbaF16Image {
  RgbaF16Image(unsigned int width = kWidth, unsigned int height = kHeight)
      : width(width),
        height(height),
        raw(UHDR_IMG_FMT_64bppRGBAHalfFloat, UHDR_CG_BT_2100, UHDR_CT_LINEAR,
            UHDR_CR_FULL_RANGE, width, height, 64) {
    constexpr uint64_t pixel = static_cast<uint64_t>(0x3c00) |
                               (static_cast<uint64_t>(0x3800) << 16) |
                               (static_cast<uint64_t>(0x3400) << 32) |
                               (static_cast<uint64_t>(0x3c00) << 48);
    uint64_t* pixels = static_cast<uint64_t*>(raw.planes[UHDR_PLANE_PACKED]);
    for (unsigned int y = 0; y < height; ++y) {
      for (unsigned int x = 0; x < width; ++x) {
        pixels[static_cast<size_t>(y) * raw.stride[UHDR_PLANE_PACKED] + x] = pixel;
      }
    }
  }

  unsigned int width;
  unsigned int height;
  uhdr_raw_image_ext_t raw;
};

class TestAvifUltraHdr : public AvifUltraHdr {
 public:
  using AvifUltraHdr::AvifUltraHdr;

  uhdr_error_info_t toneMapForTest(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent) {
    return toneMap(hdr_intent, sdr_intent);
  }
};

void fillP010WithPadding(uhdr_raw_image_ext_t* image) {
  std::fill_n(reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_Y]),
              static_cast<size_t>(image->stride[UHDR_PLANE_Y]) * image->h,
              kP010PaddingSample);
  std::fill_n(reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_UV]),
              static_cast<size_t>(image->stride[UHDR_PLANE_UV]) * (image->h / 2),
              kP010PaddingSample);
}

struct EncodedImage {
  EncodedImage() : storage(kOutputCapacity) {
    output.data = storage.data();
    output.capacity = storage.size();
  }

  std::vector<uint8_t> storage;
  uhdr_compressed_image_t output{};
};

uhdr_error_info_t encodeAvifApi0(uhdr_raw_image_t* source, EncodedImage& encoded,
                                 uhdr_codec_t codec = UHDR_CODEC_AVIF, int quality = 100,
                                 int max_base_image_bit_depth = 10) {
  TestAvifUltraHdr encoder(nullptr, kMapDimensionScaleFactorAndroidDefault,
                           kMapCompressQualityAndroidDefault,
                           kUseMultiChannelGainMapAndroidDefault, kGainMapGammaDefault,
                           kEncSpeedPresetAndroidDefault, FLT_MIN, FLT_MAX, -1.0f, codec);
  uhdr_owned_buffer_t output;
  uhdr_error_info_t status = encoder.encodeAvifUltraHdrToOwnedBuffer(
      source, &output, quality, nullptr, max_base_image_bit_depth);
  if (status.error_code != UHDR_CODEC_OK) return status;
  encoded.storage.assign(output.data(), output.data() + output.size());
  encoded.output.data = encoded.storage.data();
  encoded.output.capacity = encoded.storage.size();
  encoded.output.data_sz = encoded.storage.size();
  return status;
}

uhdr_error_info_t encodeAvifApi1(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent,
                                 EncodedImage& encoded, int quality = 100,
                                 uhdr_enc_preset_t preset = kEncSpeedPresetAndroidDefault,
                                 int max_base_image_bit_depth = 8) {
  TestAvifUltraHdr encoder(nullptr, kMapDimensionScaleFactorAndroidDefault,
                           kMapCompressQualityAndroidDefault,
                           kUseMultiChannelGainMapAndroidDefault, kGainMapGammaDefault, preset,
                           FLT_MIN, FLT_MAX, -1.0f, UHDR_CODEC_AVIF);
  uhdr_owned_buffer_t output;
  uhdr_error_info_t status = encoder.encodeAvifUltraHdrToOwnedBuffer(
      hdr_intent, sdr_intent, &output, quality, nullptr, max_base_image_bit_depth);
  if (status.error_code != UHDR_CODEC_OK) return status;
  encoded.storage.assign(output.data(), output.data() + output.size());
  encoded.output.data = encoded.storage.data();
  encoded.output.capacity = encoded.storage.size();
  encoded.output.data_sz = encoded.storage.size();
  return status;
}

struct HeifImageView {
  heif_context* context = nullptr;
  heif_image_handle* base = nullptr;
  heif_image_handle* gainmap = nullptr;

  ~HeifImageView() {
    if (gainmap != nullptr) heif_image_handle_release(gainmap);
    if (base != nullptr) heif_image_handle_release(base);
    if (context != nullptr) heif_context_free(context);
  }
};

bool openEncoded(const uhdr_compressed_image_t& encoded, HeifImageView* view) {
  view->context = heif_context_alloc();
  if (view->context == nullptr) return false;
  heif_error err = heif_context_read_from_memory_without_copy(
      view->context, encoded.data, encoded.data_sz, nullptr);
  if (err.code != heif_error_Ok) return false;
  err = heif_context_get_primary_image_handle(view->context, &view->base);
  if (err.code != heif_error_Ok) return false;
  err = heif_image_handle_get_gain_map_image_handle(view->base, &view->gainmap);
  return err.code == heif_error_Ok;
}

bool openEncoded(const EncodedImage& encoded, HeifImageView* view) {
  return openEncoded(encoded.output, view);
}

}  // namespace

TEST(AvifNative10Test, Api0P010Uses10BitBaseAnd8BitGainMap) {
  P010Image source(kWidth, kHeight, /*padded=*/false);
  EncodedImage encoded;
  uhdr_error_info_t status = encodeAvifApi0(&source.raw, encoded);
  if (isEncoderUnavailable(status)) {
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << (status.has_detail ? status.detail : "");

  HeifImageView view;
  ASSERT_TRUE(openEncoded(encoded, &view));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.gainmap), 8);
}

TEST(AvifNative10Test, DirectEncoderRejectsInvalidDepthAndRetainsDefault) {
  P010Image source(kWidth, kHeight, /*padded=*/false);
  EncodedImage encoded;
  TestAvifUltraHdr encoder;

  uhdr_owned_buffer_t invalid_output;
  EXPECT_EQ(encoder.encodeAvifUltraHdrToOwnedBuffer(
                &source.raw, &invalid_output, /*quality=*/100, nullptr,
                /*max_base_image_bit_depth=*/7)
                .error_code,
            UHDR_CODEC_INVALID_PARAM);
  uhdr_error_info_t status =
      encoder.encodeAvifUltraHdr(&source.raw, &encoded.output, /*quality=*/100, nullptr);
  if (isEncoderUnavailable(status)) {
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
      << (status.has_detail ? status.detail : "");

  HeifImageView view;
  ASSERT_TRUE(openEncoded(encoded, &view));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base),
            kMaxBaseImageBitDepthDefault);
}

TEST(AvifNative10Test, Api0DefaultsToLegacy8BitBase) {
  P010Image source(kWidth, kHeight, /*padded=*/false);
  uhdr_codec_private_t* encoder = uhdr_create_encoder();
  ASSERT_NE(encoder, nullptr);
  ASSERT_EQ(uhdr_enc_set_raw_image(encoder, &source.raw, UHDR_HDR_IMG).error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_output_format(encoder, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_OK);
  uhdr_error_info_t status = uhdr_encode(encoder);
  if (isEncoderUnavailable(status)) {
    uhdr_release_encoder(encoder);
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
      << (status.has_detail ? status.detail : "");

  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(encoder);
  ASSERT_NE(output, nullptr);
  HeifImageView view;
  ASSERT_TRUE(openEncoded(*output, &view));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 8);
  EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 8);
  uhdr_release_encoder(encoder);
}

TEST(AvifNative10Test, Api0Rgba1010102DefaultsToLegacy8BitBase) {
  Rgba1010102Image source;
  uhdr_codec_private_t* encoder = uhdr_create_encoder();
  ASSERT_NE(encoder, nullptr);
  ASSERT_EQ(uhdr_enc_set_raw_image(encoder, &source.raw, UHDR_HDR_IMG).error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_output_format(encoder, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_OK);
  uhdr_error_info_t status = uhdr_encode(encoder);
  if (isEncoderUnavailable(status)) {
    uhdr_release_encoder(encoder);
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
      << (status.has_detail ? status.detail : "");

  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(encoder);
  ASSERT_NE(output, nullptr);
  HeifImageView view;
  ASSERT_TRUE(openEncoded(*output, &view));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 8);
  EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 8);
  uhdr_release_encoder(encoder);
}

TEST(AvifNative10Test, Api0Explicit8BitUsesLegacyBaseForSupported10BitInputs) {
  P010Image p010_source(kWidth, kHeight, /*padded=*/false);
  Rgba1010102Image rgba_source;
  uhdr_raw_image_t* sources[] = {&p010_source.raw, &rgba_source.raw};

  for (uhdr_raw_image_t* source : sources) {
    EncodedImage encoded;
    uhdr_error_info_t status = encodeAvifApi0(source, encoded, UHDR_CODEC_AVIF,
                                              /*quality=*/100,
                                              /*max_base_image_bit_depth=*/8);
    if (isEncoderUnavailable(status)) {
      GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
    }
    ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
        << (status.has_detail ? status.detail : "");

    HeifImageView view;
    ASSERT_TRUE(openEncoded(encoded, &view));
    EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 8);
    EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 8);
  }
}

TEST(AvifNative10Test, Api1Rgba1010102SdrInputEncodesWithExplicitNative10Request) {
  P010Image hdr_source(kWidth, kHeight, /*padded=*/false, UHDR_CG_BT_2100, UHDR_CT_HLG,
                       UHDR_CR_FULL_RANGE);
  Rgba1010102Image sdr_source;
  sdr_source.raw.ct = UHDR_CT_SRGB;
  EncodedImage encoded;

  uhdr_error_info_t status = encodeAvifApi1(&hdr_source.raw, &sdr_source.raw, encoded, 100,
                                             kEncSpeedPresetAndroidDefault, 10);
  if (isEncoderUnavailable(status)) {
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
      << (status.has_detail ? status.detail : "");

  HeifImageView view;
  ASSERT_TRUE(openEncoded(encoded, &view));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 10);
  enum heif_colorspace colorspace = heif_colorspace_undefined;
  enum heif_chroma chroma = heif_chroma_undefined;
  ASSERT_EQ(heif_image_handle_get_preferred_decoding_colorspace(view.base, &colorspace, &chroma)
                .code,
            heif_error_Ok);
  EXPECT_EQ(colorspace, heif_colorspace_YCbCr);
  EXPECT_EQ(chroma, heif_chroma_444);
}

TEST(AvifNative10Test, Api1HighPrecisionSdrFormatsRequireExplicitNative10Request) {
  P010Image hdr_source(kWidth, kHeight, /*padded=*/false, UHDR_CG_BT_2100, UHDR_CT_HLG,
                       UHDR_CR_FULL_RANGE);
  Yuv44410Image planar_sdr;
  Rgba1010102Image packed_sdr;
  EncodedImage planar_encoded;
  EncodedImage packed_encoded;

  uhdr_error_info_t planar_status =
      encodeAvifApi1(&hdr_source.raw, &planar_sdr.raw, planar_encoded);
  uhdr_error_info_t packed_status =
      encodeAvifApi1(&hdr_source.raw, &packed_sdr.raw, packed_encoded);
  EXPECT_EQ(planar_status.error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);
  EXPECT_EQ(packed_status.error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);
  ASSERT_TRUE(planar_status.has_detail);
  ASSERT_TRUE(packed_status.has_detail);
  EXPECT_NE(strstr(planar_status.detail, "explicit 10-bit"), nullptr);
  EXPECT_NE(strstr(packed_status.detail, "explicit 10-bit"), nullptr);
}

TEST(AvifNative10Test, Api1Rgba8888SdrUsesOptIn10Bit444ThroughPublicApi) {
  RgbaF16Image hdr_source;
  Rgba8888Image sdr_source;

  for (int requested_depth : {8, 10}) {
    uhdr_codec_private_t* encoder = uhdr_create_encoder();
    ASSERT_NE(encoder, nullptr);
    ASSERT_EQ(uhdr_enc_set_raw_image(encoder, &hdr_source.raw, UHDR_HDR_IMG).error_code,
              UHDR_CODEC_OK);
    ASSERT_EQ(uhdr_enc_set_raw_image(encoder, &sdr_source.raw, UHDR_SDR_IMG).error_code,
              UHDR_CODEC_OK);
    ASSERT_EQ(uhdr_enc_set_output_format(encoder, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_OK);
    if (requested_depth == 10) {
      ASSERT_EQ(uhdr_enc_set_max_base_image_bit_depth(encoder, 10).error_code, UHDR_CODEC_OK);
    }

    uhdr_error_info_t status = uhdr_encode(encoder);
    if (isEncoderUnavailable(status)) {
      uhdr_release_encoder(encoder);
      GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
    }
    ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
        << (status.has_detail ? status.detail : "");

    uhdr_compressed_image_t* output = uhdr_get_encoded_stream(encoder);
    ASSERT_NE(output, nullptr);
    HeifImageView view;
    ASSERT_TRUE(openEncoded(*output, &view));
    EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), requested_depth);
    EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), requested_depth);
    enum heif_colorspace colorspace = heif_colorspace_undefined;
    enum heif_chroma chroma = heif_chroma_undefined;
    ASSERT_EQ(heif_image_handle_get_preferred_decoding_colorspace(view.base, &colorspace, &chroma)
                  .code,
              heif_error_Ok);
    EXPECT_EQ(colorspace, heif_colorspace_YCbCr);
    EXPECT_EQ(chroma, heif_chroma_444);
    uhdr_release_encoder(encoder);
  }
}

TEST(AvifNative10Test, Api1Rgba8888SdrOddGeometryEncodesNative10Bit444) {
  constexpr unsigned int kOddWidth = 17;
  constexpr unsigned int kOddHeight = 19;
  RgbaF16Image hdr_source(kOddWidth, kOddHeight);
  Rgba8888Image sdr_source(kOddWidth, kOddHeight);
  EncodedImage encoded;
  uhdr_error_info_t status = encodeAvifApi1(&hdr_source.raw, &sdr_source.raw, encoded, 100,
                                           kEncSpeedPresetAndroidDefault, 10);
  if (isEncoderUnavailable(status)) {
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
      << (status.has_detail ? status.detail : "");

  HeifImageView view;
  ASSERT_TRUE(openEncoded(encoded, &view));
  EXPECT_EQ(heif_image_handle_get_width(view.base), static_cast<int>(kOddWidth));
  EXPECT_EQ(heif_image_handle_get_height(view.base), static_cast<int>(kOddHeight));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 10);
  enum heif_colorspace colorspace = heif_colorspace_undefined;
  enum heif_chroma chroma = heif_chroma_undefined;
  ASSERT_EQ(heif_image_handle_get_preferred_decoding_colorspace(view.base, &colorspace, &chroma)
                .code,
            heif_error_Ok);
  EXPECT_EQ(colorspace, heif_colorspace_YCbCr);
  EXPECT_EQ(chroma, heif_chroma_444);
}

TEST(AvifNative10Test, IndependentEncodersSupportConcurrentMixedDepthCaps) {
  constexpr std::array<int, 4> kDepthCaps = {8, 10, 10, 8};
  constexpr std::array<bool, 4> kUseRgba = {false, false, true, true};
  struct ConcurrentResult {
    uhdr_error_info_t status = g_no_error;
    std::vector<uint8_t> output;
  };
  std::array<ConcurrentResult, kDepthCaps.size()> results;
  std::array<std::thread, kDepthCaps.size()> threads;

  for (size_t i = 0; i < threads.size(); ++i) {
    threads[i] = std::thread([i, &kDepthCaps, &kUseRgba, &results]() {
      EncodedImage encoded;
      if (kUseRgba[i]) {
        Rgba1010102Image source;
        results[i].status = encodeAvifApi0(&source.raw, encoded, UHDR_CODEC_AVIF,
                                           /*quality=*/85, kDepthCaps[i]);
      } else {
        P010Image source(kWidth, kHeight, /*padded=*/false);
        results[i].status = encodeAvifApi0(&source.raw, encoded, UHDR_CODEC_AVIF,
                                           /*quality=*/85, kDepthCaps[i]);
      }
      if (results[i].status.error_code == UHDR_CODEC_OK) {
        const auto* begin = static_cast<const uint8_t*>(encoded.output.data);
        results[i].output.assign(begin, begin + encoded.output.data_sz);
      }
    });
  }
  for (std::thread& thread : threads) thread.join();

  for (const ConcurrentResult& result : results) {
    if (isEncoderUnavailable(result.status)) {
      GTEST_SKIP() << "AV1 encoder plugin not available: " << result.status.detail;
    }
  }
  for (size_t i = 0; i < results.size(); ++i) {
    ASSERT_EQ(results[i].status.error_code, UHDR_CODEC_OK)
        << (results[i].status.has_detail ? results[i].status.detail : "");
    uhdr_compressed_image_t encoded{};
    encoded.data = results[i].output.data();
    encoded.data_sz = results[i].output.size();
    encoded.capacity = results[i].output.size();
    HeifImageView view;
    ASSERT_TRUE(openEncoded(encoded, &view));
    EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), kDepthCaps[i]);
    EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.gainmap), 8);
  }
}

TEST(AvifNative10Test, Api0P010RoundTripsThroughPublicDecoder) {
  P010Image source(kWidth, kHeight, /*padded=*/false);
  EncodedImage encoded;
  uhdr_error_info_t status = encodeAvifApi0(&source.raw, encoded);
  if (isEncoderUnavailable(status)) {
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << (status.has_detail ? status.detail : "");

  HeifImageView view;
  ASSERT_TRUE(openEncoded(encoded, &view));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.gainmap), 8);

  heif_image* decoded = nullptr;
  heif_decoding_options* options = heif_decoding_options_alloc();
  ASSERT_NE(options, nullptr);
  heif_error err = heif_decode_image(view.base, &decoded, heif_colorspace_YCbCr,
                                     heif_chroma_420, options);
  heif_decoding_options_free(options);
  ASSERT_EQ(err.code, heif_error_Ok) << (err.message != nullptr ? err.message : "");
  ASSERT_NE(decoded, nullptr);
  // libheif uses 16-bit storage for native 10-bit planes; the range API reports the
  // meaningful sample depth independently of that storage width.
  EXPECT_EQ(heif_image_get_bits_per_pixel_range(decoded, heif_channel_Y), 10);
  EXPECT_EQ(heif_image_get_bits_per_pixel_range(decoded, heif_channel_Cb), 10);
  EXPECT_EQ(heif_image_get_bits_per_pixel_range(decoded, heif_channel_Cr), 10);
  heif_image_release(decoded);

  // Also exercise the public UHDR decoder so the end-to-end gain-map reconstruction path is
  // covered in addition to the independent libheif depth/plane checks above.
  uhdr_codec_private_t* public_decoder = uhdr_create_decoder();
  ASSERT_NE(public_decoder, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(public_decoder, &encoded.output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_color_transfer(public_decoder, UHDR_CT_LINEAR).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_img_format(public_decoder, UHDR_IMG_FMT_64bppRGBAHalfFloat)
                .error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(public_decoder).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_get_image_width(public_decoder), kWidth);
  EXPECT_EQ(uhdr_dec_get_image_height(public_decoder), kHeight);
  uhdr_error_info_t public_decode_status = uhdr_decode(public_decoder);
  ASSERT_EQ(public_decode_status.error_code, UHDR_CODEC_OK)
      << (public_decode_status.has_detail ? public_decode_status.detail : "");
  uhdr_raw_image_t* reconstructed = uhdr_get_decoded_image(public_decoder);
  ASSERT_NE(reconstructed, nullptr);
  EXPECT_EQ(reconstructed->w, static_cast<unsigned int>(kWidth));
  EXPECT_EQ(reconstructed->h, static_cast<unsigned int>(kHeight));
  uhdr_release_decoder(public_decoder);
}

TEST(AvifNative10Test, ToneMapRgba1010102DirectlyProducesPlanar10BitPixels) {
  Rgba1010102Image source;
  uhdr_raw_image_ext_t tone_mapped(UHDR_IMG_FMT_30bppYCbCr444, UHDR_CG_UNSPECIFIED,
                                   UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, kWidth, kHeight, 64);
  uhdr_raw_image_ext_t tone_mapped_8(UHDR_IMG_FMT_32bppRGBA8888, UHDR_CG_UNSPECIFIED,
                                     UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, kWidth, kHeight, 64);

  TestAvifUltraHdr tone_mapper;
  uhdr_error_info_t status = tone_mapper.toneMapForTest(&source.raw, &tone_mapped);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
      << (status.has_detail ? status.detail : "");
  uhdr_error_info_t status_8 = tone_mapper.toneMapForTest(&source.raw, &tone_mapped_8);
  ASSERT_EQ(status_8.error_code, UHDR_CODEC_OK)
      << (status_8.has_detail ? status_8.detail : "");
  std::unique_ptr<uhdr_raw_image_ext_t> yuv_8 =
      convert_raw_input_to_ycbcr(&tone_mapped_8, false);
  ASSERT_NE(yuv_8, nullptr);

  size_t samples_different_from_expanded_8bit = 0;
  for (int plane = UHDR_PLANE_Y; plane <= UHDR_PLANE_V; ++plane) {
    const uint16_t* samples = static_cast<const uint16_t*>(tone_mapped.planes[plane]);
    const uint8_t* samples_8 = static_cast<const uint8_t*>(yuv_8->planes[plane]);
    ASSERT_NE(samples, nullptr);
    ASSERT_NE(samples_8, nullptr);
    for (int y = 0; y < kHeight; ++y) {
      for (int x = 0; x < kWidth; ++x) {
        const uint16_t sample = samples[static_cast<size_t>(y) * tone_mapped.stride[plane] + x];
        EXPECT_LE(sample, 1023u);
        const uint8_t sample_8 =
            samples_8[static_cast<size_t>(y) * yuv_8->stride[plane] + x];
        const int expanded = plane == UHDR_PLANE_Y
                                 ? static_cast<int>(std::lround(sample_8 * 1023.0 / 255.0))
                                 : static_cast<int>(std::floor((static_cast<int>(sample_8) - 128) *
                                                                   1023.0 / 255.0 + 512.5));
        if (sample != expanded) ++samples_different_from_expanded_8bit;
      }
    }
  }
  EXPECT_GT(samples_different_from_expanded_8bit, 0u)
      << "native 10-bit tone mapping must preserve samples that an 8-bit RGB/YUV intermediate "
         "would quantize";
}

TEST(AvifNative10Test, Api0Rgba1010102Uses10BitBaseThroughPublicApi) {
  Rgba1010102Image source;
  uhdr_codec_private_t* encoder = uhdr_create_encoder();
  ASSERT_NE(encoder, nullptr);

  ASSERT_EQ(uhdr_enc_set_raw_image(encoder, &source.raw, UHDR_HDR_IMG).error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_output_format(encoder, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_max_base_image_bit_depth(encoder, 10).error_code, UHDR_CODEC_OK);
  uhdr_error_info_t status = uhdr_encode(encoder);
  if (isEncoderUnavailable(status)) {
    uhdr_release_encoder(encoder);
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << (status.has_detail ? status.detail : "");

  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(encoder);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);
  HeifImageView view;
  ASSERT_TRUE(openEncoded(*output, &view));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.gainmap), 8);

  uhdr_codec_private_t* decoder = uhdr_create_decoder();
  ASSERT_NE(decoder, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(decoder, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_color_transfer(decoder, UHDR_CT_LINEAR).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_img_format(decoder, UHDR_IMG_FMT_64bppRGBAHalfFloat).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(decoder).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_get_image_width(decoder), kWidth);
  EXPECT_EQ(uhdr_dec_get_image_height(decoder), kHeight);
  uhdr_error_info_t decode_status = uhdr_decode(decoder);
  ASSERT_EQ(decode_status.error_code, UHDR_CODEC_OK)
      << (decode_status.has_detail ? decode_status.detail : "");
  uhdr_raw_image_t* reconstructed = uhdr_get_decoded_image(decoder);
  ASSERT_NE(reconstructed, nullptr);
  EXPECT_EQ(reconstructed->fmt, UHDR_IMG_FMT_64bppRGBAHalfFloat);
  EXPECT_EQ(reconstructed->w, static_cast<unsigned int>(kWidth));
  EXPECT_EQ(reconstructed->h, static_cast<unsigned int>(kHeight));
  uhdr_release_decoder(decoder);

  uhdr_release_encoder(encoder);
}

TEST(AvifNative10Test, PublicApiHandlesHighEntropyNative10Output) {
  constexpr unsigned int kHighEntropyWidth = 512;
  constexpr unsigned int kHighEntropyHeight = 512;
  Rgba1010102Image source(kHighEntropyWidth, kHighEntropyHeight);
  uint32_t* pixels = static_cast<uint32_t*>(source.raw.planes[UHDR_PLANE_PACKED]);
  uint32_t state = 0x12345678u;
  for (size_t i = 0; i < static_cast<size_t>(source.width) * source.height; ++i) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    const uint32_t r = state & 0x3ffu;
    const uint32_t g = (state >> 10) & 0x3ffu;
    const uint32_t b = ((state >> 20) ^ state) & 0x3ffu;
    pixels[i] = r | (g << 10) | (b << 20) | (0x3u << 30);
  }

  uhdr_codec_private_t* encoder = uhdr_create_encoder();
  ASSERT_NE(encoder, nullptr);
  ASSERT_EQ(uhdr_enc_set_raw_image(encoder, &source.raw, UHDR_HDR_IMG).error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_output_format(encoder, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_max_base_image_bit_depth(encoder, 10).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_quality(encoder, 100, UHDR_BASE_IMG).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t status = uhdr_encode(encoder);
  if (isEncoderUnavailable(status)) {
    uhdr_release_encoder(encoder);
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << (status.has_detail ? status.detail : "");

  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(encoder);
  ASSERT_NE(output, nullptr);
  EXPECT_GT(output->data_sz, 0u);
  EXPECT_EQ(output->capacity, output->data_sz);
  HeifImageView view;
  ASSERT_TRUE(openEncoded(*output, &view));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.gainmap), 8);
  uhdr_release_encoder(encoder);
}

TEST(AvifNative10Test, ToneMapP010IgnoresPaddedStride) {
  P010Image tight_source(kWidth, kHeight, /*padded=*/false);
  P010Image padded_source(kWidth, kHeight, /*padded=*/true);
  uhdr_raw_image_ext_t tight_sdr(UHDR_IMG_FMT_24bppYCbCrP010, UHDR_CG_UNSPECIFIED,
                                 UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, kWidth, kHeight, 16);
  uhdr_raw_image_ext_t padded_sdr(UHDR_IMG_FMT_24bppYCbCrP010, UHDR_CG_UNSPECIFIED,
                                  UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, kWidth, kHeight, 64);
  fillP010WithPadding(&tight_sdr);
  fillP010WithPadding(&padded_sdr);

  TestAvifUltraHdr tone_mapper;
  uhdr_error_info_t tight_status =
      tone_mapper.toneMapForTest(&tight_source.raw, &tight_sdr);
  uhdr_error_info_t padded_status =
      tone_mapper.toneMapForTest(&padded_source.raw, &padded_sdr);
  ASSERT_EQ(tight_status.error_code, UHDR_CODEC_OK)
      << (tight_status.has_detail ? tight_status.detail : "");
  ASSERT_EQ(padded_status.error_code, UHDR_CODEC_OK)
      << (padded_status.has_detail ? padded_status.detail : "");
  ASSERT_EQ(tight_sdr.stride[UHDR_PLANE_Y], static_cast<unsigned int>(kWidth));
  ASSERT_EQ(tight_sdr.stride[UHDR_PLANE_UV], static_cast<unsigned int>(kWidth));
  ASSERT_GT(padded_sdr.stride[UHDR_PLANE_Y], static_cast<unsigned int>(kWidth));
  ASSERT_GT(padded_sdr.stride[UHDR_PLANE_UV], static_cast<unsigned int>(kWidth));

  const uint16_t* tight_y = reinterpret_cast<const uint16_t*>(tight_sdr.planes[UHDR_PLANE_Y]);
  const uint16_t* padded_y = reinterpret_cast<const uint16_t*>(padded_sdr.planes[UHDR_PLANE_Y]);
  for (int y = 0; y < kHeight; ++y) {
    for (int x = 0; x < kWidth; ++x) {
      EXPECT_EQ(tight_y[static_cast<size_t>(y) * tight_sdr.stride[UHDR_PLANE_Y] + x],
                padded_y[static_cast<size_t>(y) * padded_sdr.stride[UHDR_PLANE_Y] + x])
          << "tone map differs at Y (" << x << ", " << y << ")";
    }
  }

  const uint16_t* tight_uv =
      reinterpret_cast<const uint16_t*>(tight_sdr.planes[UHDR_PLANE_UV]);
  const uint16_t* padded_uv =
      reinterpret_cast<const uint16_t*>(padded_sdr.planes[UHDR_PLANE_UV]);
  for (int y = 0; y < kHeight / 2; ++y) {
    for (int x = 0; x < kWidth; ++x) {
      EXPECT_EQ(tight_uv[static_cast<size_t>(y) * tight_sdr.stride[UHDR_PLANE_UV] + x],
                padded_uv[static_cast<size_t>(y) * padded_sdr.stride[UHDR_PLANE_UV] + x])
          << "tone map differs at UV (" << x << ", " << y << ")";
    }
  }

  // The output is initialized with a canary. A write or read beyond the logical image must not
  // change the P010 padding words.
  const uint16_t* padded_y_end =
      reinterpret_cast<const uint16_t*>(padded_sdr.planes[UHDR_PLANE_Y]);
  for (int y = 0; y < kHeight; ++y) {
    for (unsigned int x = kWidth; x < padded_sdr.stride[UHDR_PLANE_Y]; ++x) {
      EXPECT_EQ(padded_y_end[static_cast<size_t>(y) * padded_sdr.stride[UHDR_PLANE_Y] + x],
                kP010PaddingSample)
          << "tone map wrote into Y padding at (" << x << ", " << y << ")";
    }
  }
  const uint16_t* padded_uv_end =
      reinterpret_cast<const uint16_t*>(padded_sdr.planes[UHDR_PLANE_UV]);
  for (int y = 0; y < kHeight / 2; ++y) {
    for (unsigned int x = kWidth; x < padded_sdr.stride[UHDR_PLANE_UV]; ++x) {
      EXPECT_EQ(padded_uv_end[static_cast<size_t>(y) * padded_sdr.stride[UHDR_PLANE_UV] + x],
                kP010PaddingSample)
          << "tone map wrote into UV padding at (" << x << ", " << y << ")";
    }
  }
}

TEST(AvifNative10Test, ToneMapP010ProducesNonQuantizedLogical10BitSamples) {
  P010Image source(kWidth, kHeight, /*padded=*/false);
  uhdr_raw_image_ext_t tone_mapped(UHDR_IMG_FMT_24bppYCbCrP010, UHDR_CG_UNSPECIFIED,
                                   UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, kWidth, kHeight, 64);
  uhdr_raw_image_ext_t tone_mapped_8(UHDR_IMG_FMT_12bppYCbCr420, UHDR_CG_UNSPECIFIED,
                                     UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, kWidth, kHeight, 64);
  fillP010WithPadding(&tone_mapped);

  TestAvifUltraHdr tone_mapper;
  uhdr_error_info_t status = tone_mapper.toneMapForTest(&source.raw, &tone_mapped);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
      << (status.has_detail ? status.detail : "");
  uhdr_error_info_t status_8 = tone_mapper.toneMapForTest(&source.raw, &tone_mapped_8);
  ASSERT_EQ(status_8.error_code, UHDR_CODEC_OK)
      << (status_8.has_detail ? status_8.detail : "");

  const uint16_t* y = reinterpret_cast<const uint16_t*>(tone_mapped.planes[UHDR_PLANE_Y]);
  const uint8_t* y_8 = static_cast<const uint8_t*>(tone_mapped_8.planes[UHDR_PLANE_Y]);
  size_t samples_different_from_expanded_8bit = 0;
  for (unsigned int row = 0; row < tone_mapped.h; ++row) {
    for (unsigned int column = 0; column < tone_mapped.w; ++column) {
      const uint16_t logical_sample =
          y[static_cast<size_t>(row) * tone_mapped.stride[UHDR_PLANE_Y] + column] >> 6;
      const uint8_t sample_8 =
          y_8[static_cast<size_t>(row) * tone_mapped_8.stride[UHDR_PLANE_Y] + column];
      const uint16_t expanded_8 =
          static_cast<uint16_t>(std::lround(sample_8 * 1023.0 / 255.0));
      if (logical_sample != expanded_8) ++samples_different_from_expanded_8bit;
    }
  }
  EXPECT_GT(samples_different_from_expanded_8bit, 0u)
      << "native P010 tone mapping must preserve luma values that an 8-bit intermediate "
         "would quantize";
}

TEST(AvifNative10Test, ToneMapP010IgnoresLowSixStorageBits) {
  P010Image clean_source(kWidth, kHeight, /*padded=*/false);
  P010Image low_bits_source(kWidth, kHeight, /*padded=*/false);
  for (unsigned int row = 0; row < low_bits_source.height; ++row) {
    for (unsigned int column = 0; column < low_bits_source.width; ++column) {
      const size_t index = static_cast<size_t>(row) * low_bits_source.luma_stride + column;
      low_bits_source.luma[index] |= static_cast<uint16_t>((row + column) % 64u);
    }
  }
  for (unsigned int row = 0; row < low_bits_source.height / 2; ++row) {
    for (unsigned int column = 0; column < low_bits_source.width; ++column) {
      const size_t index = static_cast<size_t>(row) * low_bits_source.chroma_stride + column;
      low_bits_source.chroma[index] |= static_cast<uint16_t>((row + column + 1u) % 64u);
    }
  }

  uhdr_raw_image_ext_t clean_tone_map(UHDR_IMG_FMT_24bppYCbCrP010, UHDR_CG_UNSPECIFIED,
                                      UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, kWidth, kHeight,
                                      64);
  uhdr_raw_image_ext_t low_bits_tone_map(
      UHDR_IMG_FMT_24bppYCbCrP010, UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED,
      UHDR_CR_UNSPECIFIED, kWidth, kHeight, 64);
  fillP010WithPadding(&clean_tone_map);
  fillP010WithPadding(&low_bits_tone_map);
  TestAvifUltraHdr tone_mapper;
  uhdr_error_info_t clean_status =
      tone_mapper.toneMapForTest(&clean_source.raw, &clean_tone_map);
  uhdr_error_info_t low_bits_status =
      tone_mapper.toneMapForTest(&low_bits_source.raw, &low_bits_tone_map);
  ASSERT_EQ(clean_status.error_code, UHDR_CODEC_OK)
      << (clean_status.has_detail ? clean_status.detail : "");
  ASSERT_EQ(low_bits_status.error_code, UHDR_CODEC_OK)
      << (low_bits_status.has_detail ? low_bits_status.detail : "");

  const uint16_t* clean_y = reinterpret_cast<const uint16_t*>(clean_tone_map.planes[UHDR_PLANE_Y]);
  const uint16_t* low_bits_y =
      reinterpret_cast<const uint16_t*>(low_bits_tone_map.planes[UHDR_PLANE_Y]);
  for (unsigned int row = 0; row < clean_source.height; ++row) {
    for (unsigned int column = 0; column < clean_source.width; ++column) {
      EXPECT_EQ(clean_y[static_cast<size_t>(row) * clean_tone_map.stride[UHDR_PLANE_Y] + column],
                low_bits_y[static_cast<size_t>(row) * low_bits_tone_map.stride[UHDR_PLANE_Y] +
                           column])
          << "tone map changed after modifying P010 storage low bits at (" << column << ", "
          << row << ")";
    }
  }
  const uint16_t* clean_uv =
      reinterpret_cast<const uint16_t*>(clean_tone_map.planes[UHDR_PLANE_UV]);
  const uint16_t* low_bits_uv =
      reinterpret_cast<const uint16_t*>(low_bits_tone_map.planes[UHDR_PLANE_UV]);
  for (unsigned int row = 0; row < clean_source.height / 2; ++row) {
    for (unsigned int column = 0; column < clean_source.width; ++column) {
      EXPECT_EQ(clean_uv[static_cast<size_t>(row) * clean_tone_map.stride[UHDR_PLANE_UV] + column],
                low_bits_uv[static_cast<size_t>(row) * low_bits_tone_map.stride[UHDR_PLANE_UV] +
                            column])
          << "tone map changed after modifying P010 chroma storage low bits at (" << column << ", "
          << row << ")";
    }
  }
}

TEST(AvifNative10Test, PaddedP010StridesAndUvOrderingArePreserved) {
  P010Image padded_source(kRectangularWidth, kRectangularHeight, /*padded=*/true);
  EncodedImage padded_encoded;

  uhdr_error_info_t padded_status = encodeAvifApi0(&padded_source.raw, padded_encoded);
  if (isEncoderUnavailable(padded_status)) {
    GTEST_SKIP() << "AV1 encoder plugin not available";
  }
  ASSERT_EQ(padded_status.error_code, UHDR_CODEC_OK)
      << (padded_status.has_detail ? padded_status.detail : "");

  // Use the independently generated P010 SDR intent as the expected chroma source. The AV1
  // payload at quality 100 can still have small lossy errors, so compare the aggregate error for
  // the correct Cb/Cr assignment with the error after swapping the two expected channels.
  uhdr_raw_image_ext_t expected_sdr(
      UHDR_IMG_FMT_24bppYCbCrP010, UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED,
      UHDR_CR_UNSPECIFIED, padded_source.width, padded_source.height, 64);
  fillP010WithPadding(&expected_sdr);
  TestAvifUltraHdr tone_mapper;
  uhdr_error_info_t expected_status =
      tone_mapper.toneMapForTest(&padded_source.raw, &expected_sdr);
  ASSERT_EQ(expected_status.error_code, UHDR_CODEC_OK)
      << (expected_status.has_detail ? expected_status.detail : "");

  HeifImageView view;
  ASSERT_TRUE(openEncoded(padded_encoded, &view));
  heif_image* decoded = nullptr;
  heif_error err = heif_decode_image(view.base, &decoded, heif_colorspace_YCbCr,
                                     heif_chroma_420, nullptr);
  ASSERT_EQ(err.code, heif_error_Ok) << (err.message != nullptr ? err.message : "");
  ASSERT_NE(decoded, nullptr);

  int cb_stride = 0;
  int cr_stride = 0;
  const uint16_t* cb = reinterpret_cast<const uint16_t*>(
      heif_image_get_plane_readonly(decoded, heif_channel_Cb, &cb_stride));
  const uint16_t* cr = reinterpret_cast<const uint16_t*>(
      heif_image_get_plane_readonly(decoded, heif_channel_Cr, &cr_stride));
  ASSERT_NE(cb, nullptr);
  ASSERT_NE(cr, nullptr);
  ASSERT_GT(cb_stride, 0);
  ASSERT_GT(cr_stride, 0);

  auto absDifference = [](uint16_t lhs, uint16_t rhs) -> uint64_t {
    return lhs >= rhs ? static_cast<uint64_t>(lhs - rhs)
                      : static_cast<uint64_t>(rhs - lhs);
  };
  uint64_t correct_error = 0;
  uint64_t swapped_error = 0;
  const uint16_t* expected_uv =
      reinterpret_cast<const uint16_t*>(expected_sdr.planes[UHDR_PLANE_UV]);
  for (unsigned int y = 0; y < padded_source.height / 2; ++y) {
    const uint16_t* cb_row = reinterpret_cast<const uint16_t*>(
        reinterpret_cast<const uint8_t*>(cb) + static_cast<size_t>(y) * cb_stride);
    const uint16_t* cr_row = reinterpret_cast<const uint16_t*>(
        reinterpret_cast<const uint8_t*>(cr) + static_cast<size_t>(y) * cr_stride);
    const uint16_t* expected_row =
        expected_uv + static_cast<size_t>(y) * expected_sdr.stride[UHDR_PLANE_UV];
    for (unsigned int x = 0; x < padded_source.width / 2; ++x) {
      const uint16_t expected_cb = expected_row[2 * x] >> 6;
      const uint16_t expected_cr = expected_row[2 * x + 1] >> 6;
      correct_error += absDifference(cb_row[x], expected_cb);
      correct_error += absDifference(cr_row[x], expected_cr);
      swapped_error += absDifference(cb_row[x], expected_cr);
      swapped_error += absDifference(cr_row[x], expected_cb);
    }
  }
  EXPECT_LT(correct_error * 4, swapped_error)
      << "correct Cb/Cr assignment was not materially closer than swapped assignment; correct="
      << correct_error << ", swapped=" << swapped_error;
  heif_image_release(decoded);
}

TEST(AvifNative10Test, Api0P010SupportsPqLimitedP3Input) {
  P010Image source(kRectangularWidth, kRectangularHeight, /*padded=*/true,
                   UHDR_CG_DISPLAY_P3, UHDR_CT_PQ, UHDR_CR_LIMITED_RANGE);
  EncodedImage encoded;
  uhdr_error_info_t status = encodeAvifApi0(&source.raw, encoded);
  if (isEncoderUnavailable(status)) {
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
      << (status.has_detail ? status.detail : "");

  HeifImageView view;
  ASSERT_TRUE(openEncoded(encoded, &view));
  EXPECT_EQ(heif_image_handle_get_width(view.base), static_cast<int>(source.width));
  EXPECT_EQ(heif_image_handle_get_height(view.base), static_cast<int>(source.height));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.gainmap), 8);
}

TEST(AvifNative10Test, Api0Rgba1010102AndF16UseExpectedBaseDepths) {
  Rgba1010102Image rgba1010102_source;
  RgbaF16Image f16_source;
  struct SourceAndExpectedDepth {
    uhdr_raw_image_t* source;
    int expected_depth;
  } cases[] = {{&rgba1010102_source.raw, 10}, {&f16_source.raw, 8}};
  for (const SourceAndExpectedDepth& test_case : cases) {
    EncodedImage encoded;
    uhdr_error_info_t status = encodeAvifApi0(test_case.source, encoded);
    if (isEncoderUnavailable(status)) {
      GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
    }
    ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
        << (status.has_detail ? status.detail : "");

    HeifImageView view;
    ASSERT_TRUE(openEncoded(encoded, &view));
    EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), test_case.expected_depth);
    EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), test_case.expected_depth);
    EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.gainmap), 8);
  }
}

TEST(AvifNative10Test, Api0Rgba1010102OddGeometryUsesNative10Base) {
  constexpr unsigned int kOddWidth = 257;
  constexpr unsigned int kOddHeight = 259;
  Rgba1010102Image source(kOddWidth, kOddHeight);
  EncodedImage encoded;
  uhdr_error_info_t status = encodeAvifApi0(&source.raw, encoded);
  if (isEncoderUnavailable(status)) {
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK)
      << (status.has_detail ? status.detail : "");

  HeifImageView view;
  ASSERT_TRUE(openEncoded(encoded, &view));
  EXPECT_EQ(heif_image_handle_get_width(view.base), static_cast<int>(source.width));
  EXPECT_EQ(heif_image_handle_get_height(view.base), static_cast<int>(source.height));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 10);
  EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 10);
  enum heif_colorspace colorspace = heif_colorspace_undefined;
  enum heif_chroma chroma = heif_chroma_undefined;
  heif_error preferred =
      heif_image_handle_get_preferred_decoding_colorspace(view.base, &colorspace, &chroma);
  ASSERT_EQ(preferred.code, heif_error_Ok)
      << (preferred.message != nullptr ? preferred.message : "");
  EXPECT_EQ(colorspace, heif_colorspace_YCbCr);
  EXPECT_EQ(chroma, heif_chroma_444);
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.gainmap), 8);
  const int expected_gainmap_width =
      static_cast<int>(source.width / kMapDimensionScaleFactorAndroidDefault);
  const int expected_gainmap_height =
      static_cast<int>(source.height / kMapDimensionScaleFactorAndroidDefault);
  EXPECT_EQ(heif_image_handle_get_width(view.gainmap), expected_gainmap_width);
  EXPECT_EQ(heif_image_handle_get_height(view.gainmap), expected_gainmap_height);

  uhdr_codec_private_t* decoder = uhdr_create_decoder();
  ASSERT_NE(decoder, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(decoder, &encoded.output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_color_transfer(decoder, UHDR_CT_LINEAR).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_img_format(decoder, UHDR_IMG_FMT_64bppRGBAHalfFloat).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(decoder).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_get_image_width(decoder), static_cast<int>(source.width));
  EXPECT_EQ(uhdr_dec_get_image_height(decoder), static_cast<int>(source.height));
  EXPECT_EQ(uhdr_dec_get_gainmap_width(decoder), expected_gainmap_width);
  EXPECT_EQ(uhdr_dec_get_gainmap_height(decoder), expected_gainmap_height);
  uhdr_error_info_t decode_status = uhdr_decode(decoder);
  ASSERT_EQ(decode_status.error_code, UHDR_CODEC_OK)
      << (decode_status.has_detail ? decode_status.detail : "");
  uhdr_raw_image_t* reconstructed = uhdr_get_decoded_image(decoder);
  ASSERT_NE(reconstructed, nullptr);
  EXPECT_EQ(reconstructed->fmt, UHDR_IMG_FMT_64bppRGBAHalfFloat);
  EXPECT_EQ(reconstructed->w, source.width);
  EXPECT_EQ(reconstructed->h, source.height);
  uhdr_release_decoder(decoder);
}

TEST(AvifNative10Test, Api0P010RejectsMalformedP010DescriptorsBeforeToneMap) {
  struct InvalidDescriptorCase {
    const char* name;
    void (*mutate)(uhdr_raw_image_t* image);
  };
  const InvalidDescriptorCase cases[] = {
      {"odd width", [](uhdr_raw_image_t* image) { image->w = kWidth - 1; }},
      {"odd height", [](uhdr_raw_image_t* image) { image->h = kHeight - 1; }},
      {"null luma", [](uhdr_raw_image_t* image) { image->planes[UHDR_PLANE_Y] = nullptr; }},
      {"null chroma", [](uhdr_raw_image_t* image) { image->planes[UHDR_PLANE_UV] = nullptr; }},
      {"short luma stride",
       [](uhdr_raw_image_t* image) { image->stride[UHDR_PLANE_Y] = image->w - 1; }},
      {"short chroma stride",
       [](uhdr_raw_image_t* image) { image->stride[UHDR_PLANE_UV] = image->w - 1; }},
      {"unspecified range", [](uhdr_raw_image_t* image) {
         image->range = UHDR_CR_UNSPECIFIED;
       }},
      {"invalid transfer", [](uhdr_raw_image_t* image) { image->ct = UHDR_CT_SRGB; }},
      {"unspecified gamut", [](uhdr_raw_image_t* image) {
         image->cg = UHDR_CG_UNSPECIFIED;
       }},
      {"below minimum width", [](uhdr_raw_image_t* image) {
         image->w = static_cast<unsigned int>(kMinWidth - 2);
       }},
      {"above maximum width", [](uhdr_raw_image_t* image) {
         image->w = static_cast<unsigned int>(kMaxWidth) + 1u;
       }},
  };

  for (const InvalidDescriptorCase& test_case : cases) {
    P010Image source(kWidth, kHeight, /*padded=*/false);
    test_case.mutate(&source.raw);
    EncodedImage encoded;
    uhdr_error_info_t status = encodeAvifApi0(&source.raw, encoded);
    EXPECT_EQ(status.error_code, UHDR_CODEC_INVALID_PARAM) << test_case.name;
    EXPECT_EQ(encoded.output.data_sz, 0u) << test_case.name;
  }

  EncodedImage encoded;
  uhdr_error_info_t null_status = encodeAvifApi0(nullptr, encoded);
  EXPECT_EQ(null_status.error_code, UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(encoded.output.data_sz, 0u);
}

TEST(AvifNative10Test, P010HeifCodecRetains8BitFallback) {
  P010Image source(kWidth, kHeight, /*padded=*/false);
  EncodedImage encoded;

  // Native 10-bit bases are an AVIF-only capability. HEIF retains the historical 8-bit route for
  // P010 input.
  uhdr_error_info_t codec_status = encodeAvifApi0(&source.raw, encoded, UHDR_CODEC_HEIF);
  if (isEncoderUnavailable(codec_status)) {
    GTEST_SKIP() << "HEVC encoder plugin not available: " << codec_status.detail;
  }
  ASSERT_EQ(codec_status.error_code, UHDR_CODEC_OK)
      << (codec_status.has_detail ? codec_status.detail : "");

  HeifImageView view;
  ASSERT_TRUE(openEncoded(encoded, &view));
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.base), 8);
  EXPECT_EQ(heif_image_handle_get_chroma_bits_per_pixel(view.base), 8);
  EXPECT_EQ(heif_image_handle_get_luma_bits_per_pixel(view.gainmap), 8);

  EncodedImage api1_encoded;
  AvifUltraHdr default_encoder;
  uhdr_error_info_t default_api1_status = default_encoder.encodeAvifUltraHdr(
      &source.raw, &source.raw, &api1_encoded.output, 100, nullptr);
  EXPECT_EQ(default_api1_status.error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);
  ASSERT_TRUE(default_api1_status.has_detail);
  EXPECT_NE(strstr(default_api1_status.detail, "API-1"), nullptr);
}

TEST(AvifNative10Test, EncoderErrorsPropagateWithout8BitFallback) {
  P010Image source(kWidth, kHeight, /*padded=*/false);
  EncodedImage encoded;
  uhdr_error_info_t status = encodeAvifApi0(&source.raw, encoded, UHDR_CODEC_AVIF, /*quality=*/101);
  if (isEncoderUnavailable(status)) {
    GTEST_SKIP() << "AV1 encoder plugin not available: " << status.detail;
  }
  EXPECT_NE(status.error_code, UHDR_CODEC_OK);
  EXPECT_EQ(encoded.output.data_sz, 0u);
}

#endif  // defined(UHDR_ENABLE_HEIF)

}  // namespace ultrahdr
