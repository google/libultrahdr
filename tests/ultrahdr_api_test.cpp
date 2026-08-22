#if defined(__has_include)
#if __has_include("testing/base/public/gunit.h")
#include "testing/base/public/gunit.h"
#else
#include <gtest/gtest.h>
#endif
#else
#include <gtest/gtest.h>
#endif
#include <fstream>
#include <vector>
#include <memory>

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/jpegr.h"
#include "ultrahdr/gainmapmath.h"
#include "ultrahdr/heifultrahdr.h"
#include "ultrahdr/avifultrahdr.h"

namespace ultrahdr {

static const char* kYCbCrP010FileName = "raw_p010_image.p010";
static const char* kYCbCr420FileName = "raw_yuv420_image.yuv420";
static const char* kSdrJpgFileName = "jpeg_image.jpg";
static const size_t kImageWidth = 1280;
static const size_t kImageHeight = 720;

static bool loadFile(const char* filename, std::vector<uint8_t>& buffer) {
  std::vector<std::string> candidates = {
      filename,
      std::string("third_party/libultrahdr/tests/data/") + filename,
      std::string("tests/data/") + filename,
      std::string("./data/") + filename,
      std::string("data/") + filename,
      std::string("../tests/data/") + filename,
  };
  for (const auto& path : candidates) {
    std::ifstream stream(path, std::ios::binary);
    if (stream.is_open()) {
      stream.seekg(0, std::ios::end);
      size_t size = stream.tellg();
      stream.seekg(0, std::ios::beg);
      buffer.resize(size);
      stream.read(reinterpret_cast<char*>(buffer.data()), size);
      if (stream.good()) return true;
    }
  }
  return false;
}

class UltraHdrApiTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(loadFile(kYCbCrP010FileName, mP010Data));
    ASSERT_TRUE(loadFile(kYCbCr420FileName, mYuv420Data));
    ASSERT_TRUE(loadFile(kSdrJpgFileName, mSdrJpgData));

    // Setup HDR raw image descriptor (P010, HLG, BT2100)
    mHdrRaw.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
    mHdrRaw.cg = UHDR_CG_BT_2100;
    mHdrRaw.ct = UHDR_CT_HLG;
    mHdrRaw.range = UHDR_CR_FULL_RANGE;
    mHdrRaw.w = kImageWidth;
    mHdrRaw.h = kImageHeight;
    mHdrRaw.planes[UHDR_PLANE_Y] = mP010Data.data();
    mHdrRaw.planes[UHDR_PLANE_UV] = mP010Data.data() + kImageWidth * kImageHeight * 2;
    mHdrRaw.stride[UHDR_PLANE_Y] = kImageWidth;
    mHdrRaw.stride[UHDR_PLANE_UV] = kImageWidth;

    // Setup SDR raw image descriptor (YUV420, sRGB, BT709)
    mSdrRaw.fmt = UHDR_IMG_FMT_12bppYCbCr420;
    mSdrRaw.cg = UHDR_CG_BT_709;
    mSdrRaw.ct = UHDR_CT_SRGB;
    mSdrRaw.range = UHDR_CR_FULL_RANGE;
    mSdrRaw.w = kImageWidth;
    mSdrRaw.h = kImageHeight;
    mSdrRaw.planes[UHDR_PLANE_Y] = mYuv420Data.data();
    mSdrRaw.planes[UHDR_PLANE_U] = mYuv420Data.data() + kImageWidth * kImageHeight;
    mSdrRaw.planes[UHDR_PLANE_V] = mYuv420Data.data() + kImageWidth * kImageHeight * 5 / 4;
    mSdrRaw.stride[UHDR_PLANE_Y] = kImageWidth;
    mSdrRaw.stride[UHDR_PLANE_U] = kImageWidth / 2;
    mSdrRaw.stride[UHDR_PLANE_V] = kImageWidth / 2;

    // Setup SDR compressed image descriptor (JPEG)
    mSdrCompressed.data = mSdrJpgData.data();
    mSdrCompressed.data_sz = mSdrJpgData.size();
    mSdrCompressed.capacity = mSdrJpgData.size();
    mSdrCompressed.cg = UHDR_CG_BT_709;
    mSdrCompressed.ct = UHDR_CT_SRGB;
    mSdrCompressed.range = UHDR_CR_FULL_RANGE;
  }

  std::vector<uint8_t> mP010Data;
  std::vector<uint8_t> mYuv420Data;
  std::vector<uint8_t> mSdrJpgData;
  uhdr_raw_image_t mHdrRaw{};
  uhdr_raw_image_t mSdrRaw{};
  uhdr_compressed_image_t mSdrCompressed{};
};

// ============================================================================
// JPEG Tests (API-0 through API-4)
// ============================================================================

TEST_F(UltraHdrApiTest, JpegEncodeApi0AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 90, UHDR_BASE_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 90, UHDR_GAIN_MAP_IMG).error_code, UHDR_CODEC_OK);

  ASSERT_EQ(uhdr_encode(enc).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);

  // Decode stream
  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_color_transfer(dec, UHDR_CT_HLG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_img_format(dec, UHDR_IMG_FMT_32bppRGBA1010102).error_code, UHDR_CODEC_OK);

  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_get_image_width(dec), static_cast<int>(kImageWidth));
  EXPECT_EQ(uhdr_dec_get_image_height(dec), static_cast<int>(kImageHeight));

  ASSERT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);
  uhdr_raw_image_t* decoded = uhdr_get_decoded_image(dec);
  ASSERT_NE(decoded, nullptr);
  EXPECT_EQ(decoded->w, kImageWidth);
  EXPECT_EQ(decoded->h, kImageHeight);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, JpegEncodeApi1AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mSdrRaw, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);

  ASSERT_EQ(uhdr_encode(enc).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);

  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, JpegEncodeApi2AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_compressed_image(enc, &mSdrCompressed, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);

  ASSERT_EQ(uhdr_encode(enc).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);

  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

// ============================================================================
// HEIF / HEIC Tests (API-0, API-1, and Unsupported APIs)
// ============================================================================

#if defined(UHDR_ENABLE_HEIF)
namespace {

constexpr size_t kAlphaTestWidth = 64;
constexpr size_t kAlphaTestHeight = 64;

struct AlphaTestImages {
  std::vector<uint32_t> hdr1010102;
  std::vector<uint16_t> hdrHalfFloat;
  std::vector<uint32_t> sdr8888;
  uhdr_raw_image_t hdr1010102Desc{};
  uhdr_raw_image_t hdrHalfFloatDesc{};
  uhdr_raw_image_t sdr8888Desc{};

  AlphaTestImages()
      : hdr1010102(kAlphaTestWidth * kAlphaTestHeight),
        hdrHalfFloat(kAlphaTestWidth * kAlphaTestHeight * 4),
        sdr8888(kAlphaTestWidth * kAlphaTestHeight) {
    for (size_t y = 0; y < kAlphaTestHeight; ++y) {
      for (size_t x = 0; x < kAlphaTestWidth; ++x) {
        const size_t pixel = y * kAlphaTestWidth + x;
        const uint32_t alpha2 = static_cast<uint32_t>(x / (kAlphaTestWidth / 4));
        const uint32_t alpha8 = alpha2 * 85u;
        hdr1010102[pixel] = 700u | (500u << 10) | (300u << 20) | (alpha2 << 30);
        hdrHalfFloat[pixel * 4] = floatToHalf(2.0f);
        hdrHalfFloat[pixel * 4 + 1] = floatToHalf(1.5f);
        hdrHalfFloat[pixel * 4 + 2] = floatToHalf(1.0f);
        hdrHalfFloat[pixel * 4 + 3] = floatToHalf(alpha2 / 3.0f);
        sdr8888[pixel] = 120u | (80u << 8) | (40u << 16) | (alpha8 << 24);
      }
    }

    hdr1010102Desc.fmt = UHDR_IMG_FMT_32bppRGBA1010102;
    hdr1010102Desc.cg = UHDR_CG_BT_2100;
    hdr1010102Desc.ct = UHDR_CT_HLG;
    hdr1010102Desc.range = UHDR_CR_FULL_RANGE;
    hdr1010102Desc.w = kAlphaTestWidth;
    hdr1010102Desc.h = kAlphaTestHeight;
    hdr1010102Desc.planes[UHDR_PLANE_PACKED] = hdr1010102.data();
    hdr1010102Desc.stride[UHDR_PLANE_PACKED] = kAlphaTestWidth;

    hdrHalfFloatDesc.fmt = UHDR_IMG_FMT_64bppRGBAHalfFloat;
    hdrHalfFloatDesc.cg = UHDR_CG_BT_2100;
    hdrHalfFloatDesc.ct = UHDR_CT_LINEAR;
    hdrHalfFloatDesc.range = UHDR_CR_FULL_RANGE;
    hdrHalfFloatDesc.w = kAlphaTestWidth;
    hdrHalfFloatDesc.h = kAlphaTestHeight;
    hdrHalfFloatDesc.planes[UHDR_PLANE_PACKED] = hdrHalfFloat.data();
    hdrHalfFloatDesc.stride[UHDR_PLANE_PACKED] = kAlphaTestWidth;

    sdr8888Desc.fmt = UHDR_IMG_FMT_32bppRGBA8888;
    sdr8888Desc.cg = UHDR_CG_BT_709;
    sdr8888Desc.ct = UHDR_CT_SRGB;
    sdr8888Desc.range = UHDR_CR_FULL_RANGE;
    sdr8888Desc.w = kAlphaTestWidth;
    sdr8888Desc.h = kAlphaTestHeight;
    sdr8888Desc.planes[UHDR_PLANE_PACKED] = sdr8888.data();
    sdr8888Desc.stride[UHDR_PLANE_PACKED] = kAlphaTestWidth;
  }

  void makeHdr1010102AlphaOpaque() {
    for (uint32_t& pixel : hdr1010102) pixel |= 3u << 30;
  }
};

uhdr_error_info_t encodeRawAlphaImage(uhdr_codec_t codec, uhdr_raw_image_t* hdr,
                                      uhdr_raw_image_t* sdr, std::vector<uint8_t>* encoded) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  if (enc == nullptr) {
    uhdr_error_info_t status{};
    status.error_code = UHDR_CODEC_MEM_ERROR;
    return status;
  }

  uhdr_error_info_t status = uhdr_enc_set_raw_image(enc, hdr, UHDR_HDR_IMG);
  if (status.error_code == UHDR_CODEC_OK && sdr != nullptr) {
    status = uhdr_enc_set_raw_image(enc, sdr, UHDR_SDR_IMG);
  }
  if (status.error_code == UHDR_CODEC_OK) status = uhdr_enc_set_output_format(enc, codec);
  if (status.error_code == UHDR_CODEC_OK) status = uhdr_enc_set_quality(enc, 100, UHDR_BASE_IMG);
  if (status.error_code == UHDR_CODEC_OK) status = uhdr_encode(enc);
  if (status.error_code == UHDR_CODEC_OK) {
    uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
    if (output == nullptr || output->data_sz == 0) {
      status.error_code = UHDR_CODEC_ERROR;
    } else {
      const uint8_t* data = static_cast<const uint8_t*>(output->data);
      encoded->assign(data, data + output->data_sz);
    }
  }
  uhdr_release_encoder(enc);
  return status;
}

::testing::AssertionResult containerHasStraightAlpha(const std::vector<uint8_t>& encoded) {
  heif_context* context = heif_context_alloc();
  if (context == nullptr) return ::testing::AssertionFailure() << "libheif allocation failed";

  heif_error error =
      heif_context_read_from_memory_without_copy(context, encoded.data(), encoded.size(), nullptr);
  if (error.code != heif_error_Ok) {
    const std::string detail = error.message != nullptr ? error.message : "no detail";
    heif_context_free(context);
    return ::testing::AssertionFailure() << "libheif read failed: " << detail;
  }

  heif_image_handle* primary = nullptr;
  error = heif_context_get_primary_image_handle(context, &primary);
  if (error.code != heif_error_Ok || primary == nullptr) {
    const std::string detail = error.message != nullptr ? error.message : "no detail";
    heif_context_free(context);
    return ::testing::AssertionFailure() << "primary image lookup failed: " << detail;
  }

  const bool has_alpha = heif_image_handle_has_alpha_channel(primary);
  const bool is_premultiplied = heif_image_handle_is_premultiplied_alpha(primary);
  heif_image_handle_release(primary);
  heif_context_free(context);
  if (!has_alpha) return ::testing::AssertionFailure() << "base image has no alpha channel";
  if (is_premultiplied) {
    return ::testing::AssertionFailure() << "base image alpha is marked premultiplied";
  }
  return ::testing::AssertionSuccess();
}

::testing::AssertionResult decodedAlphaMatches(const std::vector<uint8_t>& encoded) {
  const ::testing::AssertionResult container_result = containerHasStraightAlpha(encoded);
  if (!container_result) return container_result;

  uhdr_compressed_image_t input{};
  input.data = const_cast<uint8_t*>(encoded.data());
  input.data_sz = encoded.size();
  input.capacity = encoded.size();

  uhdr_codec_private_t* dec = uhdr_create_decoder();
  if (dec == nullptr) return ::testing::AssertionFailure() << "decoder allocation failed";
  uhdr_error_info_t status = uhdr_dec_set_image(dec, &input);
  if (status.error_code == UHDR_CODEC_OK) {
    status = uhdr_dec_set_out_color_transfer(dec, UHDR_CT_SRGB);
  }
  if (status.error_code == UHDR_CODEC_OK) {
    status = uhdr_dec_set_out_img_format(dec, UHDR_IMG_FMT_32bppRGBA8888);
  }
  if (status.error_code == UHDR_CODEC_OK) status = uhdr_dec_probe(dec);
  if (status.error_code == UHDR_CODEC_OK) status = uhdr_decode(dec);
  if (status.error_code != UHDR_CODEC_OK) {
    const std::string detail = status.has_detail ? status.detail : "no detail";
    uhdr_release_decoder(dec);
    return ::testing::AssertionFailure() << "decode failed: " << detail;
  }

  uhdr_raw_image_t* decoded = uhdr_get_decoded_image(dec);
  if (decoded == nullptr || decoded->fmt != UHDR_IMG_FMT_32bppRGBA8888 ||
      decoded->w != kAlphaTestWidth || decoded->h != kAlphaTestHeight) {
    uhdr_release_decoder(dec);
    return ::testing::AssertionFailure() << "unexpected decoded image descriptor";
  }

  const auto* pixels = static_cast<const uint32_t*>(decoded->planes[UHDR_PLANE_PACKED]);
  const size_t stride = decoded->stride[UHDR_PLANE_PACKED];
  for (size_t y = 0; y < kAlphaTestHeight; ++y) {
    for (size_t x = 0; x < kAlphaTestWidth; ++x) {
      const int alpha = pixels[y * stride + x] >> 24;
      const int expected = static_cast<int>(x / (kAlphaTestWidth / 4)) * 85;
      if (std::abs(alpha - expected) > 16) {
        uhdr_release_decoder(dec);
        return ::testing::AssertionFailure() << "unexpected alpha " << alpha << ", expected "
                                             << expected << " at (" << x << ", " << y << ")";
      }
    }
  }
  uhdr_release_decoder(dec);
  return ::testing::AssertionSuccess();
}

void expectRawAlphaPreserved(uhdr_codec_t codec, uhdr_raw_image_t* hdr,
                             uhdr_raw_image_t* sdr = nullptr) {
  std::vector<uint8_t> encoded;
  const uhdr_error_info_t status = encodeRawAlphaImage(codec, hdr, sdr, &encoded);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << (status.has_detail ? status.detail : "no detail");
  EXPECT_TRUE(decodedAlphaMatches(encoded));
}

bool encoderUnavailable(const uhdr_error_info_t& status) {
  return status.error_code != UHDR_CODEC_OK && status.has_detail &&
         (strstr(status.detail, "Unsupported file-type") != nullptr ||
          strstr(status.detail, "No encoder") != nullptr);
}

}  // namespace

TEST_F(UltraHdrApiTest, HeicEncodeApi0AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_HEIF).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 85, UHDR_BASE_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 85, UHDR_GAIN_MAP_IMG).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t enc_status = uhdr_encode(enc);
  if (enc_status.error_code != UHDR_CODEC_OK) {
    if (enc_status.has_detail &&
        (strstr(enc_status.detail, "Unsupported file-type") != nullptr ||
         strstr(enc_status.detail, "No encoder") != nullptr)) {
      std::string detail_msg = enc_status.detail;
      uhdr_release_encoder(enc);
      GTEST_SKIP() << "HEVC encoder plugin not available in environment: " << detail_msg;
      return;
    }
  }
  ASSERT_EQ(enc_status.error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);

  // Decode HEIC stream
  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_color_transfer(dec, UHDR_CT_HLG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_img_format(dec, UHDR_IMG_FMT_32bppRGBA1010102).error_code, UHDR_CODEC_OK);

  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_get_image_width(dec), static_cast<int>(kImageWidth));
  EXPECT_EQ(uhdr_dec_get_image_height(dec), static_cast<int>(kImageHeight));

  uhdr_gainmap_metadata_t* metadata = uhdr_dec_get_gainmap_metadata(dec);
  EXPECT_NE(metadata, nullptr);

  uhdr_error_info_t dec_status = uhdr_decode(dec);
  if (dec_status.error_code != UHDR_CODEC_OK) {
    std::cout << "HeicEncodeApi0 decode error: " << (dec_status.has_detail ? dec_status.detail : "no detail") << std::endl;
  }
  ASSERT_EQ(dec_status.error_code, UHDR_CODEC_OK);
  uhdr_raw_image_t* decoded = uhdr_get_decoded_image(dec);
  ASSERT_NE(decoded, nullptr);
  EXPECT_EQ(decoded->w, kImageWidth);
  EXPECT_EQ(decoded->h, kImageHeight);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, HeicEncodeApi1AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mSdrRaw, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_HEIF).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t enc_status = uhdr_encode(enc);
  if (enc_status.error_code != UHDR_CODEC_OK) {
    if (enc_status.has_detail &&
        (strstr(enc_status.detail, "Unsupported file-type") != nullptr ||
         strstr(enc_status.detail, "No encoder") != nullptr)) {
      std::string detail_msg = enc_status.detail;
      uhdr_release_encoder(enc);
      GTEST_SKIP() << "HEVC encoder plugin not available in environment: " << detail_msg;
      return;
    }
  }
  ASSERT_EQ(enc_status.error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);

  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, HeicCompressedIntentsUnsupported) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_compressed_image(enc, &mSdrCompressed, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_HEIF).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t err = uhdr_encode(enc);
  EXPECT_EQ(err.error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);

  uhdr_release_encoder(enc);
}

// ============================================================================
// AVIF Tests (API-0, API-1, and Unsupported APIs)
// ============================================================================

TEST_F(UltraHdrApiTest, AvifEncodeApi0AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 85, UHDR_BASE_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 85, UHDR_GAIN_MAP_IMG).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t enc_status = uhdr_encode(enc);
  if (enc_status.error_code != UHDR_CODEC_OK) {
    if (enc_status.has_detail &&
        (strstr(enc_status.detail, "Unsupported file-type") != nullptr ||
         strstr(enc_status.detail, "No encoder") != nullptr)) {
      std::string detail_msg = enc_status.detail;
      uhdr_release_encoder(enc);
      GTEST_SKIP() << "AV1 encoder plugin not available in environment: " << detail_msg;
      return;
    }
  }
  ASSERT_EQ(enc_status.error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);

  // Decode AVIF stream
  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_color_transfer(dec, UHDR_CT_LINEAR).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_img_format(dec, UHDR_IMG_FMT_64bppRGBAHalfFloat).error_code, UHDR_CODEC_OK);

  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_get_image_width(dec), static_cast<int>(kImageWidth));
  EXPECT_EQ(uhdr_dec_get_image_height(dec), static_cast<int>(kImageHeight));

  uhdr_error_info_t dec_status = uhdr_decode(dec);
  if (dec_status.error_code != UHDR_CODEC_OK) {
    std::cout << "AvifEncodeApi0 decode error: " << (dec_status.has_detail ? dec_status.detail : "no detail") << std::endl;
  }
  ASSERT_EQ(dec_status.error_code, UHDR_CODEC_OK);
  uhdr_raw_image_t* decoded = uhdr_get_decoded_image(dec);
  ASSERT_NE(decoded, nullptr);
  EXPECT_EQ(decoded->w, kImageWidth);
  EXPECT_EQ(decoded->h, kImageHeight);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, AvifEncodeApi1AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mSdrRaw, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t enc_status = uhdr_encode(enc);
  if (enc_status.error_code != UHDR_CODEC_OK) {
    if (enc_status.has_detail &&
        (strstr(enc_status.detail, "Unsupported file-type") != nullptr ||
         strstr(enc_status.detail, "No encoder") != nullptr)) {
      uhdr_release_encoder(enc);
      GTEST_SKIP() << "AV1 encoder plugin not available in environment: " << enc_status.detail;
      return;
    }
  }
  ASSERT_EQ(enc_status.error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);

  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, AvifCompressedIntentsUnsupported) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_compressed_image(enc, &mSdrCompressed, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t err = uhdr_encode(enc);
  EXPECT_EQ(err.error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);

  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, AvifPreservesRawAlpha) {
  AlphaTestImages images;
  std::vector<uint8_t> encoded;
  uhdr_error_info_t status =
      encodeRawAlphaImage(UHDR_CODEC_AVIF, &images.hdr1010102Desc, nullptr, &encoded);
  if (encoderUnavailable(status)) {
    GTEST_SKIP() << "AV1 encoder plugin not available in environment: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << (status.has_detail ? status.detail : "no detail");
  EXPECT_TRUE(decodedAlphaMatches(encoded));
  expectRawAlphaPreserved(UHDR_CODEC_AVIF, &images.hdrHalfFloatDesc);
  images.makeHdr1010102AlphaOpaque();
  expectRawAlphaPreserved(UHDR_CODEC_AVIF, &images.hdr1010102Desc, &images.sdr8888Desc);
}

TEST_F(UltraHdrApiTest, HeifPreservesRawAlpha) {
  AlphaTestImages images;
  std::vector<uint8_t> encoded;
  uhdr_error_info_t status =
      encodeRawAlphaImage(UHDR_CODEC_HEIF, &images.hdr1010102Desc, nullptr, &encoded);
  if (encoderUnavailable(status)) {
    GTEST_SKIP() << "HEVC encoder plugin not available in environment: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << (status.has_detail ? status.detail : "no detail");
  EXPECT_TRUE(decodedAlphaMatches(encoded));
  expectRawAlphaPreserved(UHDR_CODEC_HEIF, &images.hdrHalfFloatDesc);
  images.makeHdr1010102AlphaOpaque();
  expectRawAlphaPreserved(UHDR_CODEC_HEIF, &images.hdr1010102Desc, &images.sdr8888Desc);
}
#else
TEST_F(UltraHdrApiTest, HeicCodecUnsupportedWhenDisabled) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_HEIF).error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, AvifCodecUnsupportedWhenDisabled) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);
  uhdr_release_encoder(enc);
}
#endif

}  // namespace ultrahdr
