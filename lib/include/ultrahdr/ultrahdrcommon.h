/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#ifndef ULTRAHDR_ULTRAHDRCOMMON_H
#define ULTRAHDR_ULTRAHDRCOMMON_H

//#define LOG_NDEBUG 0

#ifdef UHDR_ENABLE_GLES
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#endif

#include <array>
#include <cfloat>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ultrahdr_api.h"

// ===============================================================================================
// Function Macros
// ===============================================================================================

#ifdef __ANDROID__

#ifdef LOG_NDEBUG
#include "android/log.h"

#ifndef LOG_TAG
#define LOG_TAG "UHDR"
#endif

#ifndef ALOGD
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#endif

#ifndef ALOGE
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

#ifndef ALOGI
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#endif

#ifndef ALOGV
#define ALOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#endif

#ifndef ALOGW
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#endif

#else

#define ALOGD(...) ((void)0)
#define ALOGE(...) ((void)0)
#define ALOGI(...) ((void)0)
#define ALOGV(...) ((void)0)
#define ALOGW(...) ((void)0)

#endif

#else

#ifdef LOG_NDEBUG
#include <cstdio>

#define ALOGD(...)                \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n");        \
  } while (0)

#define ALOGE(...)                \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n");        \
  } while (0)

#define ALOGI(...)                \
  do {                            \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n");        \
  } while (0)

#define ALOGV(...)                \
  do {                            \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n");        \
  } while (0)

#define ALOGW(...)                \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n");        \
  } while (0)

#else

#define ALOGD(...) ((void)0)
#define ALOGE(...) ((void)0)
#define ALOGI(...) ((void)0)
#define ALOGV(...) ((void)0)
#define ALOGW(...) ((void)0)

#endif

#endif

#define ALIGNM(x, m) ((((x) + ((m)-1)) / (m)) * (m))

#define UHDR_ERR_CHECK(x)                     \
  {                                           \
    uhdr_error_info_t status = (x);           \
    if (status.error_code != UHDR_CODEC_OK) { \
      return status;                          \
    }                                         \
  }

#if defined(_MSC_VER)
#define FORCE_INLINE __forceinline
#define INLINE __inline
#else
#define FORCE_INLINE __inline__ __attribute__((always_inline))
#define INLINE inline
#endif

// '__has_attribute' macro was introduced by clang. later picked up by gcc.
// If not supported by the current toolchain, define it to zero.
#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

// Disables undefined behavior analysis for a function.
// GCC 4.9+ uses __attribute__((no_sanitize_undefined))
// clang uses __attribute__((no_sanitize("undefined")))
#if defined(__GNUC__) && ((__GNUC__ * 100 + __GNUC_MINOR__) >= 409)
#define UHDR_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize_undefined))
#elif __has_attribute(no_sanitize)
#define UHDR_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize("undefined")))
#else
#define UHDR_NO_SANITIZE_UNDEFINED
#endif

static const uhdr_error_info_t g_no_error = {UHDR_CODEC_OK, 0, ""};

namespace ultrahdr {

// ===============================================================================================
// Globals
// ===============================================================================================
extern const int kMinWidth, kMinHeight;
extern const int kMaxWidth, kMaxHeight;

// ===============================================================================================
// Structure Definitions
// ===============================================================================================

/**\brief uhdr memory block */
typedef struct uhdr_memory_block {
  uhdr_memory_block(size_t capacity);

  std::unique_ptr<uint8_t[]> m_buffer; /**< data */
  size_t m_capacity;                   /**< capacity */
} uhdr_memory_block_t;                 /**< alias for struct uhdr_memory_block */

/**\brief extended raw image descriptor */
typedef struct uhdr_raw_image_ext : uhdr_raw_image_t {
  uhdr_raw_image_ext(uhdr_img_fmt_t fmt, uhdr_color_gamut_t cg, uhdr_color_transfer_t ct,
                     uhdr_color_range_t range, unsigned w, unsigned h, unsigned align_stride_to);

 private:
  std::unique_ptr<ultrahdr::uhdr_memory_block> m_block;
} uhdr_raw_image_ext_t; /**< alias for struct uhdr_raw_image_ext */

/**\brief extended compressed image descriptor */
typedef struct uhdr_compressed_image_ext : uhdr_compressed_image_t {
  uhdr_compressed_image_ext(uhdr_color_gamut_t cg, uhdr_color_transfer_t ct,
                            uhdr_color_range_t range, size_t sz);

 private:
  std::unique_ptr<ultrahdr::uhdr_memory_block> m_block;
} uhdr_compressed_image_ext_t; /**< alias for struct uhdr_compressed_image_ext */

/*!\brief forward declaration for image effect descriptor */
typedef struct uhdr_effect_desc uhdr_effect_desc_t;

/**\brief Gain map metadata. */
typedef struct uhdr_gainmap_metadata_ext : uhdr_gainmap_metadata {
  uhdr_gainmap_metadata_ext() {}

  uhdr_gainmap_metadata_ext(std::string ver) : version(ver) {}

  uhdr_gainmap_metadata_ext(uhdr_gainmap_metadata& metadata, std::string ver)
      : uhdr_gainmap_metadata_ext(ver) {
    std::copy(metadata.max_content_boost, metadata.max_content_boost + 3, max_content_boost);
    std::copy(metadata.min_content_boost, metadata.min_content_boost + 3, min_content_boost);
    std::copy(metadata.gamma, metadata.gamma + 3, gamma);
    std::copy(metadata.offset_sdr, metadata.offset_sdr + 3, offset_sdr);
    std::copy(metadata.offset_hdr, metadata.offset_hdr + 3, offset_hdr);
    hdr_capacity_min = metadata.hdr_capacity_min;
    hdr_capacity_max = metadata.hdr_capacity_max;
    use_base_cg = metadata.use_base_cg;
  }

  bool are_all_channels_identical() const {
    return max_content_boost[0] == max_content_boost[1] &&
           max_content_boost[0] == max_content_boost[2] &&
           min_content_boost[0] == min_content_boost[1] &&
           min_content_boost[0] == min_content_boost[2] && gamma[0] == gamma[1] &&
           gamma[0] == gamma[2] && offset_sdr[0] == offset_sdr[1] &&
           offset_sdr[0] == offset_sdr[2] && offset_hdr[0] == offset_hdr[1] &&
           offset_hdr[0] == offset_hdr[2];
  }

  std::string version;         /**< Ultra HDR format version */
} uhdr_gainmap_metadata_ext_t; /**< alias for struct uhdr_gainmap_metadata */

#ifdef UHDR_ENABLE_GLES

typedef enum uhdr_effect_shader {
  UHDR_MIR_HORZ,
  UHDR_MIR_VERT,
  UHDR_ROT_90,
  UHDR_ROT_180,
  UHDR_ROT_270,
  UHDR_CROP,
  UHDR_RESIZE,
} uhdr_effect_shader_t;

/**\brief OpenGL context */
typedef struct uhdr_opengl_ctxt {
  // EGL Context
  EGLDisplay mEGLDisplay; /**< EGL display connection */
  EGLContext mEGLContext; /**< EGL rendering context */
  EGLSurface mEGLSurface; /**< EGL surface for rendering */
  EGLConfig mEGLConfig;   /**< EGL frame buffer configuration */

  // GLES Context
  GLuint mQuadVAO, mQuadVBO, mQuadEBO;           /**< GL objects */
  GLuint mShaderProgram[UHDR_RESIZE + 1];        /**< Shader programs */
  GLuint mDecodedImgTexture, mGainmapImgTexture; /**< GL Textures */
  uhdr_error_info_t mErrorStatus;                /**< Context status */

  uhdr_opengl_ctxt();
  ~uhdr_opengl_ctxt();

  /*!\brief Initializes the OpenGL context. Mainly it prepares EGL. We want a GLES3.0 context and a
   * surface that supports pbuffer. Once this is done and surface is made current, the gl state is
   * initialized
   *
   * \return none
   */
  void init_opengl_ctxt();

  /*!\brief This method is used to compile a shader
   *
   * \param[in]   type    shader type
   * \param[in]   source  shader source code
   *
   * \return GLuint #shader_id if operation succeeds, 0 otherwise.
   */
  GLuint compile_shader(GLenum type, const char* source);

  /*!\brief This method is used to create a shader program
   *
   * \param[in]   vertex_source      vertex shader source code
   * \param[in]   fragment_source    fragment shader source code
   *
   * \return GLuint #shader_program_id if operation succeeds, 0 otherwise.
   */
  GLuint create_shader_program(const char* vertex_source, const char* fragment_source);

  /*!\brief This method is used to create a 2D texture for a raw image
   * NOTE: For multichannel planar image, this method assumes the channel data to be contiguous
   * NOTE: For any channel, this method assumes width and stride to be identical
   *
   * \param[in]   fmt       image format
   * \param[in]   w         image width
   * \param[in]   h         image height
   * \param[in]   data      image data
   *
   * \return GLuint #texture_id if operation succeeds, 0 otherwise.
   */
  GLuint create_texture(uhdr_img_fmt_t fmt, int w, int h, void* data);

  /*!\breif This method is used to read data from texture into a raw image
   * NOTE: For any channel, this method assumes width and stride to be identical
   *
   * \param[in]   texture    texture_id
   * \param[in]   fmt        image format
   * \param[in]   w          image width
   * \param[in]   h          image height
   * \param[in]   data       image data
   *
   * \return none
   */
  void read_texture(GLuint* texture, uhdr_img_fmt_t fmt, int w, int h, void* data);

  /*!\brief This method is used to set up quad buffers and arrays
   *
   * \return none
   */
  void setup_quad();

  /*!\brief This method is used to set up frame buffer for a 2D texture
   *
   * \param[in]   texture         texture id
   *
   * \return GLuint #framebuffer_id if operation succeeds, 0 otherwise.
   */
  GLuint setup_framebuffer(GLuint& texture);

  /*!\brief Checks for gl errors. On error, internal error state is updated with details
   *
   * \param[in]   msg     useful description for logging
   *
   * \return none
   */
  void check_gl_errors(const char* msg);

  /*!\brief Reset the current context to default state for reuse
   *
   * \return none
   */
  void reset_opengl_ctxt();

  /*!\brief Deletes the current context
   *
   * \return none
   */
  void delete_opengl_ctxt();

} uhdr_opengl_ctxt_t; /**< alias for struct uhdr_opengl_ctxt */

bool isBufferDataContiguous(uhdr_raw_image_t* img);

#endif

uhdr_error_info_t uhdr_validate_gainmap_metadata_descriptor(uhdr_gainmap_metadata_t* metadata);

}  // namespace ultrahdr

// ===============================================================================================
// Extensions of ultrahdr api definitions, so outside ultrahdr namespace
// ===============================================================================================

struct uhdr_codec_private {
  std::deque<ultrahdr::uhdr_effect_desc_t*> m_effects;
#ifdef UHDR_ENABLE_GLES
  ultrahdr::uhdr_opengl_ctxt_t m_uhdr_gl_ctxt;
  bool m_enable_gles;
#endif
  bool m_sailed;

  virtual ~uhdr_codec_private();
};

struct uhdr_encoder_private : uhdr_codec_private {
  // config data
  std::map<uhdr_img_label, std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t>> m_raw_images;
  std::map<uhdr_img_label, std::unique_ptr<ultrahdr::uhdr_compressed_image_ext_t>>
      m_compressed_images;
  std::map<uhdr_img_label, int> m_quality;
  std::vector<uint8_t> m_exif;
  uhdr_gainmap_metadata_t m_metadata;
  uhdr_codec_t m_output_format;
  int m_gainmap_scale_factor;
  bool m_use_multi_channel_gainmap;
  float m_gamma;
  uhdr_enc_preset_t m_enc_preset;
  float m_min_content_boost;
  float m_max_content_boost;
  float m_target_disp_max_brightness;

  // internal data
  std::unique_ptr<ultrahdr::uhdr_compressed_image_ext_t> m_compressed_output_buffer;
  uhdr_error_info_t m_encode_call_status;
};

struct uhdr_decoder_private : uhdr_codec_private {
  // config data
  std::unique_ptr<ultrahdr::uhdr_compressed_image_ext_t> m_uhdr_compressed_img;
  uhdr_img_fmt_t m_output_fmt;
  uhdr_color_transfer_t m_output_ct;
  float m_output_max_disp_boost;

  // internal data
  bool m_probed;
  bool m_is_jpeg;
  std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t> m_decoded_img_buffer;
  std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t> m_gainmap_img_buffer;
  int m_img_wd, m_img_ht;
  int m_gainmap_wd, m_gainmap_ht, m_gainmap_num_comp;
  std::vector<uint8_t> m_exif;
  uhdr_mem_block_t m_exif_block;
  std::vector<uint8_t> m_icc;
  uhdr_mem_block_t m_icc_block;
  std::vector<uint8_t> m_base_img;
  uhdr_mem_block_t m_base_img_block;
  std::vector<uint8_t> m_gainmap_img;
  uhdr_mem_block_t m_gainmap_img_block;
  uhdr_gainmap_metadata_t m_metadata;
  uhdr_error_info_t m_probe_call_status;
  uhdr_error_info_t m_decode_call_status;
};

namespace ultrahdr {

// Default configurations
// gainmap image downscale factor
static const int kMapDimensionScaleFactorDefault = 1;
static const int kMapDimensionScaleFactorAndroidDefault = 4;

// JPEG compress quality (0 ~ 100) for base image
static const int kBaseCompressQualityDefault = 95;

// JPEG compress quality (0 ~ 100) for gain map
static const int kMapCompressQualityDefault = 95;
static const int kMapCompressQualityAndroidDefault = 85;

// Gain map calculation
static const bool kUseMultiChannelGainMapDefault = true;
static const bool kUseMultiChannelGainMapAndroidDefault = false;

// encoding preset
static const uhdr_enc_preset_t kEncSpeedPresetDefault = UHDR_USAGE_BEST_QUALITY;
static const uhdr_enc_preset_t kEncSpeedPresetAndroidDefault = UHDR_USAGE_REALTIME;

// Default gamma value for gain map
static const float kGainMapGammaDefault = 1.0f;

// The current JPEGR version that we encode to
static const char* const kJpegrVersion = "1.0";

class UltraHdr {
 public:
  UltraHdr(void* uhdrGLESCtxt = nullptr,
           int mapDimensionScaleFactor = kMapDimensionScaleFactorAndroidDefault,
           int mapCompressQuality = kMapCompressQualityAndroidDefault,
           bool useMultiChannelGainMap = kUseMultiChannelGainMapAndroidDefault,
           float gamma = kGainMapGammaDefault,
           uhdr_enc_preset_t preset = kEncSpeedPresetAndroidDefault,
           float minContentBoost = FLT_MIN, float maxContentBoost = FLT_MAX,
           float targetDispPeakBrightness = -1.0f);

  /*!\brief This function receives iso block and / or xmp block and parses gainmap metadata and fill
   * the output descriptor. If both iso block and xmp block are available, then iso block is
   * preferred over xmp.
   *
   * \param[in]       iso_data                  iso memory block
   * \param[in]       iso_size                  iso block size
   * \param[in]       xmp_data                  xmp memory block
   * \param[in]       xmp_size                  xmp block size
   * \param[in, out]  gainmap_metadata          gainmap metadata descriptor
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t parseGainMapMetadata(uint8_t* iso_data, size_t iso_size, uint8_t* xmp_data,
                                         size_t xmp_size, uint8_t* exif_data, int exif_size,
                                         uhdr_gainmap_metadata_ext_t* uhdr_metadata);

  /*!\brief This method is used to tone map a hdr image
   *
   * \param[in]            hdr_intent      hdr image descriptor
   * \param[in, out]       sdr_intent      sdr image descriptor
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent);

  /*!\brief This method takes hdr intent and sdr intent and computes gainmap coefficient.
   *
   * This method is called in the encoding pipeline. It takes uncompressed 8-bit and 10-bit yuv
   * images as input and calculates gainmap.
   *
   * NOTE: The input images must be the same resolution.
   * NOTE: The SDR input is assumed to use the sRGB transfer function.
   *
   * \param[in]       sdr_intent               sdr intent raw input image descriptor
   * \param[in]       hdr_intent               hdr intent raw input image descriptor
   * \param[in, out]  gainmap_metadata         gainmap metadata descriptor
   * \param[in, out]  gainmap_img              gainmap image descriptor
   * \param[in]       sdr_is_601               (optional) if sdr_is_601 is true, then use BT.601
   *                                           gamut to represent sdr intent regardless of the value
   *                                           present in the sdr intent image descriptor
   * \param[in]       use_luminance            (optional) used for single channel gainmap. If
   *                                           use_luminance is true, gainmap calculation is based
   *                                           on the pixel's luminance which is a weighted
   *                                           combination of r, g, b channels; otherwise, gainmap
   *                                           calculation is based of the maximun value of r, g, b
   *                                           channels.
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* hdr_intent,
                                    uhdr_gainmap_metadata_ext_t* gainmap_metadata,
                                    std::unique_ptr<uhdr_raw_image_ext_t>& gainmap_img,
                                    bool sdr_is_601 = false, bool use_luminance = true);

  /*!\brief This method takes sdr intent, gainmap image and gainmap metadata and computes hdr
   * intent. This method is called in the decoding pipeline. The output hdr intent image will have
   * same color gamut as sdr intent.
   *
   * NOTE: The SDR input is assumed to use the sRGB transfer function.
   *
   * \param[in]       sdr_intent               sdr intent raw input image descriptor
   * \param[in]       gainmap_img              gainmap image descriptor
   * \param[in]       gainmap_metadata         gainmap metadata descriptor
   * \param[in]       output_ct                output color transfer
   * \param[in]       output_format            output pixel format
   * \param[in]       max_display_boost        the maximum available boost supported by a
   *                                           display, the value must be greater than or equal
   *                                           to 1.0
   * \param[in, out]  dest                     output image descriptor to store output
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
                                 uhdr_gainmap_metadata_ext_t* gainmap_metadata,
                                 uhdr_color_transfer_t output_ct, uhdr_img_fmt_t output_format,
                                 float max_display_boost, uhdr_raw_image_t* dest);

  /*!\brief This method is used to convert a raw image from one gamut space to another gamut space
   * in-place.
   *
   * \param[in, out]  image              raw image descriptor
   * \param[in]       src_encoding       input gamut space
   * \param[in]       dst_encoding       destination gamut space
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t convertYuv(uhdr_raw_image_t* image, uhdr_color_gamut_t src_encoding,
                               uhdr_color_gamut_t dst_encoding);

 protected:
  /*!\brief set gain map dimension scale factor
   * NOTE: Applicable only in encoding scenario
   *
   * \param[in]       mapDimensionScaleFactor      scale factor
   *
   * \return none
   */
  void setMapDimensionScaleFactor(int mapDimensionScaleFactor) {
    this->mMapDimensionScaleFactor = mapDimensionScaleFactor;
  }

  /*!\brief get gain map dimension scale factor
   * NOTE: Applicable only in encoding scenario
   *
   * \return mapDimensionScaleFactor
   */
  int getMapDimensionScaleFactor() { return this->mMapDimensionScaleFactor; }

  /*!\brief set gain map compression quality factor
   * NOTE: Applicable only in encoding scenario
   *
   * \param[in]       mapCompressQuality      quality factor for gain map image compression
   *
   * \return none
   */
  void setMapCompressQuality(int mapCompressQuality) {
    this->mMapCompressQuality = mapCompressQuality;
  }

  /*!\brief get gain map quality factor
   * NOTE: Applicable only in encoding scenario
   *
   * \return quality factor
   */
  int getMapCompressQuality() { return this->mMapCompressQuality; }

  /*!\brief set gain map gamma
   * NOTE: Applicable only in encoding scenario
   *
   * \param[in]       gamma      gamma parameter that is used for gain map calculation
   *
   * \return none
   */
  void setGainMapGamma(float gamma) { this->mGamma = gamma; }

  /*!\brief get gain map gamma
   * NOTE: Applicable only in encoding scenario
   *
   * \return gamma parameter
   */
  float getGainMapGamma() { return this->mGamma; }

  /*!\brief enable / disable multi channel gain map
   * NOTE: Applicable only in encoding scenario
   *
   * \param[in]       useMultiChannelGainMap      enable / disable multi channel gain map
   *
   * \return none
   */
  void setUseMultiChannelGainMap(bool useMultiChannelGainMap) {
    this->mUseMultiChannelGainMap = useMultiChannelGainMap;
  }

  /*!\brief check if multi channel gain map is enabled
   * NOTE: Applicable only in encoding scenario
   *
   * \return true if multi channel gain map is enabled, false otherwise
   */
  bool isUsingMultiChannelGainMap() { return this->mUseMultiChannelGainMap; }

  /*!\brief set gain map min and max content boost
   * NOTE: Applicable only in encoding scenario
   *
   * \param[in]       minBoost      gain map min content boost
   * \param[in]       maxBoost      gain map max content boost
   *
   * \return none
   */
  void setGainMapMinMaxContentBoost(float minBoost, float maxBoost) {
    this->mMinContentBoost = minBoost;
    this->mMaxContentBoost = maxBoost;
  }

  /*!\brief get gain map min max content boost
   * NOTE: Applicable only in encoding scenario
   *
   * \param[out]       minBoost      gain map min content boost
   * \param[out]       maxBoost      gain map max content boost
   *
   * \return none
   */
  void getGainMapMinMaxContentBoost(float& minBoost, float& maxBoost) {
    minBoost = this->mMinContentBoost;
    maxBoost = this->mMaxContentBoost;
  }

  // Configurations
  void* mUhdrGLESCtxt;              // opengl es context
  int mMapDimensionScaleFactor;     // gain map scale factor
  int mMapCompressQuality;          // gain map quality factor
  bool mUseMultiChannelGainMap;     // enable multichannel gain map
  float mGamma;                     // gain map gamma parameter
  uhdr_enc_preset_t mEncPreset;     // encoding speed preset
  float mMinContentBoost;           // min content boost recommendation
  float mMaxContentBoost;           // max content boost recommendation
  float mTargetDispPeakBrightness;  // target display max luminance in nits
};

/*
 * Holds tonemapping results of a pixel
 */
struct GlobalTonemapOutputs {
  std::array<float, 3> rgb_out;
  float y_hdr;
  float y_sdr;
};

/*!\brief Applies a global tone mapping, based on Chrome's HLG/PQ rendering implemented at
 *  https://source.chromium.org/chromium/chromium/src/+/main:ui/gfx/color_transform.cc;l=1197-1252;drc=ac505aff1d29ec3bfcf317cb77d5e196a3664e92
 *
 * \param[in]       rgb_in              hdr intent pixel in array format.
 * \param[in]       headroom            ratio between hdr and sdr peak luminances. Must be greater
 *                                      than 1. If the input is normalized, then this is used to
 *                                      stretch it linearly from [0.0..1.0] to [0.0..headroom]
 * \param[in]       is_normalized       marker to differentiate, if the input is normalized.
 *
 * \return tonemapped pixel in the normalized range [0.0..1.0]
 */
GlobalTonemapOutputs globalTonemap(const std::array<float, 3>& rgb_in, float headroom,
                                   bool is_normalized);
}  // namespace ultrahdr

#endif  // ULTRAHDR_ULTRAHDRCOMMON_H
