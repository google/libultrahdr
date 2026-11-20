/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#ifndef ULTRAHDR_AGTM_H
#define ULTRAHDR_AGTM_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "ultrahdr_api.h"
#include "ultrahdr/gainmapmath.h"

namespace ultrahdr {

namespace smpte2094_50 {

/**
 * A 2D control point with an optional derivative slope `m` for SMPTE ST 2094-50 gain curves.
 */
struct ControlPoint {
  float x = 0.0f;  // Linear input luminance in SDR-relative units, in [0.0, 64.0].
  float y = 0.0f;  // Log2 gain value at `x`, in [-6.0, 6.0].
  float m = 0.0f;  // Derivative slope dy/dx at `x`, used when `use_pchip_slope` is false.

  bool operator==(const ControlPoint& other) const {
    return x == other.x && y == other.y && m == other.m;
  }
  bool operator!=(const ControlPoint& other) const { return !(*this == other); }
};

/**
 * Component mixing weights for SMPTE ST 2094-50 color gain evaluation (Clause 6.4).
 */
struct ComponentMix {
  std::array<float, 3> rgb = {0.0f, 0.0f, 0.0f};
  float max = 0.0f;
  float min = 0.0f;
  float component = 0.0f;

  bool operator==(const ComponentMix& other) const {
    return rgb == other.rgb && max == other.max && min == other.min &&
           component == other.component;
  }
  bool operator!=(const ComponentMix& other) const { return !(*this == other); }
};

/**
 * Alternate headroom tone-mapping rule in SMPTE ST 2094-50.
 */
struct ToneMappingRule {
  float alternate_hdr_headroom_log2 = 0.0f;  // In [0.0, 6.0].
  std::vector<ControlPoint> curve;           // 1 to 32 control points.
  bool use_pchip_slope = false;              // True to compute PCHIP slopes implicitly.
  ComponentMix mix{};
};

/**
 * Pure C++17 representation of SMPTE ST 2094-50:2026 Headroom Adaptive Gain Curves (HAGC)
 * dynamic metadata.
 */
struct DynamicMetadata {
  static constexpr uint8_t kApplicationVersion = 0;
  static constexpr uint8_t kMinimumApplicationVersion = 0;
  static constexpr float kDefaultHdrReferenceWhite = 203.0f;
  static constexpr size_t kMaxNumAlternateImages = 4;
  static constexpr size_t kMaxNumControlPoints = 32;
  static constexpr size_t kNumMixCoefficients = 6;

  static constexpr std::array<float, 8> kChromaticitiesSrgb = {
      0.64f, 0.33f, 0.30f, 0.60f, 0.15f, 0.06f, 0.3127f, 0.3290f};
  static constexpr std::array<float, 8> kChromaticitiesDisplayP3 = {
      0.68f, 0.32f, 0.265f, 0.69f, 0.15f, 0.06f, 0.3127f, 0.3290f};
  static constexpr std::array<float, 8> kChromaticitiesRec2020 = {
      0.708f, 0.292f, 0.17f, 0.797f, 0.131f, 0.046f, 0.3127f, 0.3290f};

  float hdr_reference_white = kDefaultHdrReferenceWhite;
  bool has_adaptive_tone_map_flag = true;
  float baseline_hdr_headroom_log2 = 0.0f;
  bool use_reference_white_tone_mapping_flag = false;
  std::array<float, 8> gain_application_space_chromaticities = kChromaticitiesRec2020;
  std::vector<ToneMappingRule> rules;
};

/**
 * Computes Fritsch-Carlson PCHIP slopes according to SMPTE ST 2094-50 Annex C (Formulas C.7-C.10).
 */
uhdr_error_info_t computePchipSlopes(const std::vector<float>& x, const std::vector<float>& y,
                                     std::vector<float>& out_slopes);

/**
 * Piecewise Cubic Hermite Interpolating Polynomial (PCHIP) evaluator with flat boundary clamping.
 */
class PchipInterpolator {
 public:
  PchipInterpolator() = default;

  static uhdr_error_info_t create(const std::vector<float>& x, const std::vector<float>& y,
                                  PchipInterpolator& out);
  static uhdr_error_info_t create(const std::vector<float>& x, const std::vector<float>& y,
                                  const std::vector<float>& slopes, PchipInterpolator& out);

  float interpolate(float xi) const;
  bool reverseInterpolate(float yi, float& out_xi) const;

  const std::vector<float>& x() const { return mX; }
  const std::vector<float>& y() const { return mY; }
  const std::vector<float>& slopes() const { return mSlopes; }

 private:
  std::vector<float> mX;
  std::vector<float> mY;
  std::vector<float> mSlopes;
};

/**
 * SMPTE ST 2094-50 gain curve evaluator: PCHIP over [x_0, x_{N-1}], flat below x_0, and
 * y_{N-1} + log2(x_{N-1} / x) highlight roll-off above x_{N-1} (Formula 11).
 */
class GainCurve {
 public:
  GainCurve() = default;

  static uhdr_error_info_t create(const std::vector<float>& x, const std::vector<float>& y,
                                  GainCurve& out);
  static uhdr_error_info_t create(const std::vector<float>& x, const std::vector<float>& y,
                                  const std::vector<float>& slopes, GainCurve& out);

  float interpolate(float xi) const;
  bool reverseInterpolate(float yi, float& out_xi) const;

  const PchipInterpolator& interpolator() const { return mInterp; }

 private:
  PchipInterpolator mInterp;
  float mYMin = 0.0f;
};

/**
 * Greedy error-minimizing PCHIP curve subsampler selecting at most `num_control_points` knots.
 */
uhdr_error_info_t createSubsampledPchip(const std::vector<float>& x, const std::vector<float>& y,
                                        size_t num_control_points, PchipInterpolator& out);

/**
 * Populates rules and slopes using the SMPTE ST 2094-50 Annex C.3.8 Reference White Tone Mapping
 * operator (RWTM).
 */
void populateUsingRwtm(DynamicMetadata& metadata);

/**
 * Populates RWTM rules (when `use_reference_white_tone_mapping_flag` is set) and computes PCHIP
 * slopes for all rules where `use_pchip_slope` is true.
 */
uhdr_error_info_t populateImplicitParameters(DynamicMetadata& metadata);

/**
 * Validates all normative SMPTE ST 2094-50 metadata and Annex C serialization constraints.
 */
uhdr_error_info_t validateDynamicMetadata(const DynamicMetadata& metadata);

/**
 * Serializes `metadata` into its SMPTE ST 2094-50 Annex C packed binary representation.
 */
uhdr_error_info_t encodeSt2094_50(const DynamicMetadata& metadata,
                                  std::vector<uint8_t>& out_bitstream);

/**
 * Parses a SMPTE ST 2094-50 Annex C binary payload into `out_metadata` and validates normative
 * constraints.
 */
uhdr_error_info_t parseSt2094_50(const uint8_t* data, size_t size, DynamicMetadata& out_metadata);

/**
 * Curve-fitting heuristic used when deriving SMPTE ST 2094-50 gain curves from a spatial gain map.
 */
enum class HagcFitHeuristic {
  kMovingAverage,
  kMovingMedian,
  kQuantileToneMap,
};

/**
 * Component-mixing weight selection mode for GainMap -> SMPTE ST 2094-50 derivation.
 */
enum class HagcComponentMixMode {
  kOptimize,         // Optimize all active weights (5 for 1-ch gainmap, 6 for 3-ch gainmap).
  kOptimize4,        // Optimize only (R, G, B, maxRGB).
  kLuma,             // Gamut-matched luminance weights.
  kMaxRgb,           // max(R, G, B).
  kHalfLumaHalfMax,  // 0.5 * luma + 0.5 * max(R, G, B).
};

/**
 * Options controlling GainMap -> SMPTE ST 2094-50 dynamic metadata derivation.
 */
struct HagcDerivationOptions {
  HagcFitHeuristic heuristic = HagcFitHeuristic::kMovingAverage;
  HagcComponentMixMode mix_mode = HagcComponentMixMode::kOptimize;
  size_t num_control_points = 16;  // Target control point count in [1, 32].
  size_t max_samples = 1001;       // Maximum subsampled pixel/solver rows (<= 1001 by default).
  bool sdr_is_601 = false;         // True when YUV SDR base uses full-range BT.601 JPEG matrix.
};

/**
 * Solves the simplex-constrained L1 regression problem:
 *   min_w ||A * w - B||_1   subject to   sum_{j=0}^{num_vars-1} w_j = 1,  w_j >= 0,
 * where `A` is row-major (`num_rows x num_vars`, with `1 <= num_vars <= 6`).
 * If `out_duality_gap` is non-null, writes a certified upper bound on `||A * w - B||_1 - opt_L1`.
 */
uhdr_error_info_t solveConstrainedL1Simplex(
    const float* A, const float* B, size_t num_rows, size_t num_vars,
    std::array<float, DynamicMetadata::kNumMixCoefficients>& out_weights,
    double* out_duality_gap = nullptr);

/**
 * Converts a linear tone-mapping PCHIP curve y = f(x) into a log2 gain PCHIP curve
 * g(x) = log2(f(x) / x), resolving x = 0 singularities via L'Hopital's rule.
 */
uhdr_error_info_t toneMapCurveToGainCurve(const PchipInterpolator& tone_map_curve,
                                          float base_headroom_log2, float alt_headroom_log2,
                                          PchipInterpolator& out_gain_curve);

}  // namespace smpte2094_50

using HagcMetadata = smpte2094_50::DynamicMetadata;

/**
 * Maximum byte length accepted for an externally supplied bare SMPTE ST 2094-50:2026 Annex C
 * payload (bounded by a single 65535-byte JPEG APP2 segment minus its 2-byte length field).
 */
inline constexpr size_t kMaxHagcPayloadBytes = 65533;

/**
 * Validates a bare SMPTE ST 2094-50:2026 Annex C binary payload (e.g., Camera HAL AGTM output).
 *
 * Fails closed with #UHDR_CODEC_INVALID_PARAM if \p hagc_data is null, \p hagc_size is outside
 * `[2, kMaxHagcPayloadBytes]`, the bitstream carries an ITU-T T.35 (`0xB5`) prefix instead of bare
 * Annex C syntax, trailing bits or bytes remain after the Annex C payload, or any field violates
 * normative SMPTE ST 2094-50 constraints.
 *
 * @param hagc_data Pointer to bare SMPTE ST 2094-50:2026 Annex C bytes.
 * @param hagc_size Size of \p hagc_data in bytes.
 * @return #UHDR_CODEC_OK on valid Annex C payload, or #UHDR_CODEC_INVALID_PARAM otherwise.
 */
uhdr_error_info_t validateHagcPayload(const void* hagc_data, size_t hagc_size);

/**
 * Validates a `uhdr_mem_block_t` descriptor carrying a bare SMPTE ST 2094-50:2026 Annex C payload.
 *
 * Fails closed with #UHDR_CODEC_INVALID_PARAM if \p hagc or `hagc->data` is null,
 * `hagc->capacity < hagc->data_sz`, or #validateHagcPayload(`hagc->data`, `hagc->data_sz`) fails.
 *
 * @param hagc Memory block descriptor containing bare SMPTE ST 2094-50:2026 Annex C bytes.
 * @return #UHDR_CODEC_OK on valid descriptor and payload, or #UHDR_CODEC_INVALID_PARAM otherwise.
 */
uhdr_error_info_t validateHagcMemBlock(const uhdr_mem_block_t* hagc);

/**
 * Derives SMPTE ST 2094-50:2026 (HAGC) dynamic metadata from an SDR base image and its
 * associated Ultra HDR / ISO 21496-1 gain map.
 */
uhdr_error_info_t deriveHagcFromGainMap(
    uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
    const uhdr_gainmap_metadata_ext_t* gainmap_metadata, smpte2094_50::DynamicMetadata& out_hagc,
    const smpte2094_50::HagcDerivationOptions& options = {});

/**
 * Derives SMPTE ST 2094-50:2026 dynamic metadata from an SDR base image and gain map, and encodes
 * it directly into its Annex C binary payload.
 */
uhdr_error_info_t deriveEncodedHagcFromGainMap(
    uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
    const uhdr_gainmap_metadata_ext_t* gainmap_metadata, std::vector<uint8_t>& out_bitstream,
    const smpte2094_50::HagcDerivationOptions& options = {});

/**
 * Serializes a standalone raw ICC v4.4 profile (`'acsp'` header at offset 0, with no 14-byte JPEG
 * `APP2` `"ICC_PROFILE\0\x01\x01"` prefix) suitable for ISO/IEC 14496-12 `'colr'` (`'prof'`) boxes
 * (HEIF/HEIC, AVIF, MP4), embedding a pre-encoded bare SMPTE ST 2094-50:2026 Annex C `'HAGC'` tag.
 *
 * Validates \p hagc_data via #validateHagcPayload without running GainMap-to-HAGC curve
 * derivation. Fails closed with #UHDR_CODEC_INVALID_PARAM on invalid color enums or malformed
 * \p hagc_data, leaving \p out_raw_icc unmodified.
 *
 * @param tf Color transfer function (#UHDR_CT_SRGB, #UHDR_CT_LINEAR, #UHDR_CT_HLG, or #UHDR_CT_PQ).
 * @param cg Color gamut (#UHDR_CG_BT_709, #UHDR_CG_DISPLAY_P3, or #UHDR_CG_BT_2100).
 * @param hagc_data Pointer to bare SMPTE ST 2094-50:2026 Annex C payload bytes.
 * @param hagc_size Size of \p hagc_data in bytes (`[2, kMaxHagcPayloadBytes]`).
 * @param out_raw_icc Output buffer receiving the raw `'acsp'` ICC v4.4 profile in a single
 *                    exact-sized allocation on success; left unmodified on error.
 * @return #UHDR_CODEC_OK on success, or #UHDR_CODEC_INVALID_PARAM on invalid arguments/payload.
 */
uhdr_error_info_t encodeRawIccProfileWithEncodedHagc(uhdr_color_transfer_t tf,
                                                     uhdr_color_gamut_t cg, const void* hagc_data,
                                                     size_t hagc_size,
                                                     std::vector<uint8_t>& out_raw_icc);

/**
 * Serializes a standalone raw ICC v4.4 profile (`'acsp'` header at offset 0, with no 14-byte JPEG
 * `APP2` `"ICC_PROFILE\0\x01\x01"` prefix) suitable for ISO/IEC 14496-12 `'colr'` (`'prof'`) boxes
 * by injecting or replacing the canonical `'HAGC'` tag (SMPTE ST 2094-50:2026) in an existing base
 * ICC profile.
 *
 * Accepts \p base_icc_data either as a raw `'acsp'` profile or with a single-chunk 14-byte JPEG
 * `APP2` `"ICC_PROFILE\0\x01\x01"` header, and always outputs raw `'acsp'` bytes without the
 * 14-byte `APP2` prefix. Preserves all non-`'HAGC'` tags (including custom tags and shared/aliased
 * tag offsets), upgrades the profile version to `>= 4.4`, clears any stale MD5 Profile ID checksum
 * (`[84..99]`), and validates \p hagc_data via #validateHagcPayload without running the
 * GainMap-to-HAGC solver. Fails closed with #UHDR_CODEC_INVALID_PARAM on null, truncated,
 * malformed, tagless, unsupported-version (`major > 4`), or unreassembled multi-chunk
 * (`chunk_count > 1`) \p base_icc_data or invalid \p hagc_data, leaving \p out_raw_icc unmodified.
 *
 * @param base_icc_data Pointer to the existing raw `'acsp'` or single-chunk `APP2` ICC profile.
 * @param base_icc_size Size of \p base_icc_data in bytes.
 * @param hagc_data Pointer to bare SMPTE ST 2094-50:2026 Annex C payload bytes.
 * @param hagc_size Size of \p hagc_data in bytes (`[2, kMaxHagcPayloadBytes]`).
 * @param out_raw_icc Output buffer receiving the raw `'acsp'` ICC v4.4 profile in a single
 *                    exact-sized allocation on success (`out_raw_icc` may alias input buffers);
 *                    left unmodified on error.
 * @return #UHDR_CODEC_OK on success, or #UHDR_CODEC_INVALID_PARAM on invalid base ICC or payload.
 */
uhdr_error_info_t encodeRawIccProfileWithEncodedHagc(const void* base_icc_data,
                                                     size_t base_icc_size, const void* hagc_data,
                                                     size_t hagc_size,
                                                     std::vector<uint8_t>& out_raw_icc);

/**
 * Derives SMPTE ST 2094-50:2026 (HAGC) dynamic metadata from an SDR base image and its gain map
 * and serializes a standalone raw `'acsp'` ICC v4.4 profile (with no 14-byte JPEG `APP2`
 * `"ICC_PROFILE\0\x01\x01"` prefix) containing the `'HAGC'` tag, suitable for ISO/IEC 14496-12
 * `'colr'` (`'prof'`) boxes (HEIF/HEIC, AVIF, MP4).
 *
 * Uses `sdr_intent->cg` (must be #UHDR_CG_BT_709, #UHDR_CG_DISPLAY_P3, or #UHDR_CG_BT_2100) and
 * `sdr_intent->ct` (defaults #UHDR_CT_UNSPECIFIED to #UHDR_CT_SRGB). Fails closed with
 * #UHDR_CODEC_INVALID_PARAM on null, invalid, or mismatched image/metadata descriptors, leaving
 * \p out_raw_icc unmodified.
 *
 * @param sdr_intent Base SDR raw image descriptor.
 * @param gainmap_img Gain-map raw image descriptor (`YCbCr400`, `RGB888`, or `RGBA8888`, with
 *                    dimensions `<= sdr_intent`).
 * @param gainmap_metadata Gain-map metadata descriptor.
 * @param out_raw_icc Output buffer receiving the raw `'acsp'` ICC v4.4 profile in a single
 *                    exact-sized allocation on success; left unmodified on error.
 * @param options Optional GainMap-to-HAGC curve-fitting options.
 * @return #UHDR_CODEC_OK on success, or #UHDR_CODEC_INVALID_PARAM on invalid inputs.
 */
uhdr_error_info_t encodeRawIccProfileWithDerivedHagc(
    const uhdr_raw_image_t* sdr_intent, const uhdr_raw_image_t* gainmap_img,
    const uhdr_gainmap_metadata_t* gainmap_metadata, std::vector<uint8_t>& out_raw_icc,
    const smpte2094_50::HagcDerivationOptions& options = {});

/**
 * Generates a gain map from an image and SMPTE 2094-50 dynamic metadata.
 *
 * @param image The input HDR image.
 * @param metadata The SMPTE 2094-50 dynamic metadata.
 * @param gainmap_metadata Output gain map metadata.
 * @param gainmap_img Output gain map image.
 * @param hdr_capacity_max Maximum display boost value for which the map is applied completely.
 * @return UHDR_CODEC_OK on success, or an error code on failure.
 */
uhdr_error_info_t generateGainMap(uhdr_raw_image_t* image,
                                  const smpte2094_50::DynamicMetadata& metadata,
                                  uhdr_gainmap_metadata_ext_t* gainmap_metadata,
                                  std::unique_ptr<uhdr_raw_image_ext_t>& gainmap_img,
                                  float hdr_capacity_max = -1.0f);

/**
 * Extracts, parses, and validates an ICC v4.4 'HAGC' tag (SMPTE ST 2094-50:2026 Annex C) for
 * HAGC-only image probing and decoding. Fails closed unless a valid 'HAGC' tag with
 * `has_adaptive_tone_map_flag == true` and invertible gain-application chromaticities is present.
 */
uhdr_error_info_t parseAndValidateHagcFromIcc(const void* icc_data, size_t icc_size,
                                              smpte2094_50::DynamicMetadata& out_hagc);

/**
 * Populates a descriptive `uhdr_gainmap_metadata_t` summary from validated SMPTE ST 2094-50
 * metadata for decoder metadata queries on HAGC-only images.
 */
void populateGainMapMetadataFromHagc(const smpte2094_50::DynamicMetadata& hagc,
                                     uhdr_color_gamut_t base_cg,
                                     uhdr_gainmap_metadata_t* out_metadata);

/**
 * Evaluates SMPTE ST 2094-50:2026 Clause 6 tone mapping directly from `base_img` into `dest`.
 */
uhdr_error_info_t applyHagc(uhdr_raw_image_t* base_img,
                            const smpte2094_50::DynamicMetadata& metadata,
                            uhdr_color_transfer_t output_ct, uhdr_img_fmt_t output_format,
                            float max_display_boost, bool base_is_601_yuv, uhdr_raw_image_t* dest);

}  // namespace ultrahdr

#endif  // ULTRAHDR_AGTM_H
