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

#ifndef USE_BIG_ENDIAN
#define USE_BIG_ENDIAN true
#endif

#include <ultrahdr/icc.h>
#include <vector>
#include <utils/Log.h>

#ifndef FLT_MAX
#define FLT_MAX 0x1.fffffep127f
#endif

namespace android::ultrahdr {
static void Matrix3x3_apply(const Matrix3x3* m, float* x) {
    float y0 = x[0] * m->vals[0][0] + x[1] * m->vals[0][1] + x[2] * m->vals[0][2];
    float y1 = x[0] * m->vals[1][0] + x[1] * m->vals[1][1] + x[2] * m->vals[1][2];
    float y2 = x[0] * m->vals[2][0] + x[1] * m->vals[2][1] + x[2] * m->vals[2][2];
    x[0] = y0;
    x[1] = y1;
    x[2] = y2;
}

bool Matrix3x3_invert(const Matrix3x3* src, Matrix3x3* dst) {
    double a00 = src->vals[0][0],
           a01 = src->vals[1][0],
           a02 = src->vals[2][0],
           a10 = src->vals[0][1],
           a11 = src->vals[1][1],
           a12 = src->vals[2][1],
           a20 = src->vals[0][2],
           a21 = src->vals[1][2],
           a22 = src->vals[2][2];

    double b0 = a00*a11 - a01*a10,
           b1 = a00*a12 - a02*a10,
           b2 = a01*a12 - a02*a11,
           b3 = a20,
           b4 = a21,
           b5 = a22;

    double determinant = b0*b5
                       - b1*b4
                       + b2*b3;

    if (determinant == 0) {
        return false;
    }

    double invdet = 1.0 / determinant;
    if (invdet > +FLT_MAX || invdet < -FLT_MAX || !isfinitef_((float)invdet)) {
        return false;
    }

    b0 *= invdet;
    b1 *= invdet;
    b2 *= invdet;
    b3 *= invdet;
    b4 *= invdet;
    b5 *= invdet;

    dst->vals[0][0] = (float)( a11*b5 - a12*b4 );
    dst->vals[1][0] = (float)( a02*b4 - a01*b5 );
    dst->vals[2][0] = (float)(        +     b2 );
    dst->vals[0][1] = (float)( a12*b3 - a10*b5 );
    dst->vals[1][1] = (float)( a00*b5 - a02*b3 );
    dst->vals[2][1] = (float)(        -     b1 );
    dst->vals[0][2] = (float)( a10*b4 - a11*b3 );
    dst->vals[1][2] = (float)( a01*b3 - a00*b4 );
    dst->vals[2][2] = (float)(        +     b0 );

    for (int r = 0; r < 3; ++r)
    for (int c = 0; c < 3; ++c) {
        if (!isfinitef_(dst->vals[r][c])) {
            return false;
        }
    }
    return true;
}

static Matrix3x3 Matrix3x3_concat(const Matrix3x3* A, const Matrix3x3* B) {
    Matrix3x3 m = { { { 0,0,0 },{ 0,0,0 },{ 0,0,0 } } };
    for (int r = 0; r < 3; r++)
        for (int c = 0; c < 3; c++) {
            m.vals[r][c] = A->vals[r][0] * B->vals[0][c]
                         + A->vals[r][1] * B->vals[1][c]
                         + A->vals[r][2] * B->vals[2][c];
        }
    return m;
}

static void float_XYZD50_to_grid16_lab(const float* xyz_float, uint8_t* grid16_lab) {
    float v[3] = {
            xyz_float[0] / kD50_x,
            xyz_float[1] / kD50_y,
            xyz_float[2] / kD50_z,
    };
    for (size_t i = 0; i < 3; ++i) {
        v[i] = v[i] > 0.008856f ? cbrtf(v[i]) : v[i] * 7.787f + (16 / 116.0f);
    }
    const float L = v[1] * 116.0f - 16.0f;
    const float a = (v[0] - v[1]) * 500.0f;
    const float b = (v[1] - v[2]) * 200.0f;
    const float Lab_unorm[3] = {
            L * (1 / 100.f),
            (a + 128.0f) * (1 / 255.0f),
            (b + 128.0f) * (1 / 255.0f),
    };
    // This will encode L=1 as 0xFFFF. This matches how skcms will interpret the
    // table, but the spec appears to indicate that the value should be 0xFF00.
    // https://crbug.com/skia/13807
    for (size_t i = 0; i < 3; ++i) {
        reinterpret_cast<uint16_t*>(grid16_lab)[i] =
                Endian_SwapBE16(float_round_to_unorm16(Lab_unorm[i]));
    }
}

std::string IccHelper::get_desc_string(const ultrahdr_transfer_function tf,
                                       const ultrahdr_color_gamut gamut) {
    std::string result;
    switch (gamut) {
        case ULTRAHDR_COLORGAMUT_BT709:
            result += "sRGB";
            break;
        case ULTRAHDR_COLORGAMUT_P3:
            result += "Display P3";
            break;
        case ULTRAHDR_COLORGAMUT_BT2100:
            result += "Rec2020";
            break;
        default:
            result += "Unknown";
            break;
    }
    result += " Gamut with ";
    switch (tf) {
        case ULTRAHDR_TF_SRGB:
            result += "sRGB";
            break;
        case ULTRAHDR_TF_LINEAR:
            result += "Linear";
            break;
        case ULTRAHDR_TF_PQ:
            result += "PQ";
            break;
        case ULTRAHDR_TF_HLG:
            result += "HLG";
            break;
        default:
            result += "Unknown";
            break;
    }
    result += " Transfer";
    return result;
}

sp<DataStruct> IccHelper::write_text_tag(const char* text) {
    uint32_t text_length = strlen(text);
    uint32_t header[] = {
            Endian_SwapBE32(kTAG_TextType),                         // Type signature
            0,                                                      // Reserved
            Endian_SwapBE32(1),                                     // Number of records
            Endian_SwapBE32(12),                                    // Record size (must be 12)
            Endian_SwapBE32(SetFourByteTag('e', 'n', 'U', 'S')),    // English USA
            Endian_SwapBE32(2 * text_length),                       // Length of string in bytes
            Endian_SwapBE32(28),                                    // Offset of string
    };

    uint32_t total_length = text_length * 2 + sizeof(header);
    total_length = (((total_length + 2) >> 2) << 2);  // 4 aligned
    sp<DataStruct> dataStruct = sp<DataStruct>::make(total_length);

    if (!dataStruct->write(header, sizeof(header))) {
        ALOGE("write_text_tag(): error in writing data");
        return dataStruct;
    }

    for (size_t i = 0; i < text_length; i++) {
        // Convert ASCII to big-endian UTF-16.
        dataStruct->write8(0);
        dataStruct->write8(text[i]);
    }

    return dataStruct;
}

sp<DataStruct> IccHelper::write_xyz_tag(float x, float y, float z) {
    uint32_t data[] = {
            Endian_SwapBE32(kXYZ_PCSSpace),
            0,
            static_cast<uint32_t>(Endian_SwapBE32(float_round_to_fixed(x))),
            static_cast<uint32_t>(Endian_SwapBE32(float_round_to_fixed(y))),
            static_cast<uint32_t>(Endian_SwapBE32(float_round_to_fixed(z))),
    };
    sp<DataStruct> dataStruct = sp<DataStruct>::make(sizeof(data));
    dataStruct->write(&data, sizeof(data));
    return dataStruct;
}

sp<DataStruct> IccHelper::write_trc_tag(const int table_entries, const void* table_16) {
    int total_length = 4 + 4 + 4 + table_entries * 2;
    total_length = (((total_length + 2) >> 2) << 2);  // 4 aligned
    sp<DataStruct> dataStruct = sp<DataStruct>::make(total_length);
    dataStruct->write32(Endian_SwapBE32(kTAG_CurveType));     // Type
    dataStruct->write32(0);                                   // Reserved
    dataStruct->write32(Endian_SwapBE32(table_entries));      // Value count
    for (size_t i = 0; i < table_entries; ++i) {
        uint16_t value = reinterpret_cast<const uint16_t*>(table_16)[i];
        dataStruct->write16(value);
    }
    return dataStruct;
}

sp<DataStruct> IccHelper::write_trc_tag(const TransferFunction& fn) {
    if (fn.a == 1.f && fn.b == 0.f && fn.c == 0.f
            && fn.d == 0.f && fn.e == 0.f && fn.f == 0.f) {
        int total_length = 16;
        sp<DataStruct> dataStruct = new DataStruct(total_length);
        dataStruct->write32(Endian_SwapBE32(kTAG_ParaCurveType));  // Type
        dataStruct->write32(0);                                    // Reserved
        dataStruct->write32(Endian_SwapBE16(kExponential_ParaCurveType));
        dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(fn.g)));
        return dataStruct;
    }

    int total_length = 40;
    sp<DataStruct> dataStruct = new DataStruct(total_length);
    dataStruct->write32(Endian_SwapBE32(kTAG_ParaCurveType));  // Type
    dataStruct->write32(0);                                    // Reserved
    dataStruct->write32(Endian_SwapBE16(kGABCDEF_ParaCurveType));
    dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(fn.g)));
    dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(fn.a)));
    dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(fn.b)));
    dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(fn.c)));
    dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(fn.d)));
    dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(fn.e)));
    dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(fn.f)));
    return dataStruct;
}

float IccHelper::compute_tone_map_gain(const ultrahdr_transfer_function tf, float L) {
    if (L <= 0.f) {
        return 1.f;
    }
    if (tf == ULTRAHDR_TF_PQ) {
        // The PQ transfer function will map to the range [0, 1]. Linearly scale
        // it up to the range [0, 10,000/203]. We will then tone map that back
        // down to [0, 1].
        constexpr float kInputMaxLuminance = 10000 / 203.f;
        constexpr float kOutputMaxLuminance = 1.0;
        L *= kInputMaxLuminance;

        // Compute the tone map gain which will tone map from 10,000/203 to 1.0.
        constexpr float kToneMapA = kOutputMaxLuminance / (kInputMaxLuminance * kInputMaxLuminance);
        constexpr float kToneMapB = 1.f / kOutputMaxLuminance;
        return kInputMaxLuminance * (1.f + kToneMapA * L) / (1.f + kToneMapB * L);
    }
    if (tf == ULTRAHDR_TF_HLG) {
        // Let Lw be the brightness of the display in nits.
        constexpr float Lw = 203.f;
        const float gamma = 1.2f + 0.42f * std::log(Lw / 1000.f) / std::log(10.f);
        return std::pow(L, gamma - 1.f);
    }
    return 1.f;
}

sp<DataStruct> IccHelper::write_cicp_tag(uint32_t color_primaries,
                                         uint32_t transfer_characteristics) {
    int total_length = 12;  // 4 + 4 + 1 + 1 + 1 + 1
    sp<DataStruct> dataStruct = sp<DataStruct>::make(total_length);
    dataStruct->write32(Endian_SwapBE32(kTAG_cicp));    // Type signature
    dataStruct->write32(0);                             // Reserved
    dataStruct->write8(color_primaries);                // Color primaries
    dataStruct->write8(transfer_characteristics);       // Transfer characteristics
    dataStruct->write8(0);                              // RGB matrix
    dataStruct->write8(1);                              // Full range
    return dataStruct;
}

void IccHelper::compute_lut_entry(const Matrix3x3& src_to_XYZD50, float rgb[3]) {
    // Compute the matrices to convert from source to Rec2020, and from Rec2020 to XYZD50.
    Matrix3x3 src_to_rec2020;
    const Matrix3x3 rec2020_to_XYZD50 = kRec2020;
    {
        Matrix3x3 XYZD50_to_rec2020;
        Matrix3x3_invert(&rec2020_to_XYZD50, &XYZD50_to_rec2020);
        src_to_rec2020 = Matrix3x3_concat(&XYZD50_to_rec2020, &src_to_XYZD50);
    }

    // Convert the source signal to linear.
    for (size_t i = 0; i < kNumChannels; ++i) {
        rgb[i] = pqOetf(rgb[i]);
    }

    // Convert source gamut to Rec2020.
    Matrix3x3_apply(&src_to_rec2020, rgb);

    // Compute the luminance of the signal.
    float L = bt2100Luminance({{{rgb[0], rgb[1], rgb[2]}}});

    // Compute the tone map gain based on the luminance.
    float tone_map_gain = compute_tone_map_gain(ULTRAHDR_TF_PQ, L);

    // Apply the tone map gain.
    for (size_t i = 0; i < kNumChannels; ++i) {
        rgb[i] *= tone_map_gain;
    }

    // Convert from Rec2020-linear to XYZD50.
    Matrix3x3_apply(&rec2020_to_XYZD50, rgb);
}

sp<DataStruct> IccHelper::write_clut(const uint8_t* grid_points, const uint8_t* grid_16) {
    uint32_t value_count = kNumChannels;
    for (uint32_t i = 0; i < kNumChannels; ++i) {
        value_count *= grid_points[i];
    }

    int total_length = 20 + 2 * value_count;
    total_length = (((total_length + 2) >> 2) << 2);  // 4 aligned
    sp<DataStruct> dataStruct = sp<DataStruct>::make(total_length);

    for (size_t i = 0; i < 16; ++i) {
        dataStruct->write8(i < kNumChannels ? grid_points[i] : 0);  // Grid size
    }
    dataStruct->write8(2);  // Grid byte width (always 16-bit)
    dataStruct->write8(0);  // Reserved
    dataStruct->write8(0);  // Reserved
    dataStruct->write8(0);  // Reserved

    for (uint32_t i = 0; i < value_count; ++i) {
        uint16_t value = reinterpret_cast<const uint16_t*>(grid_16)[i];
        dataStruct->write16(value);
    }

    return dataStruct;
}

sp<DataStruct> IccHelper::write_mAB_or_mBA_tag(uint32_t type,
                                               bool has_a_curves,
                                               const uint8_t* grid_points,
                                               const uint8_t* grid_16) {
    const size_t b_curves_offset = 32;
    sp<DataStruct> b_curves_data[kNumChannels];
    sp<DataStruct> a_curves_data[kNumChannels];
    size_t clut_offset = 0;
    sp<DataStruct> clut;
    size_t a_curves_offset = 0;

    // The "B" curve is required.
    for (size_t i = 0; i < kNumChannels; ++i) {
        b_curves_data[i] = write_trc_tag(kLinear_TransFun);
    }

    // The "A" curve and CLUT are optional.
    if (has_a_curves) {
        clut_offset = b_curves_offset;
        for (size_t i = 0; i < kNumChannels; ++i) {
            clut_offset += b_curves_data[i]->getLength();
        }
        clut = write_clut(grid_points, grid_16);

        a_curves_offset = clut_offset + clut->getLength();
        for (size_t i = 0; i < kNumChannels; ++i) {
            a_curves_data[i] = write_trc_tag(kLinear_TransFun);
        }
    }

    int total_length = b_curves_offset;
    for (size_t i = 0; i < kNumChannels; ++i) {
        total_length += b_curves_data[i]->getLength();
    }
    if (has_a_curves) {
        total_length += clut->getLength();
        for (size_t i = 0; i < kNumChannels; ++i) {
            total_length += a_curves_data[i]->getLength();
        }
    }
    sp<DataStruct> dataStruct = sp<DataStruct>::make(total_length);
    dataStruct->write32(Endian_SwapBE32(type));             // Type signature
    dataStruct->write32(0);                                 // Reserved
    dataStruct->write8(kNumChannels);                       // Input channels
    dataStruct->write8(kNumChannels);                       // Output channels
    dataStruct->write16(0);                                 // Reserved
    dataStruct->write32(Endian_SwapBE32(b_curves_offset));  // B curve offset
    dataStruct->write32(Endian_SwapBE32(0));                // Matrix offset (ignored)
    dataStruct->write32(Endian_SwapBE32(0));                // M curve offset (ignored)
    dataStruct->write32(Endian_SwapBE32(clut_offset));      // CLUT offset
    dataStruct->write32(Endian_SwapBE32(a_curves_offset));  // A curve offset
    for (size_t i = 0; i < kNumChannels; ++i) {
        if (dataStruct->write(b_curves_data[i]->getData(), b_curves_data[i]->getLength())) {
            return dataStruct;
        }
    }
    if (has_a_curves) {
        dataStruct->write(clut->getData(), clut->getLength());
        for (size_t i = 0; i < kNumChannels; ++i) {
            dataStruct->write(a_curves_data[i]->getData(), a_curves_data[i]->getLength());
        }
    }
    return dataStruct;
}

sp<DataStruct> IccHelper::writeIccProfile(ultrahdr_transfer_function tf,
                                          ultrahdr_color_gamut gamut) {
    ICCHeader header;

    std::vector<std::pair<uint32_t, sp<DataStruct>>> tags;

    // Compute profile description tag
    std::string desc = get_desc_string(tf, gamut);

    tags.emplace_back(kTAG_desc, write_text_tag(desc.c_str()));

    Matrix3x3 toXYZD50;
    switch (gamut) {
        case ULTRAHDR_COLORGAMUT_BT709:
            toXYZD50 = kSRGB;
            break;
        case ULTRAHDR_COLORGAMUT_P3:
            toXYZD50 = kDisplayP3;
            break;
        case ULTRAHDR_COLORGAMUT_BT2100:
            toXYZD50 = kRec2020;
            break;
        default:
            // Should not fall here.
            return nullptr;
    }

    // Compute primaries.
    {
        tags.emplace_back(kTAG_rXYZ,
                write_xyz_tag(toXYZD50.vals[0][0], toXYZD50.vals[1][0], toXYZD50.vals[2][0]));
        tags.emplace_back(kTAG_gXYZ,
                write_xyz_tag(toXYZD50.vals[0][1], toXYZD50.vals[1][1], toXYZD50.vals[2][1]));
        tags.emplace_back(kTAG_bXYZ,
                write_xyz_tag(toXYZD50.vals[0][2], toXYZD50.vals[1][2], toXYZD50.vals[2][2]));
    }

    // Compute white point tag (must be D50)
    tags.emplace_back(kTAG_wtpt, write_xyz_tag(kD50_x, kD50_y, kD50_z));

    // Compute transfer curves.
    if (tf != ULTRAHDR_TF_PQ) {
        if (tf == ULTRAHDR_TF_HLG) {
            std::vector<uint8_t> trc_table;
            trc_table.resize(kTrcTableSize * 2);
            for (uint32_t i = 0; i < kTrcTableSize; ++i) {
                float x = i / (kTrcTableSize - 1.f);
                float y = hlgOetf(x);
                y *= compute_tone_map_gain(tf, y);
                float_to_table16(y, &trc_table[2 * i]);
            }

            tags.emplace_back(kTAG_rTRC,
                    write_trc_tag(kTrcTableSize, reinterpret_cast<uint8_t*>(trc_table.data())));
            tags.emplace_back(kTAG_gTRC,
                    write_trc_tag(kTrcTableSize, reinterpret_cast<uint8_t*>(trc_table.data())));
            tags.emplace_back(kTAG_bTRC,
                    write_trc_tag(kTrcTableSize, reinterpret_cast<uint8_t*>(trc_table.data())));
        } else {
            tags.emplace_back(kTAG_rTRC, write_trc_tag(kSRGB_TransFun));
            tags.emplace_back(kTAG_gTRC, write_trc_tag(kSRGB_TransFun));
            tags.emplace_back(kTAG_bTRC, write_trc_tag(kSRGB_TransFun));
        }
    }

    // Compute CICP.
    if (tf == ULTRAHDR_TF_HLG || tf == ULTRAHDR_TF_PQ) {
        // The CICP tag is present in ICC 4.4, so update the header's version.
        header.version = Endian_SwapBE32(0x04400000);

        uint32_t color_primaries = 0;
        if (gamut == ULTRAHDR_COLORGAMUT_BT709) {
            color_primaries = kCICPPrimariesSRGB;
        } else if (gamut == ULTRAHDR_COLORGAMUT_P3) {
            color_primaries = kCICPPrimariesP3;
        }

        uint32_t transfer_characteristics = 0;
        if (tf == ULTRAHDR_TF_SRGB) {
            transfer_characteristics = kCICPTrfnSRGB;
        } else if (tf == ULTRAHDR_TF_LINEAR) {
            transfer_characteristics = kCICPTrfnLinear;
        } else if (tf == ULTRAHDR_TF_PQ) {
            transfer_characteristics = kCICPTrfnPQ;
        } else if (tf == ULTRAHDR_TF_HLG) {
            transfer_characteristics = kCICPTrfnHLG;
        }
        tags.emplace_back(kTAG_cicp, write_cicp_tag(color_primaries, transfer_characteristics));
    }

    // Compute A2B0.
    if (tf == ULTRAHDR_TF_PQ) {
        std::vector<uint8_t> a2b_grid;
        a2b_grid.resize(kGridSize * kGridSize * kGridSize * kNumChannels * 2);
        size_t a2b_grid_index = 0;
        for (uint32_t r_index = 0; r_index < kGridSize; ++r_index) {
            for (uint32_t g_index = 0; g_index < kGridSize; ++g_index) {
                for (uint32_t b_index = 0; b_index < kGridSize; ++b_index) {
                    float rgb[3] = {
                            r_index / (kGridSize - 1.f),
                            g_index / (kGridSize - 1.f),
                            b_index / (kGridSize - 1.f),
                    };
                    compute_lut_entry(toXYZD50, rgb);
                    float_XYZD50_to_grid16_lab(rgb, &a2b_grid[a2b_grid_index]);
                    a2b_grid_index += 6;
                }
            }
        }
        const uint8_t* grid_16 = reinterpret_cast<const uint8_t*>(a2b_grid.data());

        uint8_t grid_points[kNumChannels];
        for (size_t i = 0; i < kNumChannels; ++i) {
            grid_points[i] = kGridSize;
        }

        auto a2b_data = write_mAB_or_mBA_tag(kTAG_mABType,
                                             /* has_a_curves */ true,
                                             grid_points,
                                             grid_16);
        tags.emplace_back(kTAG_A2B0, std::move(a2b_data));
    }

    // Compute B2A0.
    if (tf == ULTRAHDR_TF_PQ) {
        auto b2a_data = write_mAB_or_mBA_tag(kTAG_mBAType,
                                             /* has_a_curves */ false,
                                             /* grid_points */ nullptr,
                                             /* grid_16 */ nullptr);
        tags.emplace_back(kTAG_B2A0, std::move(b2a_data));
    }

    // Compute copyright tag
    tags.emplace_back(kTAG_cprt, write_text_tag("Google Inc. 2022"));

    // Compute the size of the profile.
    size_t tag_data_size = 0;
    for (const auto& tag : tags) {
        tag_data_size += tag.second->getLength();
    }
    size_t tag_table_size = kICCTagTableEntrySize * tags.size();
    size_t profile_size = kICCHeaderSize + tag_table_size + tag_data_size;

    sp<DataStruct> dataStruct = sp<DataStruct>::make(profile_size + kICCIdentifierSize);

    // Write identifier, chunk count, and chunk ID
    if (!dataStruct->write(kICCIdentifier, sizeof(kICCIdentifier)) ||
        !dataStruct->write8(1) || !dataStruct->write8(1)) {
        ALOGE("writeIccProfile(): error in identifier");
        return dataStruct;
    }

    // Write the header.
    header.data_color_space = Endian_SwapBE32(Signature_RGB);
    header.pcs = Endian_SwapBE32(tf == ULTRAHDR_TF_PQ ? Signature_Lab : Signature_XYZ);
    header.size = Endian_SwapBE32(profile_size);
    header.tag_count = Endian_SwapBE32(tags.size());

    if (!dataStruct->write(&header, sizeof(header))) {
        ALOGE("writeIccProfile(): error in header");
        return dataStruct;
    }

    // Write the tag table. Track the offset and size of the previous tag to
    // compute each tag's offset. An empty SkData indicates that the previous
    // tag is to be reused.
    uint32_t last_tag_offset = sizeof(header) + tag_table_size;
    uint32_t last_tag_size = 0;
    for (const auto& tag : tags) {
        last_tag_offset = last_tag_offset + last_tag_size;
        last_tag_size = tag.second->getLength();
        uint32_t tag_table_entry[3] = {
                Endian_SwapBE32(tag.first),
                Endian_SwapBE32(last_tag_offset),
                Endian_SwapBE32(last_tag_size),
        };
        if (!dataStruct->write(tag_table_entry, sizeof(tag_table_entry))) {
            ALOGE("writeIccProfile(): error in writing tag table");
            return dataStruct;
        }
    }

    // Write the tags.
    for (const auto& tag : tags) {
        if (!dataStruct->write(tag.second->getData(), tag.second->getLength())) {
            ALOGE("writeIccProfile(): error in writing tags");
            return dataStruct;
        }
    }

    return dataStruct;
}

bool IccHelper::tagsEqualToMatrix(const Matrix3x3& matrix,
                                  const uint8_t* red_tag,
                                  const uint8_t* green_tag,
                                  const uint8_t* blue_tag) {
    sp<DataStruct> red_tag_test = write_xyz_tag(matrix.vals[0][0], matrix.vals[1][0],
                                                matrix.vals[2][0]);
    sp<DataStruct> green_tag_test = write_xyz_tag(matrix.vals[0][1], matrix.vals[1][1],
                                                  matrix.vals[2][1]);
    sp<DataStruct> blue_tag_test = write_xyz_tag(matrix.vals[0][2], matrix.vals[1][2],
                                                 matrix.vals[2][2]);
    return memcmp(red_tag, red_tag_test->getData(), kColorantTagSize) == 0 &&
           memcmp(green_tag, green_tag_test->getData(), kColorantTagSize) == 0 &&
           memcmp(blue_tag, blue_tag_test->getData(), kColorantTagSize) == 0;
}

ultrahdr_color_gamut IccHelper::readIccColorGamut(void* icc_data, size_t icc_size) {
    // Each tag table entry consists of 3 fields of 4 bytes each.
    static const size_t kTagTableEntrySize = 12;

    if (icc_data == nullptr || icc_size < sizeof(ICCHeader) + kICCIdentifierSize) {
        return ULTRAHDR_COLORGAMUT_UNSPECIFIED;
    }

    if (memcmp(icc_data, kICCIdentifier, sizeof(kICCIdentifier)) != 0) {
        return ULTRAHDR_COLORGAMUT_UNSPECIFIED;
    }

    uint8_t* icc_bytes = reinterpret_cast<uint8_t*>(icc_data) + kICCIdentifierSize;

    ICCHeader* header = reinterpret_cast<ICCHeader*>(icc_bytes);

    // Use 0 to indicate not found, since offsets are always relative to start
    // of ICC data and therefore a tag offset of zero would never be valid.
    size_t red_primary_offset = 0, green_primary_offset = 0, blue_primary_offset = 0;
    size_t red_primary_size = 0, green_primary_size = 0, blue_primary_size = 0;
    for (size_t tag_idx = 0; tag_idx < Endian_SwapBE32(header->tag_count); ++tag_idx) {
        uint32_t* tag_entry_start = reinterpret_cast<uint32_t*>(
            icc_bytes + sizeof(ICCHeader) + tag_idx * kTagTableEntrySize);
        // first 4 bytes are the tag signature, next 4 bytes are the tag offset,
        // last 4 bytes are the tag length in bytes.
        if (red_primary_offset == 0 && *tag_entry_start == Endian_SwapBE32(kTAG_rXYZ)) {
            red_primary_offset = Endian_SwapBE32(*(tag_entry_start+1));
            red_primary_size = Endian_SwapBE32(*(tag_entry_start+2));
        } else if (green_primary_offset == 0 && *tag_entry_start == Endian_SwapBE32(kTAG_gXYZ)) {
            green_primary_offset = Endian_SwapBE32(*(tag_entry_start+1));
            green_primary_size = Endian_SwapBE32(*(tag_entry_start+2));
        } else if (blue_primary_offset == 0 && *tag_entry_start == Endian_SwapBE32(kTAG_bXYZ)) {
            blue_primary_offset = Endian_SwapBE32(*(tag_entry_start+1));
            blue_primary_size = Endian_SwapBE32(*(tag_entry_start+2));
        }
    }

    if (red_primary_offset == 0 || red_primary_size != kColorantTagSize ||
        kICCIdentifierSize + red_primary_offset + red_primary_size > icc_size ||
        green_primary_offset == 0 || green_primary_size != kColorantTagSize ||
        kICCIdentifierSize + green_primary_offset + green_primary_size > icc_size ||
        blue_primary_offset == 0 || blue_primary_size != kColorantTagSize ||
        kICCIdentifierSize + blue_primary_offset + blue_primary_size > icc_size) {
        return ULTRAHDR_COLORGAMUT_UNSPECIFIED;
    }

    uint8_t* red_tag = icc_bytes + red_primary_offset;
    uint8_t* green_tag = icc_bytes + green_primary_offset;
    uint8_t* blue_tag = icc_bytes + blue_primary_offset;

    // Serialize tags as we do on encode and compare what we find to that to
    // determine the gamut (since we don't have a need yet for full deserialize).
    if (tagsEqualToMatrix(kSRGB, red_tag, green_tag, blue_tag)) {
        return ULTRAHDR_COLORGAMUT_BT709;
    } else if (tagsEqualToMatrix(kDisplayP3, red_tag, green_tag, blue_tag)) {
        return ULTRAHDR_COLORGAMUT_P3;
    } else if (tagsEqualToMatrix(kRec2020, red_tag, green_tag, blue_tag)) {
        return ULTRAHDR_COLORGAMUT_BT2100;
    }

    // Didn't find a match to one of the profiles we write; indicate the gamut
    // is unspecified since we don't understand it.
    return ULTRAHDR_COLORGAMUT_UNSPECIFIED;
}

} // namespace android::ultrahdr
