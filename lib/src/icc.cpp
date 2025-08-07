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

#include <cstring>
#include <cmath>

#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/icc.h"

namespace ultrahdr {

std::string IccHelper::get_desc_string(const uhdr_color_transfer_t tf,
                                       const uhdr_color_gamut_t gamut) {
  std::string result;
  switch (gamut) {
    case UHDR_CG_BT_709:
      result += "sRGB";
      break;
    case UHDR_CG_DISPLAY_P3:
      result += "Display P3";
      break;
    case UHDR_CG_BT_2100:
      result += "Rec2020";
      break;
    default:
      result += "Unknown";
      break;
  }
  result += " Gamut with ";
  switch (tf) {
    case UHDR_CT_SRGB:
      result += "sRGB";
      break;
    case UHDR_CT_LINEAR:
      result += "Linear";
      break;
    case UHDR_CT_PQ:
      result += "PQ";
      break;
    case UHDR_CT_HLG:
      result += "HLG";
      break;
    default:
      result += "Unknown";
      break;
  }
  result += " Transfer";
  return result;
}

std::shared_ptr<DataStruct> IccHelper::write_text_tag(const char* text) {
  uint32_t text_length = strlen(text);
  uint32_t header[] = {
      Endian_SwapBE32(kTAG_TextType),                       // Type signature
      0,                                                    // Reserved
      Endian_SwapBE32(1),                                   // Number of records
      Endian_SwapBE32(12),                                  // Record size (must be 12)
      Endian_SwapBE32(SetFourByteTag('e', 'n', 'U', 'S')),  // English USA
      Endian_SwapBE32(2 * text_length),                     // Length of string in bytes
      Endian_SwapBE32(28),                                  // Offset of string
  };

  uint32_t total_length = text_length * 2 + sizeof(header);
  total_length = (((total_length + 2) >> 2) << 2);  // 4 aligned
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);

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

std::shared_ptr<DataStruct> IccHelper::write_xyz_tag(float x, float y, float z) {
  uint32_t data[] = {
      Endian_SwapBE32(kXYZ_PCSSpace),
      0,
      static_cast<uint32_t>(Endian_SwapBE32(float_round_to_fixed(x))),
      static_cast<uint32_t>(Endian_SwapBE32(float_round_to_fixed(y))),
      static_cast<uint32_t>(Endian_SwapBE32(float_round_to_fixed(z))),
  };
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(sizeof(data));
  dataStruct->write(&data, sizeof(data));
  return dataStruct;
}

std::shared_ptr<DataStruct> IccHelper::write_trc_tag(const int table_entries,
                                                     const void* table_16) {
  int total_length = 4 + 4 + 4 + table_entries * 2;
  total_length = (((total_length + 2) >> 2) << 2);  // 4 aligned
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);
  dataStruct->write32(Endian_SwapBE32(kTAG_CurveType));  // Type
  dataStruct->write32(0);                                // Reserved
  dataStruct->write32(Endian_SwapBE32(table_entries));   // Value count
  for (int i = 0; i < table_entries; ++i) {
    uint16_t value = reinterpret_cast<const uint16_t*>(table_16)[i];
    dataStruct->write16(value);
  }
  return dataStruct;
}

std::shared_ptr<DataStruct> IccHelper::write_trc_tag(const TransferFunction& fn) {
  if (fn.a == 1.f && fn.b == 0.f && fn.c == 0.f && fn.d == 0.f && fn.e == 0.f && fn.f == 0.f) {
    int total_length = 16;
    std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);
    dataStruct->write32(Endian_SwapBE32(kTAG_ParaCurveType));  // Type
    dataStruct->write32(0);                                    // Reserved
    dataStruct->write32(Endian_SwapBE16(kExponential_ParaCurveType));
    dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(fn.g)));
    return dataStruct;
  }

  int total_length = 40;
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);
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

std::shared_ptr<DataStruct> IccHelper::write_cicp_tag(uint32_t color_primaries,
                                                      uint32_t transfer_characteristics) {
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(kCicpTagSize);
  dataStruct->write32(Endian_SwapBE32(kTAG_cicp));  // Type signature
  dataStruct->write32(0);                           // Reserved
  dataStruct->write8(color_primaries);              // Color primaries
  dataStruct->write8(transfer_characteristics);     // Transfer characteristics
  dataStruct->write8(0);                            // RGB matrix
  dataStruct->write8(1);                            // Full range
  return dataStruct;
}

std::shared_ptr<DataStruct> IccHelper::write_chad_tag() {
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(44);
  dataStruct->write32(Endian_SwapBE32(kTAG_s15Fixed16ArrayType));  // Type signature
  dataStruct->write32(0);                                          // Reserved
  for (int i = 0; i < 3; ++i) {
    for (int j = 0; j < 3; ++j) {
      dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(adaptation_matrix.vals[i][j])));
    }
  }
  return dataStruct;
}

void IccHelper::compute_lut_entry(uhdr_color_transfer_t tf, uhdr_color_gamut_t cg, float rgb[3]) {
  Color hdr_rgb = {{{rgb[0], rgb[1], rgb[2]}}};
  float headroom = 1.0f;
  if (tf == UHDR_CT_HLG) {
    hdr_rgb = hlgInvOetf(hdr_rgb);
    LuminanceFn hdrLuminanceFn = getLuminanceFn(cg);
    hdr_rgb = hlgOotf(hdr_rgb, hdrLuminanceFn);
    headroom = kHlgMaxNits / kSdrWhiteNits;
  } else if (tf == UHDR_CT_PQ) {
    hdr_rgb = pqInvOetf(hdr_rgb);
    headroom = kPqMaxNits / kSdrWhiteNits;
  }
  GlobalTonemapOutputs tonemapped =
      globalTonemap({hdr_rgb.r, hdr_rgb.g, hdr_rgb.b}, headroom, false);
  rgb[0] = tonemapped.rgb_out[0];
  rgb[1] = tonemapped.rgb_out[1];
  rgb[2] = tonemapped.rgb_out[2];
}

std::shared_ptr<DataStruct> IccHelper::write_clut(const uint8_t* grid_points,
                                                  const uint8_t* grid_16) {
  uint32_t value_count = kNumChannels;
  for (uint32_t i = 0; i < kNumChannels; ++i) {
    value_count *= grid_points[i];
  }

  int total_length = 20 + 2 * value_count;
  total_length = (((total_length + 2) >> 2) << 2);  // 4 aligned
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);

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

std::shared_ptr<DataStruct> IccHelper::write_matrix(const Matrix3x3* matrix) {
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(12 * 4);
  // See layout details in section "10.12.5 Matrix".
  for (int i = 0; i < 3; ++i) {
    for (int j = 0; j < 3; ++j) {
      dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(matrix->vals[i][j])));
    }
  }
  for (int i = 0; i < 3; ++i) {
    dataStruct->write32(Endian_SwapBE32(float_round_to_fixed(0.f)));
  }
  return dataStruct;
}

std::shared_ptr<DataStruct> IccHelper::write_mAB_or_mBA_tag(uint32_t type, bool has_a_curves,
                                                            const uint8_t* grid_points,
                                                            const uint8_t* grid_16,
                                                            bool has_m_curves,
                                                            Matrix3x3* toXYZD50) {
  size_t offset = 32;

  // The "B" curve is required.
  size_t b_curves_offset = offset;
  std::shared_ptr<DataStruct> b_curves_data[kNumChannels];
  for (size_t i = 0; i < kNumChannels; ++i) {
    b_curves_data[i] = write_trc_tag(kLinear_TransFun);
    offset += b_curves_data[i]->getLength();
  }

  // The CLUT.
  size_t clut_offset = 0;
  std::shared_ptr<DataStruct> clut;
  if (grid_points) {
    clut_offset = offset;
    clut = write_clut(grid_points, grid_16);
    offset += clut->getLength();
  }

  // The A curves.
  size_t a_curves_offset = 0;
  std::shared_ptr<DataStruct> a_curves_data[kNumChannels];
  if (has_a_curves) {
    a_curves_offset = offset;
    for (size_t i = 0; i < kNumChannels; ++i) {
      a_curves_data[i] = write_trc_tag(kLinear_TransFun);
      offset += a_curves_data[i]->getLength();
    }
  }

  // The matrix.
  size_t matrix_offset = 0;
  std::shared_ptr<DataStruct> matrix_data;
  if (toXYZD50) {
    matrix_offset = offset;
    matrix_data = write_matrix(toXYZD50);
    offset += matrix_data->getLength();
  }

  // The "M" curves.
  size_t m_curves_offset = 0;
  std::shared_ptr<DataStruct> m_curves_data[kNumChannels];
  if (has_m_curves) {
    m_curves_offset = offset;
    for (size_t i = 0; i < kNumChannels; ++i) {
      m_curves_data[i] = write_trc_tag(kLinear_TransFun);
      offset += m_curves_data[i]->getLength();
    }
  }

  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(offset);
  dataStruct->write32(Endian_SwapBE32(type));             // Type signature
  dataStruct->write32(0);                                 // Reserved
  dataStruct->write8(kNumChannels);                       // Input channels
  dataStruct->write8(kNumChannels);                       // Output channels
  dataStruct->write16(0);                                 // Reserved
  dataStruct->write32(Endian_SwapBE32(b_curves_offset));  // B curve offset
  dataStruct->write32(Endian_SwapBE32(matrix_offset));    // Matrix offset
  dataStruct->write32(Endian_SwapBE32(m_curves_offset));  // M curve offset
  dataStruct->write32(Endian_SwapBE32(clut_offset));      // CLUT offset
  dataStruct->write32(Endian_SwapBE32(a_curves_offset));  // A curve offset
  for (size_t i = 0; i < kNumChannels; ++i) {
    dataStruct->write(b_curves_data[i]->getData(), b_curves_data[i]->getLength());
  }
  if (clut) {
    dataStruct->write(clut->getData(), clut->getLength());
  }
  if (has_a_curves) {
    for (size_t i = 0; i < kNumChannels; ++i) {
      dataStruct->write(a_curves_data[i]->getData(), a_curves_data[i]->getLength());
    }
  }
  if (toXYZD50) {
    dataStruct->write(matrix_data->getData(), matrix_data->getLength());
  }
  if (has_m_curves) {
    for (size_t i = 0; i < kNumChannels; ++i) {
      dataStruct->write(m_curves_data[i]->getData(), m_curves_data[i]->getLength());
    }
  }
  return dataStruct;
}

std::shared_ptr<DataStruct> IccHelper::writeIccProfile(uhdr_color_transfer_t tf,
                                                       uhdr_color_gamut_t gamut,
                                                       bool write_tonemap_icc) {
  ICCHeader header;

  std::vector<std::pair<uint32_t, std::shared_ptr<DataStruct>>> tags;

  // Compute profile description tag
  std::string desc = get_desc_string(tf, gamut);
  tags.emplace_back(kTAG_desc, write_text_tag(desc.c_str()));

  // Compute primaries.
  Matrix3x3 toXYZD50;
  switch (gamut) {
    case UHDR_CG_BT_709:
      toXYZD50 = kSRGB;
      break;
    case UHDR_CG_DISPLAY_P3:
      toXYZD50 = kDisplayP3;
      break;
    case UHDR_CG_BT_2100:
      toXYZD50 = kRec2020;
      break;
    default:
      // Should not fall here.
      return nullptr;
  }
  tags.emplace_back(kTAG_rXYZ,
                    write_xyz_tag(toXYZD50.vals[0][0], toXYZD50.vals[1][0], toXYZD50.vals[2][0]));
  tags.emplace_back(kTAG_gXYZ,
                    write_xyz_tag(toXYZD50.vals[0][1], toXYZD50.vals[1][1], toXYZD50.vals[2][1]));
  tags.emplace_back(kTAG_bXYZ,
                    write_xyz_tag(toXYZD50.vals[0][2], toXYZD50.vals[1][2], toXYZD50.vals[2][2]));

  // Compute white point tag (must be D50)
  tags.emplace_back(kTAG_wtpt, write_xyz_tag(kD50_x, kD50_y, kD50_z));

  // Compute transfer curves.
  if (tf == UHDR_CT_SRGB) {
    tags.emplace_back(kTAG_rTRC, write_trc_tag(kSRGB_TransFun));
    // Use empty data to indicate that the entry should use the previous tag's
    // data.
    tags.emplace_back(kTAG_gTRC, make_empty());
    // Use empty data to indicate that the entry should use the previous tag's
    // data.
    tags.emplace_back(kTAG_bTRC, make_empty());
  }

  // Chroma adaptation matrix
  tags.emplace_back(kTAG_chad, write_chad_tag());

  // Compute CICP - for hdr images icc profile shall contain cicp.
  if (tf == UHDR_CT_HLG || tf == UHDR_CT_PQ || tf == UHDR_CT_LINEAR) {
    // The CICP tag is present in ICC 4.4, so update the header's version.
    header.version = Endian_SwapBE32(0x04400000);

    uint32_t color_primaries = kCICPPrimariesUnSpecified;
    if (gamut == UHDR_CG_BT_709) {
      color_primaries = kCICPPrimariesSRGB;
    } else if (gamut == UHDR_CG_DISPLAY_P3) {
      color_primaries = kCICPPrimariesP3;
    } else if (gamut == UHDR_CG_BT_2100) {
      color_primaries = kCICPPrimariesRec2020;
    }

    uint32_t transfer_characteristics = kCICPTrfnUnSpecified;
    if (tf == UHDR_CT_SRGB) {
      transfer_characteristics = kCICPTrfnSRGB;
    } else if (tf == UHDR_CT_LINEAR) {
      transfer_characteristics = kCICPTrfnLinear;
    } else if (tf == UHDR_CT_PQ) {
      transfer_characteristics = kCICPTrfnPQ;
    } else if (tf == UHDR_CT_HLG) {
      transfer_characteristics = kCICPTrfnHLG;
    }
    tags.emplace_back(kTAG_cicp, write_cicp_tag(color_primaries, transfer_characteristics));
  }

  // Compute A2B, B2A (PQ and HLG only).
  if (write_tonemap_icc && (tf == UHDR_CT_PQ || tf == UHDR_CT_HLG)) {
    // The uInt16Number used to encoude XYZ values has 1.0 map to 0x8000.
    // See section "6.3.4.2 General PCS encoding" and Table 11.
    constexpr uint16_t kOne16XYZ = 0x8000;

    std::vector<uint16_t> a2b_grid;
    a2b_grid.resize(kGridSize * kGridSize * kGridSize * kNumChannels);
    size_t a2b_grid_index = 0;
    for (uint32_t r_index = 0; r_index < kGridSize; ++r_index) {
      for (uint32_t g_index = 0; g_index < kGridSize; ++g_index) {
        for (uint32_t b_index = 0; b_index < kGridSize; ++b_index) {
          float rgb[3] = {
              r_index / (kGridSize - 1.f),
              g_index / (kGridSize - 1.f),
              b_index / (kGridSize - 1.f),
          };
          compute_lut_entry(tf, gamut, rgb);
          // Write the result to the LUT.
          for (const auto& c : rgb) {
            a2b_grid[a2b_grid_index++] = Endian_SwapBE16(float_to_uInt16Number(c, kOne16XYZ));
          }
        }
      }
    }
    const uint8_t* grid_16 = reinterpret_cast<const uint8_t*>(a2b_grid.data());

    uint8_t grid_points[kNumChannels];
    for (size_t i = 0; i < kNumChannels; ++i) {
      grid_points[i] = kGridSize;
    }

    auto a2b_data = write_mAB_or_mBA_tag(kTAG_mABType, true, grid_points, grid_16, true, &toXYZD50);
    tags.emplace_back(kTAG_A2B0, std::move(a2b_data));

    auto b2a_data = write_mAB_or_mBA_tag(kTAG_mBAType, false, nullptr, nullptr, false, nullptr);
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

  std::shared_ptr<DataStruct> dataStruct =
      std::make_shared<DataStruct>(profile_size + kICCIdentifierSize);

  // Write identifier, chunk count, and chunk ID
  if (!dataStruct->write(kICCIdentifier, sizeof(kICCIdentifier)) || !dataStruct->write8(1) ||
      !dataStruct->write8(1)) {
    ALOGE("writeIccProfile(): error in identifier");
    return dataStruct;
  }

  // Write the header.
  header.data_color_space = Endian_SwapBE32(Signature_RGB);
  header.pcs = Endian_SwapBE32(tf == UHDR_CT_PQ ? Signature_Lab : Signature_XYZ);
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
    if (tag.second->getLength()) {
      last_tag_offset = last_tag_offset + last_tag_size;
      last_tag_size = tag.second->getLength();
    }
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

bool IccHelper::tagsEqualToMatrix(const Matrix3x3& matrix, const uint8_t* red_tag,
                                  const uint8_t* green_tag, const uint8_t* blue_tag) {
  const float tolerance = 0.001f;
  Fixed r_x_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(red_tag))[2]);
  Fixed r_y_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(red_tag))[3]);
  Fixed r_z_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(red_tag))[4]);
  float r_x = FixedToFloat(r_x_fixed);
  float r_y = FixedToFloat(r_y_fixed);
  float r_z = FixedToFloat(r_z_fixed);
  if (fabs(r_x - matrix.vals[0][0]) > tolerance || fabs(r_y - matrix.vals[1][0]) > tolerance ||
      fabs(r_z - matrix.vals[2][0]) > tolerance) {
    return false;
  }

  Fixed g_x_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(green_tag))[2]);
  Fixed g_y_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(green_tag))[3]);
  Fixed g_z_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(green_tag))[4]);
  float g_x = FixedToFloat(g_x_fixed);
  float g_y = FixedToFloat(g_y_fixed);
  float g_z = FixedToFloat(g_z_fixed);
  if (fabs(g_x - matrix.vals[0][1]) > tolerance || fabs(g_y - matrix.vals[1][1]) > tolerance ||
      fabs(g_z - matrix.vals[2][1]) > tolerance) {
    return false;
  }

  Fixed b_x_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(blue_tag))[2]);
  Fixed b_y_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(blue_tag))[3]);
  Fixed b_z_fixed = Endian_SwapBE32(reinterpret_cast<int32_t*>(const_cast<uint8_t*>(blue_tag))[4]);
  float b_x = FixedToFloat(b_x_fixed);
  float b_y = FixedToFloat(b_y_fixed);
  float b_z = FixedToFloat(b_z_fixed);
  if (fabs(b_x - matrix.vals[0][2]) > tolerance || fabs(b_y - matrix.vals[1][2]) > tolerance ||
      fabs(b_z - matrix.vals[2][2]) > tolerance) {
    return false;
  }

  return true;
}

uhdr_color_gamut_t IccHelper::readIccColorGamut(void* icc_data, size_t icc_size) {
  // Each tag table entry consists of 3 fields of 4 bytes each.
  static const size_t kTagTableEntrySize = 12;

  if (icc_data == nullptr || icc_size < sizeof(ICCHeader) + kICCIdentifierSize) {
    return UHDR_CG_UNSPECIFIED;
  }

  if (memcmp(icc_data, kICCIdentifier, sizeof(kICCIdentifier)) != 0) {
    return UHDR_CG_UNSPECIFIED;
  }

  uint8_t* icc_bytes = reinterpret_cast<uint8_t*>(icc_data) + kICCIdentifierSize;
  auto alignment_needs = alignof(ICCHeader);
  uint8_t* aligned_block = nullptr;
  if (((uintptr_t)icc_bytes) % alignment_needs != 0) {
    aligned_block = static_cast<uint8_t*>(
        ::operator new[](icc_size - kICCIdentifierSize, std::align_val_t(alignment_needs)));
    if (!aligned_block) {
      ALOGE("unable allocate memory, icc parsing failed");
      return UHDR_CG_UNSPECIFIED;
    }
    std::memcpy(aligned_block, icc_bytes, icc_size - kICCIdentifierSize);
    icc_bytes = aligned_block;
  }
  ICCHeader* header = reinterpret_cast<ICCHeader*>(icc_bytes);

  // Use 0 to indicate not found, since offsets are always relative to start
  // of ICC data and therefore a tag offset of zero would never be valid.
  size_t red_primary_offset = 0, green_primary_offset = 0, blue_primary_offset = 0;
  size_t red_primary_size = 0, green_primary_size = 0, blue_primary_size = 0;
  size_t cicp_size = 0, cicp_offset = 0;
  for (size_t tag_idx = 0; tag_idx < Endian_SwapBE32(header->tag_count); ++tag_idx) {
    if (icc_size < kICCIdentifierSize + sizeof(ICCHeader) + ((tag_idx + 1) * kTagTableEntrySize)) {
      ALOGE(
          "Insufficient buffer size during icc parsing. tag index %zu, header %zu, tag size %zu, "
          "icc size %zu",
          tag_idx, kICCIdentifierSize + sizeof(ICCHeader), kTagTableEntrySize, icc_size);
      if (aligned_block) ::operator delete[](aligned_block, std::align_val_t(alignment_needs));
      return UHDR_CG_UNSPECIFIED;
    }
    uint32_t* tag_entry_start =
        reinterpret_cast<uint32_t*>(icc_bytes + sizeof(ICCHeader) + tag_idx * kTagTableEntrySize);
    // first 4 bytes are the tag signature, next 4 bytes are the tag offset,
    // last 4 bytes are the tag length in bytes.
    if (red_primary_offset == 0 && *tag_entry_start == Endian_SwapBE32(kTAG_rXYZ)) {
      red_primary_offset = Endian_SwapBE32(*(tag_entry_start + 1));
      red_primary_size = Endian_SwapBE32(*(tag_entry_start + 2));
    } else if (green_primary_offset == 0 && *tag_entry_start == Endian_SwapBE32(kTAG_gXYZ)) {
      green_primary_offset = Endian_SwapBE32(*(tag_entry_start + 1));
      green_primary_size = Endian_SwapBE32(*(tag_entry_start + 2));
    } else if (blue_primary_offset == 0 && *tag_entry_start == Endian_SwapBE32(kTAG_bXYZ)) {
      blue_primary_offset = Endian_SwapBE32(*(tag_entry_start + 1));
      blue_primary_size = Endian_SwapBE32(*(tag_entry_start + 2));
    } else if (cicp_offset == 0 && *tag_entry_start == Endian_SwapBE32(kTAG_cicp)) {
      cicp_offset = Endian_SwapBE32(*(tag_entry_start + 1));
      cicp_size = Endian_SwapBE32(*(tag_entry_start + 2));
    }
  }

  if (cicp_offset != 0 && cicp_size == kCicpTagSize &&
      kICCIdentifierSize + cicp_offset + cicp_size <= icc_size) {
    uint8_t* cicp = icc_bytes + cicp_offset;
    uint8_t primaries = cicp[8];
    uhdr_color_gamut_t gamut = UHDR_CG_UNSPECIFIED;
    if (primaries == kCICPPrimariesSRGB) {
      gamut = UHDR_CG_BT_709;
    } else if (primaries == kCICPPrimariesP3) {
      gamut = UHDR_CG_DISPLAY_P3;
    } else if (primaries == kCICPPrimariesRec2020) {
      gamut = UHDR_CG_BT_2100;
    }
    if (gamut != UHDR_CG_UNSPECIFIED) {
      if (aligned_block) ::operator delete[](aligned_block, std::align_val_t(alignment_needs));
      return gamut;
    }
  }

  if (red_primary_offset == 0 || red_primary_size != kColorantTagSize ||
      kICCIdentifierSize + red_primary_offset + red_primary_size > icc_size ||
      green_primary_offset == 0 || green_primary_size != kColorantTagSize ||
      kICCIdentifierSize + green_primary_offset + green_primary_size > icc_size ||
      blue_primary_offset == 0 || blue_primary_size != kColorantTagSize ||
      kICCIdentifierSize + blue_primary_offset + blue_primary_size > icc_size) {
    if (aligned_block) ::operator delete[](aligned_block, std::align_val_t(alignment_needs));
    return UHDR_CG_UNSPECIFIED;
  }

  uint8_t* red_tag = icc_bytes + red_primary_offset;
  uint8_t* green_tag = icc_bytes + green_primary_offset;
  uint8_t* blue_tag = icc_bytes + blue_primary_offset;

  // Serialize tags as we do on encode and compare what we find to that to
  // determine the gamut (since we don't have a need yet for full deserialize).
  uhdr_color_gamut_t gamut = UHDR_CG_UNSPECIFIED;
  if (tagsEqualToMatrix(kSRGB, red_tag, green_tag, blue_tag)) {
    gamut = UHDR_CG_BT_709;
  } else if (tagsEqualToMatrix(kDisplayP3, red_tag, green_tag, blue_tag)) {
    gamut = UHDR_CG_DISPLAY_P3;
  } else if (tagsEqualToMatrix(kRec2020, red_tag, green_tag, blue_tag)) {
    gamut = UHDR_CG_BT_2100;
  }

  if (aligned_block) ::operator delete[](aligned_block, std::align_val_t(alignment_needs));
  // Didn't find a match to one of the profiles we write; indicate the gamut
  // is unspecified since we don't understand it.
  return gamut;
}

}  // namespace ultrahdr
