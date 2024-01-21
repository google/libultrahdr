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

#include <cstddef>
#include <cstring>

#include "ultrahdr/ultrahdr_api.h"
#include "ultrahdr/jpegr.h"
#include "ultrahdr/jpegrutils.h"

class ultrahdr_mem_context {
 public:
  ultrahdr_mem_context() = default;
  ~ultrahdr_mem_context() { mem_records.clear(); }

  std::vector<std::vector<uint8_t>> mem_records;
};

status_t ultrahdr_compress_api0(ultrahdr_uncompressed_ptr p010_image_ptr,
                                ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest,
                                int quality, ultrahdr_exif_ptr exif) {
  ultrahdr::JpegR jpegHdr;
  return jpegHdr.encodeJPEGR(p010_image_ptr, hdr_tf, dest, quality, exif);
}

status_t ultrahdr_compress_api1(ultrahdr_uncompressed_ptr p010_image_ptr,
                                ultrahdr_uncompressed_ptr yuv420_image_ptr,
                                ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest,
                                int quality, ultrahdr_exif_ptr exif) {
  ultrahdr::JpegR jpegHdr;
  return jpegHdr.encodeJPEGR(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest, quality, exif);
}

status_t ultrahdr_compress_api2(ultrahdr_uncompressed_ptr p010_image_ptr,
                                ultrahdr_uncompressed_ptr yuv420_image_ptr,
                                ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                                ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest) {
  ultrahdr::JpegR jpegHdr;
  return jpegHdr.encodeJPEGR(p010_image_ptr, yuv420_image_ptr, yuv420jpg_image_ptr, hdr_tf, dest);
}

status_t ultrahdr_compress_api3(ultrahdr_uncompressed_ptr p010_image_ptr,
                                ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                                ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest) {
  ultrahdr::JpegR jpegHdr;
  return jpegHdr.encodeJPEGR(p010_image_ptr, yuv420jpg_image_ptr, hdr_tf, dest);
}

status_t ultrahdr_compress_api4(ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                                ultrahdr_compressed_ptr gainmapjpg_image_ptr,
                                ultrahdr_metadata_ptr metadata, ultrahdr_compressed_ptr dest) {
  ultrahdr::JpegR jpegHdr;
  return jpegHdr.encodeJPEGR(yuv420jpg_image_ptr, gainmapjpg_image_ptr, metadata, dest);
}

status_t get_image_dimensions(ultrahdr_compressed_ptr ultrahdr_image_ptr, size_t *width,
                              size_t *height) {
  if (width == nullptr || height == nullptr) return ERROR_UHDR_BAD_PTR;
  ultrahdr::JpegR jpegHdr;
  ultrahdr::jpegr_info_struct jpegrInfo{};
  ULTRAHDR_CHECK(jpegHdr.getJPEGRInfo(ultrahdr_image_ptr, &jpegrInfo));
  *width = jpegrInfo.width;
  *height = jpegrInfo.height;

  return UHDR_NO_ERROR;
}

status_t get_gainmap_image_dimensions(ultrahdr_compressed_ptr ultrahdr_image_ptr, size_t *width,
                                      size_t *height) {
  if (width == nullptr || height == nullptr) return ERROR_UHDR_BAD_PTR;
  ultrahdr::JpegR jpegHdr;
  ultrahdr::jpeg_info_struct gainmapImage;
  ultrahdr::jpegr_info_struct jpegrInfo;
  jpegrInfo.width = 0;
  jpegrInfo.height = 0;
  jpegrInfo.primaryImgInfo = nullptr;
  jpegrInfo.gainmapImgInfo = &gainmapImage;
  ULTRAHDR_CHECK(jpegHdr.getJPEGRInfo(ultrahdr_image_ptr, &jpegrInfo));
  *width = gainmapImage.width;
  *height = gainmapImage.height;

  return UHDR_NO_ERROR;
}

void *ultrahdr_create_memctxt(void) { return new ultrahdr_mem_context; }

void ultrahdr_destroy_memctxt(void *ctxt) {
  if (ctxt) {
    auto dec_ctxt = static_cast<ultrahdr_mem_context *>(ctxt);
    dec_ctxt->mem_records.clear();
    delete dec_ctxt;
  }
}

status_t get_ultrahdr_info(void *ctxt, ultrahdr_compressed_ptr ultrahdr_image_ptr,
                           ultrahdr_attributes_ptr ultrahdr_image_info_ptr) {
  if (!ctxt || !ultrahdr_image_info_ptr) return ERROR_UHDR_BAD_PTR;
  ultrahdr::JpegR jpegHdr;
  ultrahdr::jpeg_info_struct primaryImage, gainmapImage;
  ultrahdr::jpegr_info_struct jpegrInfo;
  jpegrInfo.width = 0;
  jpegrInfo.height = 0;
  jpegrInfo.primaryImgInfo = &primaryImage;
  jpegrInfo.gainmapImgInfo = &gainmapImage;
  ULTRAHDR_CHECK(jpegHdr.getJPEGRInfo(ultrahdr_image_ptr, &jpegrInfo));

  memset(ultrahdr_image_info_ptr, 0, sizeof(*ultrahdr_image_info_ptr));
  auto dec_ctxt = static_cast<ultrahdr_mem_context *>(ctxt);
  auto curr_idx = dec_ctxt->mem_records.size();

#define FILL_STRUCT(source, mov_loc, idx, dest) \
  if ((source).size() != 0) {                   \
    mov_loc.push_back(std::move((source)));     \
    dest.data = (mov_loc)[idx].data();          \
    dest.length = (mov_loc)[idx].size();        \
    idx++;                                      \
  } else {                                      \
    dest.data = nullptr;                        \
    dest.length = 0;                            \
  }

  ultrahdr_image_info_ptr->primaryImage.width = primaryImage.width;
  ultrahdr_image_info_ptr->primaryImage.height = primaryImage.height;
  FILL_STRUCT(primaryImage.imgData, dec_ctxt->mem_records, curr_idx,
              ultrahdr_image_info_ptr->primaryImage.imgData);
  FILL_STRUCT(primaryImage.iccData, dec_ctxt->mem_records, curr_idx,
              ultrahdr_image_info_ptr->primaryImage.iccData);
  FILL_STRUCT(primaryImage.exifData, dec_ctxt->mem_records, curr_idx,
              ultrahdr_image_info_ptr->primaryImage.exifData);
  FILL_STRUCT(primaryImage.xmpData, dec_ctxt->mem_records, curr_idx,
              ultrahdr_image_info_ptr->primaryImage.xmpData);

  ultrahdr_image_info_ptr->gainmapImage.width = gainmapImage.width;
  ultrahdr_image_info_ptr->gainmapImage.height = gainmapImage.height;
  FILL_STRUCT(gainmapImage.imgData, dec_ctxt->mem_records, curr_idx,
              ultrahdr_image_info_ptr->gainmapImage.imgData);
  FILL_STRUCT(gainmapImage.iccData, dec_ctxt->mem_records, curr_idx,
              ultrahdr_image_info_ptr->gainmapImage.iccData);
  FILL_STRUCT(gainmapImage.exifData, dec_ctxt->mem_records, curr_idx,
              ultrahdr_image_info_ptr->gainmapImage.exifData);
  FILL_STRUCT(gainmapImage.xmpData, dec_ctxt->mem_records, curr_idx,
              ultrahdr_image_info_ptr->gainmapImage.xmpData);

  return UHDR_NO_ERROR;
}

int is_valid_ultrahdr_image(ultrahdr_compressed_ptr ultrahdr_image_ptr) {
  void *ctxt = ultrahdr_create_memctxt();
  ultrahdr_attributes_struct ultrahdr_info_struct;
  auto status = get_ultrahdr_info(ctxt, ultrahdr_image_ptr, &ultrahdr_info_struct);
  int isValid = 0;
  if (status == UHDR_NO_ERROR) {
    ultrahdr_metadata_struct metadata;
    isValid = ultrahdr::getMetadataFromXMP(
        static_cast<uint8_t *>(ultrahdr_info_struct.gainmapImage.xmpData.data),
        ultrahdr_info_struct.gainmapImage.xmpData.length, &metadata);
  }
  ultrahdr_destroy_memctxt(ctxt);
  return isValid;
}

status_t ultrahdr_decompress(ultrahdr_compressed_ptr ultrahdr_image_ptr,
                             ultrahdr_uncompressed_ptr dest, float max_display_boost,
                             ultrahdr_output_format output_format, ultrahdr_metadata_ptr metadata) {
  ultrahdr::JpegR jpegHdr;
  return jpegHdr.decodeJPEGR(ultrahdr_image_ptr, dest, max_display_boost, nullptr, output_format,
                             nullptr, metadata);
}
