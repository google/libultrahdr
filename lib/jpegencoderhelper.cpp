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
#include <memory>
#include <string>

#include "ultrahdrcommon.h"
#include "ultrahdr.h"
#include "jpegencoderhelper.h"

namespace ultrahdr {

// The destination manager that can access |mResultBuffer| in JpegEncoderHelper.
struct destination_mgr {
    struct jpeg_destination_mgr mgr;
    JpegEncoderHelper* encoder;
};

JpegEncoderHelper::JpegEncoderHelper() {}

JpegEncoderHelper::~JpegEncoderHelper() {}

bool JpegEncoderHelper::compressImage(const uint8_t* yBuffer, const uint8_t* uvBuffer, int width,
                                      int height, int lumaStride, int chromaStride, int quality,
                                      const void* iccBuffer, unsigned int iccSize) {
    mResultBuffer.clear();
    if (!encode(yBuffer, uvBuffer, width, height, lumaStride, chromaStride, quality, iccBuffer,
                iccSize)) {
        return false;
    }
    ALOGV("Compressed JPEG: %d[%dx%d] -> %zu bytes", (width * height * 12) / 8, width, height,
          mResultBuffer.size());
    return true;
}

void* JpegEncoderHelper::getCompressedImagePtr() {
    return mResultBuffer.data();
}

size_t JpegEncoderHelper::getCompressedImageSize() {
    return mResultBuffer.size();
}

void JpegEncoderHelper::initDestination(j_compress_ptr cinfo) {
    destination_mgr* dest = reinterpret_cast<destination_mgr*>(cinfo->dest);
    std::vector<JOCTET>& buffer = dest->encoder->mResultBuffer;
    buffer.resize(kBlockSize);
    dest->mgr.next_output_byte = &buffer[0];
    dest->mgr.free_in_buffer = buffer.size();
}

boolean JpegEncoderHelper::emptyOutputBuffer(j_compress_ptr cinfo) {
    destination_mgr* dest = reinterpret_cast<destination_mgr*>(cinfo->dest);
    std::vector<JOCTET>& buffer = dest->encoder->mResultBuffer;
    size_t oldsize = buffer.size();
    buffer.resize(oldsize + kBlockSize);
    dest->mgr.next_output_byte = &buffer[oldsize];
    dest->mgr.free_in_buffer = kBlockSize;
    return true;
}

void JpegEncoderHelper::terminateDestination(j_compress_ptr cinfo) {
    destination_mgr* dest = reinterpret_cast<destination_mgr*>(cinfo->dest);
    std::vector<JOCTET>& buffer = dest->encoder->mResultBuffer;
    buffer.resize(buffer.size() - dest->mgr.free_in_buffer);
}

void JpegEncoderHelper::outputErrorMessage(j_common_ptr cinfo) {
    char buffer[JMSG_LENGTH_MAX];

    /* Create the message */
    (*cinfo->err->format_message)(cinfo, buffer);
    ALOGE("%s\n", buffer);
}

bool JpegEncoderHelper::encode(const uint8_t* yBuffer, const uint8_t* uvBuffer, int width,
                               int height, int lumaStride, int chromaStride, int quality,
                               const void* iccBuffer, unsigned int iccSize) {
    jpeg_compress_struct cinfo;
    jpeg_error_mgr jerr;

    cinfo.err = jpeg_std_error(&jerr);
    cinfo.err->output_message = &outputErrorMessage;
    jpeg_create_compress(&cinfo);
    setJpegDestination(&cinfo);
    setJpegCompressStruct(width, height, quality, &cinfo, uvBuffer == nullptr);
    jpeg_start_compress(&cinfo, TRUE);
    if (iccBuffer != nullptr && iccSize > 0) {
        jpeg_write_marker(&cinfo, JPEG_APP0 + 2, static_cast<const JOCTET*>(iccBuffer), iccSize);
    }
    bool status = cinfo.num_components == 1
            ? compressY(&cinfo, yBuffer, lumaStride)
            : compressYuv(&cinfo, yBuffer, uvBuffer, lumaStride, chromaStride);
    jpeg_finish_compress(&cinfo);
    jpeg_destroy_compress(&cinfo);

    return status;
}

void JpegEncoderHelper::setJpegDestination(jpeg_compress_struct* cinfo) {
    destination_mgr* dest = static_cast<struct destination_mgr*>(
            (*cinfo->mem->alloc_small)((j_common_ptr)cinfo, JPOOL_PERMANENT,
                                       sizeof(destination_mgr)));
    dest->encoder = this;
    dest->mgr.init_destination = &initDestination;
    dest->mgr.empty_output_buffer = &emptyOutputBuffer;
    dest->mgr.term_destination = &terminateDestination;
    cinfo->dest = reinterpret_cast<struct jpeg_destination_mgr*>(dest);
}

void JpegEncoderHelper::setJpegCompressStruct(int width, int height, int quality,
                                              jpeg_compress_struct* cinfo, bool isSingleChannel) {
    cinfo->image_width = width;
    cinfo->image_height = height;
    cinfo->input_components = isSingleChannel ? 1 : 3;
    cinfo->in_color_space = isSingleChannel ? JCS_GRAYSCALE : JCS_YCbCr;
    jpeg_set_defaults(cinfo);
    jpeg_set_quality(cinfo, quality, TRUE);
    cinfo->raw_data_in = TRUE;
    cinfo->dct_method = JDCT_ISLOW;
    cinfo->comp_info[0].h_samp_factor = cinfo->in_color_space == JCS_GRAYSCALE ? 1 : 2;
    cinfo->comp_info[0].v_samp_factor = cinfo->in_color_space == JCS_GRAYSCALE ? 1 : 2;
    for (int i = 1; i < cinfo->num_components; i++) {
        cinfo->comp_info[i].h_samp_factor = 1;
        cinfo->comp_info[i].v_samp_factor = 1;
    }
}

bool JpegEncoderHelper::compressYuv(jpeg_compress_struct* cinfo, const uint8_t* yBuffer,
                                    const uint8_t* uvBuffer, int lumaStride, int chromaStride) {
    size_t chroma_plane_size = chromaStride * cinfo->image_height / 2;
    uint8_t* y_plane = const_cast<uint8_t*>(yBuffer);
    uint8_t* u_plane = const_cast<uint8_t*>(uvBuffer);
    uint8_t* v_plane = const_cast<uint8_t*>(u_plane + chroma_plane_size);

    const int aligned_width = ALIGNM(cinfo->image_width, kCompressBatchSize);
    const bool need_luma_padding = (lumaStride < aligned_width);
    const int aligned_chroma_width = ALIGNM(cinfo->image_width / 2, kCompressBatchSize / 2);
    const bool need_chroma_padding = (chromaStride < aligned_chroma_width);

    std::unique_ptr<uint8_t[]> empty = nullptr;
    std::unique_ptr<uint8_t[]> y_mcu_row = nullptr;
    std::unique_ptr<uint8_t[]> cb_mcu_row = nullptr;
    std::unique_ptr<uint8_t[]> cr_mcu_row = nullptr;
    uint8_t* y_mcu_row_ptr = nullptr;
    uint8_t* cb_mcu_row_ptr = nullptr;
    uint8_t* cr_mcu_row_ptr = nullptr;

    JSAMPROW y[kCompressBatchSize];
    JSAMPROW cb[kCompressBatchSize / 2];
    JSAMPROW cr[kCompressBatchSize / 2];
    JSAMPARRAY planes[3]{y, cb, cr};

    if (cinfo->image_height % kCompressBatchSize != 0) {
        empty = std::make_unique<uint8_t[]>(aligned_width);
        memset(empty.get(), 0, aligned_width);
    }

    if (need_luma_padding) {
        size_t mcu_row_size = aligned_width * kCompressBatchSize;
        y_mcu_row = std::make_unique<uint8_t[]>(mcu_row_size);
        y_mcu_row_ptr = y_mcu_row.get();
        uint8_t* tmp = y_mcu_row_ptr;
        for (int i = 0; i < kCompressBatchSize; ++i, tmp += aligned_width) {
            memset(tmp + cinfo->image_width, 0, aligned_width - cinfo->image_width);
        }
    }

    if (need_chroma_padding) {
        size_t mcu_row_size = aligned_chroma_width * kCompressBatchSize / 2;
        cb_mcu_row = std::make_unique<uint8_t[]>(mcu_row_size);
        cb_mcu_row_ptr = cb_mcu_row.get();
        cr_mcu_row = std::make_unique<uint8_t[]>(mcu_row_size);
        cr_mcu_row_ptr = cr_mcu_row.get();
        uint8_t* tmp1 = cb_mcu_row_ptr;
        uint8_t* tmp2 = cr_mcu_row_ptr;
        for (int i = 0; i < kCompressBatchSize / 2;
             ++i, tmp1 += aligned_chroma_width, tmp2 += aligned_chroma_width) {
            memset(tmp1 + cinfo->image_width / 2, 0,
                   aligned_chroma_width - (cinfo->image_width / 2));
            memset(tmp2 + cinfo->image_width / 2, 0,
                   aligned_chroma_width - (cinfo->image_width / 2));
        }
    }

    while (cinfo->next_scanline < cinfo->image_height) {
        for (int i = 0; i < kCompressBatchSize; ++i) {
            size_t scanline = cinfo->next_scanline + i;
            if (scanline < cinfo->image_height) {
                y[i] = y_plane + scanline * lumaStride;
                if (need_luma_padding) {
                    uint8_t* tmp = y_mcu_row_ptr + i * aligned_width;
                    memcpy(tmp, y[i], cinfo->image_width);
                    y[i] = tmp;
                }
            } else {
                y[i] = empty.get();
            }
        }
        // cb, cr only have half scanlines
        for (int i = 0; i < kCompressBatchSize / 2; ++i) {
            size_t scanline = cinfo->next_scanline / 2 + i;
            if (scanline < cinfo->image_height / 2) {
                int offset = scanline * chromaStride;
                cb[i] = u_plane + offset;
                cr[i] = v_plane + offset;
                if (need_chroma_padding) {
                    uint8_t* tmp = cb_mcu_row_ptr + i * aligned_chroma_width;
                    memcpy(tmp, cb[i], cinfo->image_width / 2);
                    cb[i] = tmp;
                    tmp = cr_mcu_row_ptr + i * aligned_chroma_width;
                    memcpy(tmp, cr[i], cinfo->image_width / 2);
                    cr[i] = tmp;
                }
            } else {
                cb[i] = cr[i] = empty.get();
            }
        }
        int processed = jpeg_write_raw_data(cinfo, planes, kCompressBatchSize);
        if (processed != kCompressBatchSize) {
            ALOGE("Number of processed lines does not equal input lines.");
            return false;
        }
    }
    return true;
}

bool JpegEncoderHelper::compressY(jpeg_compress_struct* cinfo, const uint8_t* yBuffer,
                                  int lumaStride) {
    uint8_t* y_plane = const_cast<uint8_t*>(yBuffer);

    const int aligned_luma_width = ALIGNM(cinfo->image_width, kCompressBatchSize);
    const bool need_luma_padding = (lumaStride < aligned_luma_width);

    std::unique_ptr<uint8_t[]> empty = nullptr;
    std::unique_ptr<uint8_t[]> y_mcu_row = nullptr;
    uint8_t* y_mcu_row_ptr = nullptr;

    JSAMPROW y[kCompressBatchSize];
    JSAMPARRAY planes[1]{y};

    if (cinfo->image_height % kCompressBatchSize != 0) {
        empty = std::make_unique<uint8_t[]>(aligned_luma_width);
        memset(empty.get(), 0, aligned_luma_width);
    }

    if (need_luma_padding) {
        size_t mcu_row_size = aligned_luma_width * kCompressBatchSize;
        y_mcu_row = std::make_unique<uint8_t[]>(mcu_row_size);
        y_mcu_row_ptr = y_mcu_row.get();
        uint8_t* tmp = y_mcu_row_ptr;
        for (int i = 0; i < kCompressBatchSize; ++i, tmp += aligned_luma_width) {
            memset(tmp + cinfo->image_width, 0, aligned_luma_width - cinfo->image_width);
        }
    }

    while (cinfo->next_scanline < cinfo->image_height) {
        for (int i = 0; i < kCompressBatchSize; ++i) {
            size_t scanline = cinfo->next_scanline + i;
            if (scanline < cinfo->image_height) {
                y[i] = y_plane + scanline * lumaStride;
                if (need_luma_padding) {
                    uint8_t* tmp = y_mcu_row_ptr + i * aligned_luma_width;
                    memcpy(tmp, y[i], cinfo->image_width);
                    y[i] = tmp;
                }
            } else {
                y[i] = empty.get();
            }
        }
        int processed = jpeg_write_raw_data(cinfo, planes, kCompressBatchSize);
        if (processed != kCompressBatchSize / 2) {
            ALOGE("Number of processed lines does not equal input lines.");
            return false;
        }
    }
    return true;
}

} // namespace ultrahdr
