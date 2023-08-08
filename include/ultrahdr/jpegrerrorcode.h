/*
 * Copyright (C) 2022 The Android Open Source Project
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

#ifndef ANDROID_ULTRAHDR_JPEGRERRORCODE_H
#define ANDROID_ULTRAHDR_JPEGRERRORCODE_H

#include <utils/Errors.h>

namespace android::ultrahdr {

enum {
    // status_t map for errors in the media framework
    // OK or NO_ERROR or 0 represents no error.

    // See system/core/include/utils/Errors.h
    // System standard errors from -1 through (possibly) -133
    //
    // Errors with special meanings and side effects.
    // INVALID_OPERATION:  Operation attempted in an illegal state (will try to signal to app).
    // DEAD_OBJECT:        Signal from CodecBase to MediaCodec that MediaServer has died.
    // NAME_NOT_FOUND:     Signal from CodecBase to MediaCodec that the component was not found.

    // JPEGR errors
    JPEGR_IO_ERROR_BASE                 = -10000,
    ERROR_JPEGR_INVALID_INPUT_TYPE      = JPEGR_IO_ERROR_BASE,
    ERROR_JPEGR_INVALID_OUTPUT_TYPE     = JPEGR_IO_ERROR_BASE - 1,
    ERROR_JPEGR_INVALID_NULL_PTR        = JPEGR_IO_ERROR_BASE - 2,
    ERROR_JPEGR_RESOLUTION_MISMATCH     = JPEGR_IO_ERROR_BASE - 3,
    ERROR_JPEGR_BUFFER_TOO_SMALL        = JPEGR_IO_ERROR_BASE - 4,
    ERROR_JPEGR_INVALID_COLORGAMUT      = JPEGR_IO_ERROR_BASE - 5,
    ERROR_JPEGR_INVALID_TRANS_FUNC      = JPEGR_IO_ERROR_BASE - 6,
    ERROR_JPEGR_INVALID_METADATA        = JPEGR_IO_ERROR_BASE - 7,
    ERROR_JPEGR_UNSUPPORTED_METADATA    = JPEGR_IO_ERROR_BASE - 8,
    ERROR_JPEGR_GAIN_MAP_IMAGE_NOT_FOUND = JPEGR_IO_ERROR_BASE - 9,

    JPEGR_RUNTIME_ERROR_BASE            = -20000,
    ERROR_JPEGR_ENCODE_ERROR            = JPEGR_RUNTIME_ERROR_BASE - 1,
    ERROR_JPEGR_DECODE_ERROR            = JPEGR_RUNTIME_ERROR_BASE - 2,
    ERROR_JPEGR_CALCULATION_ERROR       = JPEGR_RUNTIME_ERROR_BASE - 3,
    ERROR_JPEGR_METADATA_ERROR          = JPEGR_RUNTIME_ERROR_BASE - 4,
    ERROR_JPEGR_TONEMAP_ERROR           = JPEGR_RUNTIME_ERROR_BASE - 5,

    ERROR_JPEGR_UNSUPPORTED_FEATURE     = -20000,
};

}  // namespace android::ultrahdr

#endif // ANDROID_ULTRAHDR_JPEGRERRORCODE_H
