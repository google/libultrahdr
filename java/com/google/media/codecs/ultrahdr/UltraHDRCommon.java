/*
 * Copyright (C) 2024 The Android Open Source Project
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

package com.google.media.codecs.ultrahdr;

/**
 * Ultra HDR common utility class (cannot be instantiated). These constants MUST be kept in sync
 * with the constants defined ultrahdr_api.h
 */
public class UltraHDRCommon {
    // Fields describing the color format of raw image
    /**
     * Unspecified color format
     */
    public static final int UHDR_IMG_FMT_UNSPECIFIED = -1;

    /**
     * P010 is 10-bit-per component 4:2:0 YCbCr semiplanar format.
     * <p>
     * This format uses 24 allocated bits per pixel with 15 bits of
     * data per pixel. Chroma planes are subsampled by 2 both
     * horizontally and vertically. Each chroma and luma component
     * has 16 allocated bits in little-endian configuration with 10
     * MSB of actual data.
     *
     * <pre>
     *            byte                   byte
     *  <--------- i --------> | <------ i + 1 ------>
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |     UNUSED      |      Y/Cb/Cr                |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *  0               5 6   7 0                    7
     * bit
     * </pre>
     */
    public static final int UHDR_IMG_FMT_24bppYCbCrP010 = 0;

    /**
     * Flexible 12 bits per pixel, subsampled YUV color format with 8-bit chroma and luma
     * components.
     * <p>
     * Chroma planes are subsampled by 2 both horizontally and vertically.
     */
    public static final int UHDR_IMG_FMT_12bppYCbCr420 = 1;

    /**
     * 8 bits per pixel Y color format.
     * <p>
     * Each byte contains a single pixel.
     */
    public static final int UHDR_IMG_FMT_8bppYCbCr400 = 2;

    /**
     * 32 bits per pixel RGBA color format, with 8-bit red, green, blue, and alpha components.
     * <p>
     * Using 32-bit little-endian representation, colors stored as Red 7:0, Green 15:8,
     * Blue 23:16, and Alpha 31:24.
     * <pre>
     *         byte              byte             byte              byte
     *  <------ i -----> | <---- i+1 ----> | <---- i+2 ----> | <---- i+3 ----->
     * +-----------------+-----------------+-----------------+-----------------+
     * |       RED       |      GREEN      |       BLUE      |      ALPHA      |
     * +-----------------+-----------------+-----------------+-----------------+
     * </pre>
     */
    public static final int UHDR_IMG_FMT_32bppRGBA8888 = 3;

    /**
     * 64 bits per pixel, 16 bits per channel, half-precision floating point RGBA color format.
     * In a pixel even though each channel has storage space of 16 bits, the nominal range is
     * expected to be [0.0..(10000/203)]
     * <p>
     *
     * <pre>
     *         byte              byte             byte              byte
     *  <-- i -->|<- i+1 ->|<- i+2 ->|<- i+3 ->|<- i+4 ->|<- i+5 ->|<- i+6 ->|<- i+7 ->
     * +---------+---------+-------------------+---------+---------+---------+---------+
     * |        RED        |       GREEN       |       BLUE        |       ALPHA       |
     * +---------+---------+-------------------+---------+---------+---------+---------+
     *  0       7 0       7 0       7 0       7 0       7 0       7 0       7 0       7
     * </pre>
     */
    public static final int UHDR_IMG_FMT_64bppRGBAHalfFloat = 4;

    /**
     * 32 bits per pixel RGBA color format, with 10-bit red, green,
     * blue, and 2-bit alpha components.
     * <p>
     * Using 32-bit little-endian representation, colors stored as
     * Red 9:0, Green 19:10, Blue 29:20, and Alpha 31:30.
     * <pre>
     *         byte              byte             byte              byte
     *  <------ i -----> | <---- i+1 ----> | <---- i+2 ----> | <---- i+3 ----->
     * +-----------------+---+-------------+-------+---------+-----------+-----+
     * |       RED           |      GREEN          |       BLUE          |ALPHA|
     * +-----------------+---+-------------+-------+---------+-----------+-----+
     *  0               7 0 1 2           7 0     3 4       7 0         5 6   7
     * </pre>
     */
    public static final int UHDR_IMG_FMT_32bppRGBA1010102 = 5;

    // Fields describing the color primaries of the content
    /**
     * Unspecified color gamut
     */
    public static final int UHDR_CG_UNSPECIFIED = -1;

    /**
     * BT.709 color chromaticity coordinates with KR = 0.2126, KB = 0.0722
     */
    public static final int UHDR_CG_BT709 = 0;

    /**
     * Display P3 color chromaticity coordinates with KR = 0.22897, KB = 0.07929
     */
    public static final int UHDR_CG_DISPLAY_P3 = 1;

    /**
     * BT.2020 color chromaticity coordinates with KR = 0.2627, KB = 0.0593
     */
    public static final int UHDR_CG_BT2100 = 2;

    // Fields describing the opto-electronic transfer function of the content
    /**
     * Unspecified color transfer
     */
    public static final int UHDR_CT_UNSPECIFIED = -1;

    /**
     * Linear transfer characteristic curve
     */
    public static final int UHDR_CT_LINEAR = 0;

    /**
     * hybrid-log-gamma transfer function
     */
    public static final int UHDR_CT_HLG = 1;

    /**
     * PQ transfer function
     */
    public static final int UHDR_CT_PQ = 2;

    /**
     * sRGB transfer function
     */
    public static final int UHDR_CT_SRGB = 3;

    // Fields describing the data range of the content
    /**
     * Unspecified color range
     */
    public static final int UHDR_CR_UNSPECIFIED = -1;

    /**
     * Limited range. Y component values range from [16 - 235] * pow(2, (bpc - 8)) and Cb, Cr
     * component values range from [16 - 240] * pow(2, (bpc - 8)). Here, bpc is bits per channel
     */
    public static final int UHDR_CR_LIMITED_RANGE = 0;

    /**
     * Full range. Y component values range from [0 - 255] * pow(2, (bpc - 8)) and Cb, Cr
     * component values range from [0 - 255] * pow(2, (bpc - 8)). Here, bpc is bits per channel
     */
    public static final int UHDR_CR_FULL_RANGE = 1;

    // Fields describing the technology associated with the content
    /**
     * Hdr rendition of an image
     */
    public static final int UHDR_HDR_IMG = 0;

    /**
     * Sdr rendition of an image
     */
    public static final int UHDR_SDR_IMG = 1;

    /**
     * Base rendition of an ultrahdr image
     */
    public static final int UHDR_BASE_IMG = 2;

    /**
     * GainMap rendition of an ultrahdr image
     */
    public static final int UHDR_GAIN_MAP_IMG = 3;

    private UltraHDRCommon() {
    }

    /**
     * Get library version in string format
     * @return version string
     */
    public static String getVersionString() {
        return getVersionStringNative();
    }

    /**
     * Get library version
     * @return version
     */
    public static int getVersion() {
        return getVersionNative();
    }

    private static native String getVersionStringNative();

    private static native int getVersionNative();

    static {
        System.loadLibrary("uhdrjni");
    }
}
