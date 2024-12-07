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

import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_12bppYCbCr420;
import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_24bppYCbCrP010;
import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_32bppRGBA1010102;
import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_32bppRGBA8888;
import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_64bppRGBAHalfFloat;

import java.io.IOException;

/**
 * Ultra HDR encoding utility class.
 */
public class UltraHDREncoder implements AutoCloseable {

    // Fields describing the compression technology used to encode the content
    /**
     * Compress {Hdr, Sdr rendition} to an {Sdr rendition + Gain Map} using jpeg
     */
    public static final int UHDR_CODEC_JPG = 0;

    /**
     * Compress {Hdr, Sdr rendition} to an {Sdr rendition + Gain Map} using heif
     */
    public static final int UHDR_CODEC_HEIF = 1;

    /**
     * Compress {Hdr, Sdr rendition} to an {Sdr rendition + Gain Map} using avif
     */
    public static final int UHDR_CODEC_AVIF = 2;

    // Fields describing the encoder tuning configurations
    /**
     * Tune encoder settings for best performance
     */
    public static final int UHDR_USAGE_REALTIME = 0;

    /**
     * Tune encoder settings for best quality
     */
    public static final int UHDR_USAGE_BEST_QUALITY = 1;

    // APIs

    /**
     * Create and Initialize an ultrahdr encoder instance
     *
     * @throws IOException If the codec cannot be created then exception is thrown
     */
    public UltraHDREncoder() throws IOException {
        handle = 0;
        init();
    }

    /**
     * Release current ultrahdr encoder instance
     *
     * @throws Exception During release, if errors are seen, then exception is thrown
     */
    @Override
    public void close() throws Exception {
        destroy();
    }

    /**
     * Add raw image info to encoder context. This interface is used for adding 32 bits-per-pixel
     * packed formats. The function goes through all the arguments and checks for their sanity.
     * If no anomalies are seen then the image info is added to internal list. Repeated calls to
     * this function will replace the old entry with the current.
     *
     * @param rgbBuff       rgb buffer handle
     * @param width         image width
     * @param height        image height
     * @param rgbStride     rgb buffer stride
     * @param colorGamut    color gamut of input image
     * @param colorTransfer color transfer of input image
     * @param colorRange    color range of input image
     * @param colorFormat   color format of input image
     * @param intent        {@link UltraHDRCommon#UHDR_HDR_IMG} for hdr intent,
     *                      {@link UltraHDRCommon#UHDR_SDR_IMG} for sdr intent
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setRawImage(int[] rgbBuff, int width, int height, int rgbStride, int colorGamut,
            int colorTransfer, int colorRange, int colorFormat, int intent) throws IOException {
        if (rgbBuff == null) {
            throw new IOException("received null for image data handle");
        }
        if (width <= 0 || height <= 0) {
            throw new IOException("received bad width and/or height, width or height is <= 0");
        }
        if (rgbStride <= 0) {
            throw new IOException("received bad stride, stride is <= 0");
        }
        if (colorFormat != UHDR_IMG_FMT_32bppRGBA8888
                && colorFormat != UHDR_IMG_FMT_32bppRGBA1010102) {
            throw new IOException("received unsupported color format. supported color formats are"
                    + "{UHDR_IMG_FMT_32bppRGBA8888, UHDR_IMG_FMT_32bppRGBA1010102}");
        }
        setRawImageNative(rgbBuff, width, height, rgbStride, colorGamut, colorTransfer, colorRange,
                colorFormat, intent);
    }

    /**
     * Add raw image info to encoder context. This interface is used for adding 64 bits-per-pixel
     * packed formats. The function goes through all the arguments and checks for their sanity.
     * If no anomalies are seen then the image info is added to internal list. Repeated calls to
     * this function will replace the old entry with the current.
     *
     * @param rgbBuff       rgb buffer handle
     * @param width         image width
     * @param height        image height
     * @param rgbStride     rgb buffer stride
     * @param colorGamut    color gamut of input image
     * @param colorTransfer color transfer of input image
     * @param colorRange    color range of input image
     * @param colorFormat   color format of input image
     * @param intent        {@link UltraHDRCommon#UHDR_HDR_IMG} for hdr intent
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setRawImage(long[] rgbBuff, int width, int height, int rgbStride, int colorGamut,
            int colorTransfer, int colorRange, int colorFormat, int intent) throws IOException {
        if (rgbBuff == null) {
            throw new IOException("received null for image data handle");
        }
        if (width <= 0 || height <= 0) {
            throw new IOException("received bad width and/or height, width or height is <= 0");
        }
        if (rgbStride <= 0) {
            throw new IOException("received bad stride, stride is <= 0");
        }
        if (colorFormat != UHDR_IMG_FMT_64bppRGBAHalfFloat) {
            throw new IOException("received unsupported color format. supported color formats are"
                    + "{UHDR_IMG_FMT_64bppRGBAHalfFloat}");
        }
        setRawImageNative(rgbBuff, width, height, rgbStride, colorGamut, colorTransfer, colorRange,
                colorFormat, intent);
    }

    /**
     * Add raw image info to encoder context. This interface is used for adding 16 bits-per-sample
     * pixel formats. The function goes through all the arguments and checks for their sanity. If
     * no anomalies are seen then the image info is added to internal list. Repeated calls to
     * this function will replace the old entry with the current.
     *
     * @param yBuff         luma buffer handle
     * @param uvBuff        Chroma buffer handle
     * @param width         image width
     * @param height        image height
     * @param yStride       luma buffer stride
     * @param uvStride      Chroma buffer stride
     * @param colorGamut    color gamut of input image
     * @param colorTransfer color transfer of input image
     * @param colorRange    color range of input image
     * @param colorFormat   color format of input image
     * @param intent        {@link UltraHDRCommon#UHDR_HDR_IMG} for hdr intent
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setRawImage(short[] yBuff, short[] uvBuff, int width, int height,
            int yStride, int uvStride, int colorGamut, int colorTransfer,
            int colorRange, int colorFormat, int intent) throws IOException {
        if (yBuff == null || uvBuff == null) {
            throw new IOException("received null for image data handle");
        }
        if (width <= 0 || height <= 0) {
            throw new IOException("received bad width and/or height, width or height is <= 0");
        }
        if (yStride <= 0 || uvStride <= 0) {
            throw new IOException("received bad stride, stride is <= 0");
        }
        if (colorFormat != UHDR_IMG_FMT_24bppYCbCrP010) {
            throw new IOException("received unsupported color format. supported color formats are"
                    + "{UHDR_IMG_FMT_24bppYCbCrP010}");
        }
        setRawImageNative(yBuff, uvBuff, width, height, yStride, uvStride, colorGamut,
                colorTransfer, colorRange, colorFormat, intent);
    }

    /**
     * Add raw image info to encoder context. This interface is used for adding 8 bits-per-sample
     * pixel formats. The function goes through all the arguments and checks for their sanity. If
     * no anomalies are seen then the image info is added to internal list. Repeated calls to
     * this function will replace the old entry with the current.
     *
     * @param yBuff         luma buffer handle
     * @param uBuff         Cb buffer handle
     * @param vBuff         Cr buffer handle
     * @param width         image width
     * @param height        image height
     * @param yStride       luma buffer stride
     * @param uStride       Cb buffer stride
     * @param vStride       Cr buffer stride
     * @param colorGamut    color gamut of input image
     * @param colorTransfer color transfer of input image
     * @param colorRange    color range of input image
     * @param colorFormat   color format of input image
     * @param intent        {@link UltraHDRCommon#UHDR_SDR_IMG} for sdr intent
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setRawImage(byte[] yBuff, byte[] uBuff, byte[] vBuff, int width, int height,
            int yStride, int uStride, int vStride, int colorGamut, int colorTransfer,
            int colorRange, int colorFormat, int intent) throws IOException {
        if (yBuff == null || uBuff == null || vBuff == null) {
            throw new IOException("received null for image data handle");
        }
        if (width <= 0 || height <= 0) {
            throw new IOException("received bad width and/or height, width or height is <= 0");
        }
        if (yStride <= 0 || uStride <= 0 || vStride <= 0) {
            throw new IOException("received bad stride, stride is <= 0");
        }
        if (colorFormat != UHDR_IMG_FMT_12bppYCbCr420) {
            throw new IOException("received unsupported color format. supported color formats are"
                    + "{UHDR_IMG_FMT_12bppYCbCr420}");
        }
        setRawImageNative(yBuff, uBuff, vBuff, width, height, yStride, uStride, vStride, colorGamut,
                colorTransfer, colorRange, colorFormat, intent);
    }

    /**
     * Add compressed image info to encoder context. The function goes through all the arguments
     * and checks for their sanity. If no anomalies are seen then the image info is added to
     * internal list. Repeated calls to this function will replace the old entry with the current.
     * <p>
     * If both {@link UltraHDREncoder#setRawImage} and this function are called during a session
     * for the same intent, it is assumed that raw image descriptor and compressed image
     * descriptor are relatable via compress <-> decompress process.
     *
     * @param data          byteArray containing compressed image data
     * @param size          compressed image size
     * @param colorGamut    color standard of the image. Certain image formats are capable of
     *                      storing color standard information in the bitstream, for instance heif.
     *                      Some formats are not capable of storing the same. This field can be used
     *                      as an additional source to convey this information. If unknown, this can
     *                      be set to {@link UltraHDRCommon#UHDR_CG_UNSPECIFIED}.
     * @param colorTransfer color transfer of the image. Just like colorGamut parameter, this
     *                      field can be used as an additional source to convey image transfer
     *                      characteristics. If unknown, this can be set to
     *                      {@link UltraHDRCommon#UHDR_CT_UNSPECIFIED}.
     * @param range         color range. Just like colorGamut parameter, this field can be used
     *                      as an additional source to convey color range characteristics. If
     *                      unknown, this can be set to {@link UltraHDRCommon#UHDR_CR_UNSPECIFIED}.
     * @param intent        {@link UltraHDRCommon#UHDR_HDR_IMG} for hdr intent,
     *                      {@link UltraHDRCommon#UHDR_SDR_IMG} for sdr intent,
     *                      {@link UltraHDRCommon#UHDR_BASE_IMG} for base image intent
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setCompressedImage(byte[] data, int size, int colorGamut, int colorTransfer,
            int range, int intent) throws IOException {
        if (data == null) {
            throw new IOException("received null for image data handle");
        }
        if (size <= 0) {
            throw new IOException("received invalid compressed image size, size is <= 0");
        }
        setCompressedImageNative(data, size, colorGamut, colorTransfer, range, intent);
    }

    /**
     * Add gain map image descriptor and gainmap metadata info that was used to generate the
     * aforth gainmap image to encoder context. The function internally goes through all the
     * arguments and checks for their sanity. If no anomalies are seen then the image is added to
     * internal list. Repeated calls to this function will replace the old entry with the current.
     * <p>
     * NOTE: There are apis that allow configuration of gainmap info separately. For instance
     * {@link UltraHDREncoder#setGainMapGamma(float)},
     * {@link UltraHDREncoder#setGainMapScaleFactor(int)}, ... They have no effect on the
     * information that is configured via this api. The information configured here is treated as
     * immutable and used as-is in encoding scenario where gainmap computations are intended to
     * be by-passed.
     *
     * @param data            byteArray containing compressed image data
     * @param size            compressed image size
     * @param maxContentBoost value to control how much brighter an image can get, when shown on
     *                        an HDR display, relative to the SDR rendition. This is constant for
     *                        a given image. Value MUST be in linear scale.
     * @param minContentBoost value to control how much darker an image can get, when shown on
     *                        an HDR display, relative to the SDR rendition. This is constant for
     *                        a given image. Value MUST be in linear scale.
     * @param gainmapGamma    Encoding gamma of gainmap image.
     * @param offsetSdr       The offset to apply to the SDR pixel values during gainmap
     *                        generation and application.
     * @param offsetHdr       The offset to apply to the HDR pixel values during gainmap
     *                        generation and application.
     * @param hdrCapacityMin  Minimum display boost value for which the map is applied completely.
     *                        Value MUST be in linear scale.
     * @param hdrCapacityMax  Maximum display boost value for which the map is applied completely.
     *                        Value MUST be in linear scale.
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setGainMapImageInfo(byte[] data, int size, float[] maxContentBoost,
            float[] minContentBoost, float[] gainmapGamma, float[] offsetSdr, float[] offsetHdr,
            float hdrCapacityMin, float hdrCapacityMax, boolean useBaseColorSpace)
            throws IOException {
        if (data == null) {
            throw new IOException("received null for image data handle");
        }
        if (size <= 0) {
            throw new IOException("received invalid compressed image size, size is <= 0");
        }
        setGainMapImageInfoNative(data, size, maxContentBoost, minContentBoost, gainmapGamma,
                offsetSdr, offsetHdr, hdrCapacityMin, hdrCapacityMax, useBaseColorSpace);
    }

    /**
     * Set Exif data that needs to be inserted in the output compressed stream. This function
     * does not generate or validate exif data on its own. It merely copies the supplied
     * information into the bitstream.
     *
     * @param data exif data
     * @param size exif size
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setExifData(byte[] data, int size) throws IOException {
        if (data == null) {
            throw new IOException("received null for exif data handle");
        }
        if (size <= 0) {
            throw new IOException("received invalid compressed image size, size is <= 0");
        }
        setExifDataNative(data, size);
    }

    /**
     * Set quality factor for compressing base image and/or gainmap image. Default configured
     * quality factor of base image and gainmap image are 95 and 95 respectively.
     *
     * @param qualityFactor Any integer in range [0 - 100]
     * @param intent        {@link UltraHDRCommon#UHDR_BASE_IMG} or
     *                      {@link UltraHDRCommon#UHDR_GAIN_MAP_IMG}
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setQualityFactor(int qualityFactor, int intent) throws IOException {
        setQualityFactorNative(qualityFactor, intent);
    }

    /**
     * Enable/Disable multi-channel gainmap. By default, multi-channel gainmap is enabled.
     *
     * @param enable if true, multi-channel gainmap is enabled, else, single-channel gainmap is
     *               enabled
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setMultiChannelGainMapEncoding(boolean enable) throws IOException {
        setMultiChannelGainMapEncodingNative(enable);
    }

    /**
     * Set gain map scaling factor. The encoding process allows signalling a downscaled gainmap
     * image instead of full resolution. This setting controls the factor by which the renditions
     * are downscaled. For instance, gain_map_scale_factor = 2 implies gainmap_image_width =
     * primary_image_width / 2 and gainmap image height = primary_image_height / 2.
     * Default gain map scaling factor is 1.
     * <p>
     * NOTE: This has no effect on base image rendition. Base image is signalled in full resolution
     * always.
     *
     * @param scaleFactor gain map scale factor. Any integer in range (0, 128]
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setGainMapScaleFactor(int scaleFactor) throws IOException {
        setGainMapScaleFactorNative(scaleFactor);
    }

    /**
     * Set encoding gamma of gainmap image. For multi-channel gainmap image, set gamma is used
     * for gamma correction of all planes separately. Default gamma value is 1.0.
     *
     * @param gamma gamma of gainmap image. Any positive real number
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setGainMapGamma(float gamma) throws IOException {
        setGainMapGammaNative(gamma);
    }

    /**
     * Set encoding preset. Tunes the encoder configurations for performance or quality. Default
     * configuration is {@link UltraHDREncoder#UHDR_USAGE_BEST_QUALITY}.
     *
     * @param preset encoding preset. {@link UltraHDREncoder#UHDR_USAGE_REALTIME} for best
     *               performance {@link UltraHDREncoder#UHDR_USAGE_BEST_QUALITY} for best quality
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setEncPreset(int preset) throws IOException {
        setEncPresetNative(preset);
    }

    /**
     * Set output image compression format. Selects the compression format for encoding base
     * image and gainmap image. Default configuration is {@link UltraHDREncoder#UHDR_CODEC_JPG}.
     *
     * @param mediaType output image compression format. Supported values are
     *                  {@link UltraHDREncoder#UHDR_CODEC_JPG}
     * @throws IOException If parameters are not valid or current encoder instance is not valid
     *                     or current encoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setOutputFormat(int mediaType) throws IOException {
        setOutputFormatNative(mediaType);
    }

    /**
     * Set min max content boost. This configuration is treated as a recommendation by the
     * library. It is entirely possible for the library to use a different set of values. Value
     * MUST be in linear scale.
     *
     * @param minContentBoost min content boost. Any positive real number
     * @param maxContentBoost max content boost. Any positive real numer >= minContentBoost
     * @throws IOException If parameters are not valid or current encoder instance
     *                     is not valid or current encoder instance is not suitable
     *                     for configuration exception is thrown
     */
    public void setMinMaxContentBoost(float minContentBoost, float maxContentBoost)
            throws IOException {
        setMinMaxContentBoostNative(minContentBoost, maxContentBoost);
    }

    /**
     * Set target display peak brightness in nits. This is used for configuring
     * {@link UltraHDRDecoder.GainMapMetadata#hdrCapacityMax}. This value determines the weight
     * by which the gain map coefficients are scaled during decode. If this is not configured,
     * then default peak luminance of HDR intent's color transfer under test is used. For
     * {@link UltraHDRCommon#UHDR_CT_HLG} input, this corresponds to 1000 nits and for
     * {@link UltraHDRCommon#UHDR_CT_LINEAR} and {@link UltraHDRCommon#UHDR_CT_PQ} inputs, this
     * corresponds to 10000 nits.
     *
     * @param nits target display peak brightness in nits. Any positive real number in range
     *             [203, 10000]
     * @throws IOException If parameters are not valid or current encoder instance
     *                     is not valid or current encoder instance is not suitable
     *                     for configuration exception is thrown
     */
    public void setTargetDisplayPeakBrightness(float nits) throws IOException {
        setTargetDisplayPeakBrightnessNative(nits);
    }

    /**
     * Encode process call.
     * <p>
     * After initializing the encoder context, call to this function will submit data for
     * encoding. If the call is successful, the encoded output is stored internally and is
     * accessible via {@link UltraHDREncoder#getOutput()}.
     *
     * @throws IOException If any errors are encountered during the encoding process, exception is
     *                     thrown
     */
    public void encode() throws IOException {
        encodeNative();
    }

    /**
     * Get encoded ultra hdr stream
     *
     * @return byte array contains encoded output data
     * @throws IOException If {@link UltraHDREncoder#encode()} is not called or encoding process
     *                     is not successful, exception is thrown
     */
    public byte[] getOutput() throws IOException {
        return getOutputNative();
    }

    /**
     * Reset encoder instance. Clears all previous settings and resets to default state and ready
     * for re-initialization and usage.
     *
     * @throws IOException If the current encoder instance is not valid exception is thrown.
     */
    public void reset() throws IOException {
        resetNative();
    }

    private native void init() throws IOException;

    private native void destroy() throws IOException;

    private native void setRawImageNative(int[] rgbBuff, int width, int height, int rgbStride,
            int colorGamut, int colorTransfer, int colorRange, int colorFormat, int intent)
            throws IOException;

    private native void setRawImageNative(long[] rgbBuff, int width, int height, int rgbStride,
            int colorGamut, int colorTransfer, int colorRange, int colorFormat, int intent)
            throws IOException;

    private native void setRawImageNative(short[] yBuff, short[] uvBuff, int width, int height,
            int yStride, int uvStride, int colorGamut, int colorTransfer, int colorRange,
            int colorFormat, int intent) throws IOException;

    private native void setRawImageNative(byte[] yBuff, byte[] uBuff, byte[] vBuff, int width,
            int height, int yStride, int uStride, int vStride, int colorGamut, int colorTransfer,
            int colorRange, int colorFormat, int intent) throws IOException;

    private native void setCompressedImageNative(byte[] data, int size, int colorGamut,
            int colorTransfer, int range, int intent) throws IOException;

    private native void setGainMapImageInfoNative(byte[] data, int size, float[] maxContentBoost,
            float[] minContentBoost, float[] gainmapGamma, float[] offsetSdr, float[] offsetHdr,
            float hdrCapacityMin, float hdrCapacityMax, boolean useBaseColorSpace)
            throws IOException;

    private native void setExifDataNative(byte[] data, int size) throws IOException;

    private native void setQualityFactorNative(int qualityFactor, int intent) throws IOException;

    private native void setMultiChannelGainMapEncodingNative(boolean enable) throws IOException;

    private native void setGainMapScaleFactorNative(int scaleFactor) throws IOException;

    private native void setGainMapGammaNative(float gamma) throws IOException;

    private native void setEncPresetNative(int preset) throws IOException;

    private native void setOutputFormatNative(int mediaType) throws IOException;

    private native void setMinMaxContentBoostNative(float minContentBoost,
            float maxContentBoost) throws IOException;

    private native void setTargetDisplayPeakBrightnessNative(float nits) throws IOException;

    private native void encodeNative() throws IOException;

    private native byte[] getOutputNative() throws IOException;

    private native void resetNative() throws IOException;

    /**
     * Encoder handle. Filled by {@link UltraHDREncoder#init()}
     */
    private long handle;

    static {
        System.loadLibrary("uhdrjni");
    }
}
