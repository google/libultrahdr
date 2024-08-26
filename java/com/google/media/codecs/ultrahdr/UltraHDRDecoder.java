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

import java.io.IOException;

/**
 * Ultra HDR decoding utility class
 */
public class UltraHDRDecoder implements AutoCloseable {

    public static class GainMapMetadata {
        public float maxContentBoost;
        public float minContentBoost;
        public float gamma;
        public float offsetSdr;
        public float offsetHdr;
        public float hdrCapacityMin;
        public float hdrCapacityMax;

        public GainMapMetadata(float maxContentBoost, float minContentBoost, float gamma,
                float offsetSdr, float offsetHdr, float hdrCapacityMin, float hdrCapacityMax) {
            this.maxContentBoost = maxContentBoost;
            this.minContentBoost = minContentBoost;
            this.gamma = gamma;
            this.offsetSdr = offsetSdr;
            this.offsetHdr = offsetHdr;
            this.hdrCapacityMin = hdrCapacityMin;
            this.hdrCapacityMax = hdrCapacityMax;
        }
    }

    public static class RawImageDescriptor {
        public int fmt;
        public int cg;
        public int ct;
        public int range;
        public int w;
        public int h;
        public byte[] data;
        public int stride;

        public RawImageDescriptor(int fmt, int cg, int ct, int range, int w, int h, byte[] data,
                int stride) {
            this.fmt = fmt;
            this.cg = cg;
            this.ct = ct;
            this.range = range;
            this.w = w;
            this.h = h;
            this.data = data;
            this.stride = stride;
        }
    }

    // APIs

    /**
     * Checks if the current input image is a valid ultrahdr image
     *
     * @param data The compressed image data.
     * @param size The size of the compressed image data.
     * @return TRUE if the input data has a primary image, gainmap image and gainmap metadata.
     * FALSE if any errors are encountered during parsing process or if the image does not have
     * primary image or gainmap image or gainmap metadata
     * @throws IOException If parameters are not valid exception is thrown.
     */
    public static boolean isUHDRImage(byte[] data, int size) throws IOException {
        if (data == null) {
            throw new IOException("received null for image data handle");
        }
        if (size <= 0) {
            throw new IOException("received invalid compressed image size, size is <= 0");
        }
        return (isUHDRImageNative(data, size) == 1);
    }

    /**
     * Create and Initialize an ultrahdr decoder instance
     *
     * @throws IOException If the codec cannot be created then exception is thrown
     */
    UltraHDRDecoder() throws IOException {
        handle = 0;
        init();
        resetState();
    }

    /**
     * Release current ultrahdr decoder instance
     *
     * @throws Exception during release, if errors are seen, then exception is thrown
     */
    @Override
    public void close() throws Exception {
        destroy();
        resetState();
    }

    /**
     * Add compressed image data to be decoded to the decoder context. The function goes through
     * all the arguments and checks for their sanity. If no anomalies are seen then the image
     * info is added to internal list. Repeated calls to this function will replace the old entry
     * with the current.
     *
     * @param data          The compressed image data.
     * @param size          The size of the compressed image data.
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
     * @throws IOException If parameters are not valid or current decoder instance is not valid
     *                     or current decoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setCompressedImage(byte[] data, int size, int colorGamut, int colorTransfer,
            int range) throws IOException {
        if (data == null) {
            throw new IOException("received null for image data handle");
        }
        if (size <= 0) {
            throw new IOException("received invalid compressed image size, size is <= 0");
        }
        setCompressedImageNative(data, size, colorGamut, colorTransfer, range);
    }

    /**
     * Set output image color format
     *
     * @param fmt output image color format. Supported values are
     *            {@link UltraHDRCommon#UHDR_IMG_FMT_32bppRGBA8888},
     *            {@link UltraHDRCommon#UHDR_IMG_FMT_32bppRGBA1010102},
     *            {@link UltraHDRCommon#UHDR_IMG_FMT_64bppRGBAHalfFloat}
     * @throws IOException If parameters are not valid or current decoder instance is not valid
     *                     or current decoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setOutputFormat(int fmt) throws IOException {
        setOutputFormatNative(fmt);
    }

    /**
     * Set output image color transfer characteristics. It should be noted that not all
     * combinations of output color format and output transfer function are supported.
     * {@link UltraHDRCommon#UHDR_CT_SRGB} output color transfer shall be paired with
     * {@link UltraHDRCommon#UHDR_IMG_FMT_32bppRGBA8888} only. {@link UltraHDRCommon#UHDR_CT_HLG}
     * and {@link UltraHDRCommon#UHDR_CT_PQ} shall be paired with
     * {@link UltraHDRCommon#UHDR_IMG_FMT_32bppRGBA1010102}.
     * {@link UltraHDRCommon#UHDR_CT_LINEAR} shall be paired with
     * {@link UltraHDRCommon#UHDR_IMG_FMT_64bppRGBAHalfFloat}.
     *
     * @param ct output image color transfer.
     * @throws IOException If parameters are not valid or current decoder instance is not valid
     *                     or current decoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setColorTransfer(int ct) throws IOException {
        setColorTransferNative(ct);
    }

    /**
     * Set output display's HDR capacity. Value MUST be in linear scale. This value determines
     * the weight by which the gain map coefficients are scaled. If no value is configured, no
     * weight is applied to gainmap image.
     *
     * @param displayBoost hdr capacity of target display. Any real number >= 1.0f
     * @throws IOException If parameters are not valid or current decoder instance is not valid
     *                     or current decoder instance is not suitable for configuration
     *                     exception is thrown
     */
    public void setMaxDisplayBoost(float displayBoost) throws IOException {
        setMaxDisplayBoostNative(displayBoost);
    }

    /**
     * This function parses the bitstream that is registered with the decoder context and makes
     * image information available to the client via getter functions. It does not decompress the
     * image. That is done by {@link UltraHDRDecoder#decode()}.
     *
     * @throws IOException during parsing process if any errors are seen exception is thrown
     */
    public void probe() throws IOException {
        probeNative();
    }

    /**
     * Get base image width
     *
     * @return base image width
     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
     *                     process if any errors are seen exception is thrown
     */
    public int getImageWidth() throws IOException {
        return getImageWidthNative();
    }

    /**
     * Get base image height
     *
     * @return base image height
     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
     *                     process if any errors are seen exception is thrown
     */
    public int getImageHeight() throws IOException {
        return getImageHeightNative();
    }

    /**
     * Get gainmap image width
     *
     * @return gainmap image width
     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
     *                     process if any errors are seen exception is thrown
     */
    public int getGainMapWidth() throws IOException {
        return getGainMapWidthNative();
    }

    /**
     * Get gainmap image height
     *
     * @return gainmap image height
     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
     *                     process if any errors are seen exception is thrown
     */
    public int getGainMapHeight() throws IOException {
        return getGainMapHeightNative();
    }

    /**
     * Get exif information
     *
     * @return A byte array containing the EXIF metadata
     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
     *                     process if any errors are seen exception is thrown
     */
    public byte[] getExif() throws IOException {
        return getExifNative();
    }

    /**
     * Get icc information
     *
     * @return A byte array containing the icc data
     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
     *                     process if any errors are seen exception is thrown
     */
    public byte[] getIcc() throws IOException {
        return getIccNative();
    }

    /**
     * Get gain map metadata
     *
     * @return gainmap metadata
     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
     *                     process if any errors are seen exception is thrown
     */
    public GainMapMetadata getGainmapMetadata() throws IOException {
        getGainmapMetadataNative();
        return new GainMapMetadata(maxContentBoost, minContentBoost, gamma, offsetSdr,
                offsetHdr, hdrCapacityMin, hdrCapacityMax);
    }

    /**
     * Decode process call.
     * <p>
     * After initializing the decode context, call to this function will submit data for
     * encoding. If the call is successful, the decode output is stored internally and is
     * accessible via {@link UltraHDRDecoder#getDecodedImage()}.
     *
     * @throws IOException If any errors are encountered during the decoding process, exception is
     *                     thrown
     */
    public void decode() throws IOException {
        decodeNative();
    }

    /**
     * Get decoded image data
     *
     * @return Raw image descriptor containing decoded image data
     * @throws IOException If {@link UltraHDRDecoder#decode()} is not called or decoding process
     *                     is not successful, exception is thrown
     */
    public RawImageDescriptor getDecodedImage() throws IOException {
        decodedData = getDecodedImageNative();
        return new RawImageDescriptor(imgFormat, imgGamut, imgTransfer, imgRange, imgWidth,
                imgHeight, decodedData, imgStride);
    }

    /**
     * Get decoded gainmap image data
     *
     * @return Raw image descriptor containing decoded gainmap image data
     * @throws IOException If {@link UltraHDRDecoder#decode()} is not called or decoding process
     *                     is not successful, exception is thrown
     */
    public RawImageDescriptor getGainMapImage() throws IOException {
        decodedGainMapData = getGainMapImageNative();
        return new RawImageDescriptor(gainmapFormat, UltraHDRCommon.UHDR_CG_UNSPECIFIED,
                UltraHDRCommon.UHDR_CT_UNSPECIFIED, UltraHDRCommon.UHDR_CR_UNSPECIFIED,
                gainmapWidth, gainmapHeight, decodedGainMapData, gainmapStride);
    }

    /**
     * Reset decoder instance. Clears all previous settings and resets to default state and ready
     * for re-initialization and usage.
     *
     * @throws IOException If the current decoder instance is not valid exception is thrown.
     */
    public void reset() throws IOException {
        resetNative();
        resetState();
    }

    private void resetState() {
        maxContentBoost = 1.0f;
        minContentBoost = 1.0f;
        gamma = 1.0f;
        offsetSdr = 0.0f;
        offsetHdr = 0.0f;
        hdrCapacityMin = 1.0f;
        hdrCapacityMax = 1.0f;

        decodedData = null;
        imgWidth = -1;
        imgHeight = -1;
        imgStride = 0;
        imgFormat = UltraHDRCommon.UHDR_IMG_FMT_UNSPECIFIED;
        imgGamut = UltraHDRCommon.UHDR_CG_UNSPECIFIED;
        imgTransfer = UltraHDRCommon.UHDR_CG_UNSPECIFIED;
        imgRange = UltraHDRCommon.UHDR_CG_UNSPECIFIED;

        decodedGainMapData = null;
        gainmapWidth = -1;
        gainmapHeight = -1;
        gainmapStride = 0;
        gainmapFormat = UltraHDRCommon.UHDR_IMG_FMT_UNSPECIFIED;
    }

    private static native int isUHDRImageNative(byte[] data, int size) throws IOException;

    private native void init() throws IOException;

    private native void destroy() throws IOException;

    private native void setCompressedImageNative(byte[] data, int size, int colorGamut,
            int colorTransfer, int range) throws IOException;

    private native void setOutputFormatNative(int fmt) throws IOException;

    private native void setColorTransferNative(int ct) throws IOException;

    private native void setMaxDisplayBoostNative(float displayBoost) throws IOException;

    private native void probeNative() throws IOException;

    private native int getImageWidthNative() throws IOException;

    private native int getImageHeightNative() throws IOException;

    private native int getGainMapWidthNative() throws IOException;

    private native int getGainMapHeightNative() throws IOException;

    private native byte[] getExifNative() throws IOException;

    private native byte[] getIccNative() throws IOException;

    private native void getGainmapMetadataNative() throws IOException;

    private native void decodeNative() throws IOException;

    private native byte[] getDecodedImageNative() throws IOException;

    private native byte[] getGainMapImageNative() throws IOException;

    private native void resetNative() throws IOException;

    /**
     * Decoder handle. Filled by {@link UltraHDRDecoder#init()}
     */
    private long handle;

    /**
     * gainmap metadata fields. Filled by {@link UltraHDRDecoder#getGainmapMetadataNative()}
     */
    private float maxContentBoost;
    private float minContentBoost;
    private float gamma;
    private float offsetSdr;
    private float offsetHdr;
    private float hdrCapacityMin;
    private float hdrCapacityMax;

    /**
     * decoded image fields. Filled by {@link UltraHDRDecoder#getDecodedImageNative()}
     */
    private byte[] decodedData;
    private int imgWidth;
    private int imgHeight;
    private int imgStride;
    private int imgFormat;
    private int imgGamut;
    private int imgTransfer;
    private int imgRange;

    /**
     * decoded image fields. Filled by {@link UltraHDRDecoder#getGainMapImageNative()}
     */
    private byte[] decodedGainMapData;
    private int gainmapWidth;
    private int gainmapHeight;
    private int gainmapStride;
    private int gainmapFormat;

    static {
        System.loadLibrary("ultrahdr");
    }
}
