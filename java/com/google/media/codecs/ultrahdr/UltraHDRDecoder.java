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

import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_CG_UNSPECIFIED;
import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_CR_UNSPECIFIED;
import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_CT_UNSPECIFIED;
import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_32bppRGBA1010102;
import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_32bppRGBA8888;
import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_64bppRGBAHalfFloat;
import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_8bppYCbCr400;
import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_UNSPECIFIED;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Ultra HDR decoding utility class.
 */
public class UltraHDRDecoder implements AutoCloseable {

    /**
     * GainMap Metadata Descriptor
     */
    public static class GainMapMetadata {
        public float[] maxContentBoost = new float[3];
        public float[] minContentBoost = new float[3];
        public float[] gamma = new float[3];
        public float[] offsetSdr = new float[3];
        public float[] offsetHdr = new float[3];
        public float hdrCapacityMin;
        public float hdrCapacityMax;
        public boolean useBaseColorSpace;

        public GainMapMetadata() {
            Arrays.fill(this.maxContentBoost, 1.0f);
            Arrays.fill(this.minContentBoost, 1.0f);
            Arrays.fill(this.gamma, 1.0f);
            Arrays.fill(this.offsetSdr, 0.0f);
            Arrays.fill(this.offsetHdr, 0.0f);
            this.hdrCapacityMin = 1.0f;
            this.hdrCapacityMax = 1.0f;
            this.useBaseColorSpace = true;
        }

        public GainMapMetadata(float[] maxContentBoost, float[] minContentBoost, float[] gamma,
                float[] offsetSdr, float[] offsetHdr, float hdrCapacityMin, float hdrCapacityMax,
                boolean useBaseColorSpace) {
            System.arraycopy(maxContentBoost, 0, this.maxContentBoost, 0, 3);
            System.arraycopy(minContentBoost, 0, this.minContentBoost, 0, 3);
            System.arraycopy(gamma, 0, this.gamma, 0, 3);
            System.arraycopy(offsetSdr, 0, this.offsetSdr, 0, 3);
            System.arraycopy(offsetHdr, 0, this.offsetHdr, 0, 3);
            this.hdrCapacityMin = hdrCapacityMin;
            this.hdrCapacityMax = hdrCapacityMax;
            this.useBaseColorSpace = useBaseColorSpace;
        }
    }

    /**
     * Raw Image Descriptor.
     */
    public static abstract class RawImage {
        public byte[] nativeOrderBuffer;
        public int fmt;
        public int cg;
        public int ct;
        public int range;
        public int w;
        public int h;
        public int stride;

        public RawImage(byte[] nativeOrderBuffer, int fmt, int cg, int ct, int range, int w, int h,
                int stride) {
            this.nativeOrderBuffer = nativeOrderBuffer;
            this.fmt = fmt;
            this.cg = cg;
            this.ct = ct;
            this.range = range;
            this.w = w;
            this.h = h;
            this.stride = stride;
        }
    }

    /**
     * To represent packed pixel formats with 4 bytes-per-sample.
     */
    public static class RawImage32 extends RawImage {
        public int[] data;

        public RawImage32(byte[] nativeOrderBuffer, int fmt, int cg, int ct, int range, int w,
                int h, int[] data, int stride) {
            super(nativeOrderBuffer, fmt, cg, ct, range, w, h, stride);
            this.data = data;
        }
    }

    /**
     * To represent packed pixel formats with 8 bits-per-sample.
     */
    public static class RawImage8 extends RawImage {
        public byte[] data;

        public RawImage8(byte[] nativeOrderBuffer, int fmt, int cg, int ct, int range, int w, int h,
                byte[] data, int stride) {
            super(nativeOrderBuffer, fmt, cg, ct, range, w, h, stride);
            this.data = data;
        }
    }

    /**
     * To represent packed pixel formats with 8 bytes-per-sample.
     */
    public static class RawImage64 extends RawImage {
        public long[] data;

        public RawImage64(byte[] nativeOrderBuffer, int fmt, int cg, int ct, int range, int w,
                int h, long[] data, int stride) {
            super(nativeOrderBuffer, fmt, cg, ct, range, w, h, stride);
            this.data = data;
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
    public UltraHDRDecoder() throws IOException {
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
     * Enable/Disable GPU acceleration. If enabled, certain operations (if possible) of uhdr
     * decode will be offloaded to GPU.
     * <p>
     * NOTE: It is entirely possible for this API to have no effect on the decode operation
     *
     * @param enable enable/disable gpu acceleration
     * @throws IOException If current decoder instance is not valid or current decoder instance
     *                     is not suitable for configuration exception is thrown.
     */
    public void enableGpuAcceleration(int enable) throws IOException {
        enableGpuAccelerationNative(enable);
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
     * Get base image (compressed)
     *
     * @return A byte array containing the base image data
     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
     *                     process if any errors are seen exception is thrown
     */
    public byte[] getBaseImage() throws IOException {
        return getBaseImageNative();
    }

    /**
     * Get gain map image (compressed)
     *
     * @return A byte array containing the gain map image data
     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
     *                     process if any errors are seen exception is thrown
     */
    public byte[] getGainMapImage() throws IOException {
        return getGainMapImageNative();
    }

    /**
     * Get gain map metadata
     *
     * @return gainmap metadata descriptor
     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
     *                     process if any errors are seen exception is thrown
     */
    public GainMapMetadata getGainmapMetadata() throws IOException {
        getGainmapMetadataNative();
        return new GainMapMetadata(maxContentBoost, minContentBoost, gamma, offsetSdr,
                offsetHdr, hdrCapacityMin, hdrCapacityMax, useBaseColorSpace);
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
    public RawImage getDecodedImage() throws IOException {
        if (decodedDataNativeOrder == null) {
            decodedDataNativeOrder = getDecodedImageNative();
        }
        if (imgFormat == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
            if (decodedDataInt64 == null) {
                ByteBuffer data = ByteBuffer.wrap(decodedDataNativeOrder);
                data.order(ByteOrder.nativeOrder());
                decodedDataInt64 = new long[imgWidth * imgHeight];
                data.asLongBuffer().get(decodedDataInt64);
            }
            return new RawImage64(decodedDataNativeOrder, imgFormat, imgGamut, imgTransfer,
                    imgRange, imgWidth, imgHeight, decodedDataInt64, imgStride);
        } else if (imgFormat == UHDR_IMG_FMT_32bppRGBA8888
                || imgFormat == UHDR_IMG_FMT_32bppRGBA1010102) {
            if (decodedDataInt32 == null) {
                ByteBuffer data = ByteBuffer.wrap(decodedDataNativeOrder);
                data.order(ByteOrder.nativeOrder());
                decodedDataInt32 = new int[imgWidth * imgHeight];
                data.asIntBuffer().get(decodedDataInt32);
            }
            return new RawImage32(decodedDataNativeOrder, imgFormat, imgGamut, imgTransfer,
                    imgRange, imgWidth, imgHeight, decodedDataInt32, imgStride);
        }
        return null;
    }

    /**
     * Get decoded gainmap image data
     *
     * @return Raw image descriptor containing decoded gainmap image data
     * @throws IOException If {@link UltraHDRDecoder#decode()} is not called or decoding process
     *                     is not successful, exception is thrown
     */
    public RawImage getDecodedGainMapImage() throws IOException {
        if (decodedGainMapDataNativeOrder == null) {
            decodedGainMapDataNativeOrder = getDecodedGainMapImageNative();
        }
        if (gainmapFormat == UHDR_IMG_FMT_32bppRGBA8888) {
            if (decodedGainMapDataInt32 == null) {
                ByteBuffer data = ByteBuffer.wrap(decodedGainMapDataNativeOrder);
                data.order(ByteOrder.nativeOrder());
                decodedGainMapDataInt32 = new int[imgWidth * imgHeight];
                data.asIntBuffer().get(decodedGainMapDataInt32);
            }
            return new RawImage32(decodedGainMapDataNativeOrder, imgFormat, imgGamut, imgTransfer,
                    imgRange, imgWidth, imgHeight, decodedGainMapDataInt32, imgStride);
        } else if (imgFormat == UHDR_IMG_FMT_8bppYCbCr400) {
            return new RawImage8(decodedGainMapDataNativeOrder, gainmapFormat, UHDR_CG_UNSPECIFIED,
                    UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, gainmapWidth, gainmapHeight,
                    decodedGainMapDataNativeOrder, gainmapStride);
        }
        return null;
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
        Arrays.fill(maxContentBoost, 1.0f);
        Arrays.fill(minContentBoost, 1.0f);
        Arrays.fill(gamma, 1.0f);
        Arrays.fill(offsetSdr, 0.0f);
        Arrays.fill(offsetHdr, 0.0f);
        hdrCapacityMin = 1.0f;
        hdrCapacityMax = 1.0f;
        useBaseColorSpace = true;

        decodedDataNativeOrder = null;
        decodedDataInt32 = null;
        decodedDataInt64 = null;
        imgWidth = -1;
        imgHeight = -1;
        imgStride = 0;
        imgFormat = UHDR_IMG_FMT_UNSPECIFIED;
        imgGamut = UHDR_CG_UNSPECIFIED;
        imgTransfer = UHDR_CG_UNSPECIFIED;
        imgRange = UHDR_CG_UNSPECIFIED;

        decodedGainMapDataNativeOrder = null;
        decodedGainMapDataInt32 = null;
        gainmapWidth = -1;
        gainmapHeight = -1;
        gainmapStride = 0;
        gainmapFormat = UHDR_IMG_FMT_UNSPECIFIED;
    }

    private static native int isUHDRImageNative(byte[] data, int size) throws IOException;

    private native void init() throws IOException;

    private native void destroy() throws IOException;

    private native void setCompressedImageNative(byte[] data, int size, int colorGamut,
            int colorTransfer, int range) throws IOException;

    private native void setOutputFormatNative(int fmt) throws IOException;

    private native void setColorTransferNative(int ct) throws IOException;

    private native void setMaxDisplayBoostNative(float displayBoost) throws IOException;

    private native void enableGpuAccelerationNative(int enable) throws IOException;

    private native void probeNative() throws IOException;

    private native int getImageWidthNative() throws IOException;

    private native int getImageHeightNative() throws IOException;

    private native int getGainMapWidthNative() throws IOException;

    private native int getGainMapHeightNative() throws IOException;

    private native byte[] getExifNative() throws IOException;

    private native byte[] getIccNative() throws IOException;

    private native byte[] getBaseImageNative() throws IOException;

    private native byte[] getGainMapImageNative() throws IOException;

    private native void getGainmapMetadataNative() throws IOException;

    private native void decodeNative() throws IOException;

    private native byte[] getDecodedImageNative() throws IOException;

    private native byte[] getDecodedGainMapImageNative() throws IOException;

    private native void resetNative() throws IOException;

    /**
     * Decoder handle. Filled by {@link UltraHDRDecoder#init()}
     */
    private long handle;

    /**
     * gainmap metadata fields. Filled by {@link UltraHDRDecoder#getGainmapMetadataNative()}
     */
    private float[] maxContentBoost = new float[3];
    private float[] minContentBoost = new float[3];
    private float[] gamma = new float[3];
    private float[] offsetSdr = new float[3];
    private float[] offsetHdr = new float[3];
    private float hdrCapacityMin;
    private float hdrCapacityMax;
    private boolean useBaseColorSpace;

    /**
     * decoded image fields. Filled by {@link UltraHDRDecoder#getDecodedImageNative()}
     */
    private byte[] decodedDataNativeOrder;
    private int[] decodedDataInt32;
    private long[] decodedDataInt64;
    private int imgWidth;
    private int imgHeight;
    private int imgStride;
    private int imgFormat;
    private int imgGamut;
    private int imgTransfer;
    private int imgRange;

    /**
     * decoded image fields. Filled by {@link UltraHDRDecoder#getDecodedGainMapImageNative()}
     */
    private byte[] decodedGainMapDataNativeOrder;
    private int[] decodedGainMapDataInt32;
    private int gainmapWidth;
    private int gainmapHeight;
    private int gainmapStride;
    private int gainmapFormat;

    static {
        System.loadLibrary("uhdrjni");
    }
}
