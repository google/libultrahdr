/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

import static com.google.media.codecs.ultrahdr.UltraHDRCommon.*;

import com.google.media.codecs.ultrahdr.UltraHDRCommon;
import com.google.media.codecs.ultrahdr.UltraHDRDecoder;
import com.google.media.codecs.ultrahdr.UltraHDRDecoder.GainMapMetadata;
import com.google.media.codecs.ultrahdr.UltraHDRDecoder.RawImage;
import com.google.media.codecs.ultrahdr.UltraHDRDecoder.RawImage32;
import com.google.media.codecs.ultrahdr.UltraHDRDecoder.RawImage64;
import com.google.media.codecs.ultrahdr.UltraHDRDecoder.RawImage8;
import com.google.media.codecs.ultrahdr.UltraHDREncoder;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Regression and security bounds tests for libultrahdr JNI bindings and Java wrappers.
 */
public class UltraHdrJniTest {

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Throwable;
    }

    private static void assertTrue(boolean cond, String message) {
        if (!cond) {
            throw new AssertionError("Assertion failed: " + message);
        }
    }

    private static void assertEquals(long expected, long actual, String message) {
        if (expected != actual) {
            throw new AssertionError(
                    message + " (expected=" + expected + ", actual=" + actual + ")");
        }
    }

    private static IOException assertThrowsIOException(ThrowingRunnable action, String context) {
        try {
            action.run();
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getTargetException();
            if (cause instanceof IOException) {
                return (IOException) cause;
            }
            throw new AssertionError(
                    context + ": expected IOException, got " + cause, cause);
        } catch (IOException ioe) {
            return ioe;
        } catch (Throwable t) {
            throw new AssertionError(
                    context + ": expected IOException, got " + t, t);
        }
        throw new AssertionError(context + ": expected IOException, but call succeeded");
    }

    private static long getNativeHandle(Object instance) throws Exception {
        Field field = instance.getClass().getDeclaredField("handle");
        field.setAccessible(true);
        return field.getLong(instance);
    }

    private static short floatToHalf(float f) {
        int bits = Float.floatToIntBits(f);
        int sign = (bits >>> 16) & 0x8000;
        int exp = ((bits >>> 23) & 0xFF) - (127 - 15);
        int mantissa = bits & 0x007FFFFF;
        if (exp <= 0) {
            return (short) sign;
        }
        if (exp >= 31) {
            return (short) (sign | 0x7C00);
        }
        return (short) (sign | (exp << 10) | (mantissa >>> 13));
    }

    private static long packRgbaF16(float r, float g, float b, float a) {
        long hr = floatToHalf(r) & 0xFFFFL;
        long hg = floatToHalf(g) & 0xFFFFL;
        long hb = floatToHalf(b) & 0xFFFFL;
        long ha = floatToHalf(a) & 0xFFFFL;
        return hr | (hg << 16) | (hb << 32) | (ha << 48);
    }

    private static void testHandleReleasedOnClose() throws Exception {
        UltraHDREncoder encoder = new UltraHDREncoder();
        assertTrue(getNativeHandle(encoder) != 0L, "encoder handle should be non-zero after init");
        encoder.close();
        assertEquals(0L, getNativeHandle(encoder), "encoder handle must be cleared on close()");
        encoder.close(); // idempotent second close
        assertThrowsIOException(encoder::reset, "reset() after encoder close()");

        UltraHDRDecoder decoder = new UltraHDRDecoder();
        assertTrue(getNativeHandle(decoder) != 0L, "decoder handle should be non-zero after init");
        decoder.close();
        assertEquals(0L, getNativeHandle(decoder), "decoder handle must be cleared on close()");
        decoder.close(); // idempotent second close
        assertThrowsIOException(decoder::reset, "reset() after decoder close()");
    }

    private static void testRawImageArraySizeChecks() throws Exception {
        final int w = 8;
        final int h = 8;

        // 1. int[] (RGBA8888 / RGBA1010102): tight, padded, 1-below, and 32-bit overflow
        try (UltraHDREncoder enc = new UltraHDREncoder()) {
            enc.setRawImage(new int[w * h], w, h, w, UHDR_CG_BT709, UHDR_CT_SRGB,
                    UHDR_CR_FULL_RANGE, UHDR_IMG_FMT_32bppRGBA8888, UHDR_SDR_IMG);
            enc.setRawImage(new int[(w + 4) * h], w, h, w + 4, UHDR_CG_BT709, UHDR_CT_SRGB,
                    UHDR_CR_FULL_RANGE, UHDR_IMG_FMT_32bppRGBA8888, UHDR_SDR_IMG);

            assertThrowsIOException(() -> enc.setRawImage(new int[w * h - 1], w, h, w,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_32bppRGBA8888, UHDR_SDR_IMG), "int[] tight 1-below");
            assertThrowsIOException(() -> enc.setRawImage(new int[(w + 4) * h - 1], w, h, w + 4,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_32bppRGBA8888, UHDR_SDR_IMG), "int[] padded 1-below");

            // 4096 * 524289 overflows signed 32-bit int to -2147479552
            assertThrowsIOException(() -> enc.setRawImage(new int[16], 16, 4096, 524289,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_32bppRGBA8888, UHDR_SDR_IMG), "int[] 32-bit stride*height wrap");
        }

        // 2. long[] (RGBAHalfFloat): tight, padded, 1-below, and 32-bit overflow
        try (UltraHDREncoder enc = new UltraHDREncoder()) {
            enc.setRawImage(new long[w * h], w, h, w, UHDR_CG_BT709, UHDR_CT_LINEAR,
                    UHDR_CR_FULL_RANGE, UHDR_IMG_FMT_64bppRGBAHalfFloat, UHDR_HDR_IMG);
            enc.setRawImage(new long[(w + 6) * h], w, h, w + 6, UHDR_CG_BT709, UHDR_CT_LINEAR,
                    UHDR_CR_FULL_RANGE, UHDR_IMG_FMT_64bppRGBAHalfFloat, UHDR_HDR_IMG);

            assertThrowsIOException(() -> enc.setRawImage(new long[w * h - 1], w, h, w,
                    UHDR_CG_BT709, UHDR_CT_LINEAR, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_64bppRGBAHalfFloat, UHDR_HDR_IMG), "long[] tight 1-below");
            assertThrowsIOException(() -> enc.setRawImage(new long[16], 16, 4096, 524289,
                    UHDR_CG_BT709, UHDR_CT_LINEAR, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_64bppRGBAHalfFloat, UHDR_HDR_IMG),
                    "long[] 32-bit stride*height wrap");
        }

        // 3. short[] (P010): tight, padded, 1-below on Y and UV separately, and 32-bit overflow
        try (UltraHDREncoder enc = new UltraHDREncoder()) {
            final int yTight = w * h;
            final int uvTight = (h / 2) * w;
            enc.setRawImage(new short[yTight], new short[uvTight], w, h, w, w,
                    UHDR_CG_BT2100, UHDR_CT_HLG, UHDR_CR_LIMITED_RANGE,
                    UHDR_IMG_FMT_24bppYCbCrP010, UHDR_HDR_IMG);
            enc.setRawImage(new short[(w + 8) * h], new short[(h / 2) * (w + 8)], w, h,
                    w + 8, w + 8, UHDR_CG_BT2100, UHDR_CT_HLG, UHDR_CR_LIMITED_RANGE,
                    UHDR_IMG_FMT_24bppYCbCrP010, UHDR_HDR_IMG);

            assertThrowsIOException(() -> enc.setRawImage(new short[yTight - 1], new short[uvTight],
                    w, h, w, w, UHDR_CG_BT2100, UHDR_CT_HLG, UHDR_CR_LIMITED_RANGE,
                    UHDR_IMG_FMT_24bppYCbCrP010, UHDR_HDR_IMG), "P010 Y 1-below");
            assertThrowsIOException(() -> enc.setRawImage(new short[yTight], new short[uvTight - 1],
                    w, h, w, w, UHDR_CG_BT2100, UHDR_CT_HLG, UHDR_CR_LIMITED_RANGE,
                    UHDR_IMG_FMT_24bppYCbCrP010, UHDR_HDR_IMG), "P010 UV 1-below");
            assertThrowsIOException(() -> enc.setRawImage(new short[16], new short[16],
                    16, 4096, 524289, 16, UHDR_CG_BT2100, UHDR_CT_HLG, UHDR_CR_LIMITED_RANGE,
                    UHDR_IMG_FMT_24bppYCbCrP010, UHDR_HDR_IMG), "P010 Y 32-bit overflow");
            assertThrowsIOException(() -> enc.setRawImage(new short[16 * 64], new short[16],
                    16, 64, 16, 67108865, UHDR_CG_BT2100, UHDR_CT_HLG, UHDR_CR_LIMITED_RANGE,
                    UHDR_IMG_FMT_24bppYCbCrP010, UHDR_HDR_IMG), "P010 UV 32-bit overflow");
        }

        // 4. byte[] (YCbCr420): tight, padded, half-sized/1-below on Y, U, V separately, overflow
        try (UltraHDREncoder enc = new UltraHDREncoder()) {
            final int ySize = w * h;
            final int cStride = w / 2;
            final int cSize = (h / 2) * cStride;
            enc.setRawImage(new byte[ySize], new byte[cSize], new byte[cSize], w, h, w,
                    cStride, cStride, UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_12bppYCbCr420, UHDR_SDR_IMG);
            enc.setRawImage(new byte[(w + 4) * h], new byte[(h / 2) * (cStride + 4)],
                    new byte[(h / 2) * (cStride + 6)], w, h, w + 4, cStride + 4, cStride + 6,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_12bppYCbCr420, UHDR_SDR_IMG);

            assertThrowsIOException(() -> enc.setRawImage(new byte[ySize - 1], new byte[cSize],
                    new byte[cSize], w, h, w, cStride, cStride, UHDR_CG_BT709, UHDR_CT_SRGB,
                    UHDR_CR_FULL_RANGE, UHDR_IMG_FMT_12bppYCbCr420, UHDR_SDR_IMG),
                    "YCbCr420 Y 1-below");
            IOException uEx = assertThrowsIOException(() -> enc.setRawImage(new byte[ySize],
                    new byte[cSize - 1], new byte[cSize], w, h, w, cStride, cStride,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_12bppYCbCr420, UHDR_SDR_IMG), "YCbCr420 U 1-below");
            assertTrue(uEx.getMessage().contains("cb"), "U error message should mention cb");

            IOException vEx = assertThrowsIOException(() -> enc.setRawImage(new byte[ySize],
                    new byte[cSize], new byte[cSize - 1], w, h, w, cStride, cStride,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_12bppYCbCr420, UHDR_SDR_IMG), "YCbCr420 V 1-below");
            assertTrue(vEx.getMessage().contains("cr"), "V error message should mention cr");

            // Regression for the old height * stride / 4 bug (half-sized chroma buffers)
            assertThrowsIOException(() -> enc.setRawImage(new byte[ySize], new byte[cSize / 2],
                    new byte[cSize], w, h, w, cStride, cStride, UHDR_CG_BT709, UHDR_CT_SRGB,
                    UHDR_CR_FULL_RANGE, UHDR_IMG_FMT_12bppYCbCr420, UHDR_SDR_IMG),
                    "YCbCr420 half-size U buffer");
            assertThrowsIOException(() -> enc.setRawImage(new byte[ySize], new byte[cSize],
                    new byte[cSize / 2], w, h, w, cStride, cStride, UHDR_CG_BT709, UHDR_CT_SRGB,
                    UHDR_CR_FULL_RANGE, UHDR_IMG_FMT_12bppYCbCr420, UHDR_SDR_IMG),
                    "YCbCr420 half-size V buffer");

            // 32-bit overflow on U and V strides
            assertThrowsIOException(() -> enc.setRawImage(new byte[16 * 64], new byte[16],
                    new byte[32 * 8], 16, 64, 16, 67108865, 8, UHDR_CG_BT709, UHDR_CT_SRGB,
                    UHDR_CR_FULL_RANGE, UHDR_IMG_FMT_12bppYCbCr420, UHDR_SDR_IMG),
                    "YCbCr420 U 32-bit overflow");
            assertThrowsIOException(() -> enc.setRawImage(new byte[16 * 64], new byte[32 * 8],
                    new byte[16], 16, 64, 16, 8, 67108865, UHDR_CG_BT709, UHDR_CT_SRGB,
                    UHDR_CR_FULL_RANGE, UHDR_IMG_FMT_12bppYCbCr420, UHDR_SDR_IMG),
                    "YCbCr420 V 32-bit overflow");
        }
    }

    private static void testNativeBoundaryGuardsViaReflection() throws Exception {
        Method setRawInt = UltraHDREncoder.class.getDeclaredMethod("setRawImageNative",
                int[].class, int.class, int.class, int.class, int.class, int.class, int.class,
                int.class, int.class);
        setRawInt.setAccessible(true);

        Method setRawYuv = UltraHDREncoder.class.getDeclaredMethod("setRawImageNative",
                byte[].class, byte[].class, byte[].class, int.class, int.class, int.class,
                int.class, int.class, int.class, int.class, int.class, int.class, int.class);
        setRawYuv.setAccessible(true);

        Method setCompEnc = UltraHDREncoder.class.getDeclaredMethod("setCompressedImageNative",
                byte[].class, int.class, int.class, int.class, int.class, int.class);
        setCompEnc.setAccessible(true);

        Method isUhdrNative = UltraHDRDecoder.class.getDeclaredMethod("isUHDRImageNative",
                byte[].class, int.class);
        isUhdrNative.setAccessible(true);

        try (UltraHDREncoder enc = new UltraHDREncoder()) {
            // Null buffer, negative dimensions, and negative stride (-1 previously wrapped to 4G)
            assertThrowsIOException(() -> setRawInt.invoke(enc, null, 8, 8, 8,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_32bppRGBA8888, UHDR_SDR_IMG), "native null int[]");
            assertThrowsIOException(() -> setRawInt.invoke(enc, new int[64], 8, -1, 8,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_32bppRGBA8888, UHDR_SDR_IMG), "native negative height");
            assertThrowsIOException(() -> setRawInt.invoke(enc, new int[64], 8, 8, -1,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_32bppRGBA8888, UHDR_SDR_IMG), "native negative rgbStride");

            // Odd height (h=7 -> ceil(7/2)=4 chroma rows) with only 3 chroma rows must fail size
            IOException oddEx = assertThrowsIOException(() -> setRawYuv.invoke(enc,
                    new byte[8 * 7], new byte[4 * 3], new byte[4 * 4], 8, 7, 8, 4, 4,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_12bppYCbCr420, UHDR_SDR_IMG), "native odd-height U ceiling");
            assertTrue(oddEx.getMessage().contains("less than required size"),
                    "odd-height chroma ceiling check must trigger in JNI");

            // Compressed image null & non-positive size checks
            assertThrowsIOException(() -> setCompEnc.invoke(enc, null, 4,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE, UHDR_BASE_IMG),
                    "native null compressed byte[]");
            assertThrowsIOException(() -> setCompEnc.invoke(enc, new byte[4], 0,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE, UHDR_BASE_IMG),
                    "native zero compressed size");
            assertThrowsIOException(() -> setCompEnc.invoke(enc, new byte[4], -1,
                    UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE, UHDR_BASE_IMG),
                    "native negative compressed size");

            // setGainMapImageInfo invalid float[] metadata validation (must not leak pinned data)
            float[] ok3 = new float[]{1.0f, 1.0f, 1.0f};
            float[] bad2 = new float[]{1.0f, 1.0f};
            assertThrowsIOException(() -> enc.setGainMapImageInfo(new byte[16], 16, null, ok3,
                    ok3, ok3, ok3, 1.0f, 2.0f, true), "null maxContentBoost");
            assertThrowsIOException(() -> enc.setGainMapImageInfo(new byte[16], 16, ok3, ok3,
                    bad2, ok3, ok3, 1.0f, 2.0f, true), "2-element gainmapGamma");
        }

        assertThrowsIOException(() -> isUhdrNative.invoke(null, null, 4),
                "isUHDRImageNative null byte[]");
        assertThrowsIOException(() -> isUhdrNative.invoke(null, new byte[4], -1),
                "isUHDRImageNative negative size");
    }

    private static void testEndToEndEncodeAndDecodeGainMaps(boolean multiChannel)
            throws Exception {
        final int w = 16;
        final int h = 16;
        final int scale = 4;
        long[] hdr = new long[w * h];
        int[] sdr = new int[w * h];
        for (int i = 0; i < w * h; i++) {
            float v = (i % w) / (float) (w - 1);
            hdr[i] = packRgbaF16(v * 2.0f, v * 1.5f, v, 1.0f);
            int c = Math.min(255, Math.round(v * 200.0f));
            sdr[i] = c | (c << 8) | (c << 16) | (0xFF << 24);
        }

        byte[] encoded;
        try (UltraHDREncoder enc = new UltraHDREncoder()) {
            enc.setRawImage(hdr, w, h, w, UHDR_CG_BT709, UHDR_CT_LINEAR, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_64bppRGBAHalfFloat, UHDR_HDR_IMG);
            enc.setRawImage(sdr, w, h, w, UHDR_CG_BT709, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE,
                    UHDR_IMG_FMT_32bppRGBA8888, UHDR_SDR_IMG);
            enc.setGainMapScaleFactor(scale);
            enc.setMultiChannelGainMapEncoding(multiChannel);
            enc.encode();
            encoded = enc.getOutput();
        }
        assertTrue(encoded != null && encoded.length > 0, "encoded JPEG/R must be non-empty");
        assertTrue(UltraHDRDecoder.isUHDRImage(encoded, encoded.length), "isUHDRImage must be true");

        try (UltraHDRDecoder dec = new UltraHDRDecoder()) {
            dec.setCompressedImage(encoded, encoded.length, UHDR_CG_UNSPECIFIED,
                    UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED);
            dec.setOutputFormat(UHDR_IMG_FMT_64bppRGBAHalfFloat);
            dec.setColorTransfer(UHDR_CT_LINEAR);
            dec.probe();

            assertEquals(w, dec.getImageWidth(), "probed width");
            assertEquals(h, dec.getImageHeight(), "probed height");
            assertEquals(w / scale, dec.getGainMapWidth(), "probed gainmap width");
            assertEquals(h / scale, dec.getGainMapHeight(), "probed gainmap height");
            assertTrue(dec.getBaseImage().length > 0, "base image bytes");
            assertTrue(dec.getGainMapImage().length > 0, "gainmap image bytes");
            GainMapMetadata meta = dec.getGainmapMetadata();
            assertTrue(meta != null && meta.maxContentBoost.length == 3, "gainmap metadata");

            dec.decode();

            // Fetch gainmap image BEFORE getDecodedImage() to verify independent field population
            RawImage gm = dec.getDecodedGainMapImage();
            assertTrue(gm != null, "decoded gainmap must not be null (multiChannel=" + multiChannel
                    + ")");
            assertEquals(w / scale, gm.w, "decoded gainmap width");
            assertEquals(h / scale, gm.h, "decoded gainmap height");
            if (multiChannel) {
                assertEquals(UHDR_IMG_FMT_32bppRGBA8888, gm.fmt, "3ch gainmap format");
                assertTrue(gm instanceof RawImage32, "3ch gainmap RawImage32");
                assertEquals((long) gm.stride * gm.h, ((RawImage32) gm).data.length,
                        "3ch gainmap int[] length");
            } else {
                assertEquals(UHDR_IMG_FMT_8bppYCbCr400, gm.fmt, "1ch gainmap format");
                assertTrue(gm instanceof RawImage8, "1ch gainmap RawImage8");
                assertEquals((long) gm.stride * gm.h, ((RawImage8) gm).data.length,
                        "1ch gainmap byte[] length");
            }

            RawImage img = dec.getDecodedImage();
            assertTrue(img instanceof RawImage64, "decoded HDR image must be RawImage64");
            assertEquals(w, img.w, "decoded image width");
            assertEquals(h, img.h, "decoded image height");
            assertEquals((long) img.stride * img.h, ((RawImage64) img).data.length,
                    "decoded image long[] length");
        }
    }

    public static void main(String[] args) throws Exception {
        assertTrue(UltraHDRCommon.getVersion() > 0, "version must be positive");
        assertTrue(UltraHDRCommon.getVersionString().startsWith("v"), "version string prefix");

        testHandleReleasedOnClose();
        testRawImageArraySizeChecks();
        testNativeBoundaryGuardsViaReflection();
        testEndToEndEncodeAndDecodeGainMaps(true);
        testEndToEndEncodeAndDecodeGainMaps(false);

        System.out.println("All UltraHdrJniTest cases passed.");
    }
}
