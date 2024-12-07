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

import static com.google.media.codecs.ultrahdr.UltraHDRCommon.*;
import static com.google.media.codecs.ultrahdr.UltraHDREncoder.UHDR_USAGE_BEST_QUALITY;

import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import com.google.media.codecs.ultrahdr.UltraHDRDecoder;
import com.google.media.codecs.ultrahdr.UltraHDREncoder;
import com.google.media.codecs.ultrahdr.UltraHDRDecoder.GainMapMetadata;
import com.google.media.codecs.ultrahdr.UltraHDRDecoder.RawImage;

/**
 * Ultra HDR Encoding/Decoding Demo Application
 */
public class UltraHdrApp {
    private final String mHdrIntentRawFile;
    private final String mSdrIntentRawFile;
    private final String mSdrIntentCompressedFile;
    private final String mGainMapCompressedFile;
    private final String mGainMapMetadaCfgFile;
    private final String mExifFile;
    private final String mUhdrFile;
    private final String mOutputFile;
    private final int mWidth;
    private final int mHeight;
    private final int mHdrCf;
    private final int mSdrCf;
    private final int mHdrCg;
    private final int mSdrCg;
    private final int mHdrTf;
    private final int mQuality;
    private final int mOTF;
    private final int mOfmt;
    private final boolean mFullRange;
    private final int mMapDimensionScaleFactor;
    private final int mMapCompressQuality;
    private final boolean mUseMultiChannelGainMap;
    private final float mGamma;
    private final boolean mEnableGLES;
    private final int mEncPreset;
    private final float mMinContentBoost;
    private final float mMaxContentBoost;
    private final float mTargetDispPeakBrightness;

    byte[] mYuv420YData, mYuv420CbData, mYuv420CrData;
    short[] mP010YData, mP010CbCrData;
    int[] mRgba1010102Data, mRgba8888Data;
    long[] mRgbaF16Data;
    byte[] mCompressedImageData;
    byte[] mGainMapCompressedImageData;
    byte[] mExifData;
    byte[] mUhdrImagedata;
    GainMapMetadata mMetadata;
    RawImage mDecodedUhdrRgbImage;

    public UltraHdrApp(String hdrIntentRawFile, String sdrIntentRawFile,
            String sdrIntentCompressedFile, String gainmapCompressedFile,
            String gainmapMetadataCfgFile, String exifFile, String outputFile, int width,
            int height, int hdrCf, int sdrCf, int hdrCg, int sdrCg, int hdrTf, int quality, int oTf,
            int oFmt, boolean isHdrCrFull, int gainmapScaleFactor, int gainmapQuality,
            boolean enableMultiChannelGainMap, float gamma, int encPreset, float minContentBoost,
            float maxContentBoost, float targetDispPeakBrightness) {
        mHdrIntentRawFile = hdrIntentRawFile;
        mSdrIntentRawFile = sdrIntentRawFile;
        mSdrIntentCompressedFile = sdrIntentCompressedFile;
        mGainMapCompressedFile = gainmapCompressedFile;
        mGainMapMetadaCfgFile = gainmapMetadataCfgFile;
        mExifFile = exifFile;
        mUhdrFile = null;
        mOutputFile = outputFile;
        mWidth = width;
        mHeight = height;
        mHdrCf = hdrCf;
        mSdrCf = sdrCf;
        mHdrCg = hdrCg;
        mSdrCg = sdrCg;
        mHdrTf = hdrTf;
        mQuality = quality;
        mOTF = oTf;
        mOfmt = oFmt;
        mFullRange = isHdrCrFull;
        mMapDimensionScaleFactor = gainmapScaleFactor;
        mMapCompressQuality = gainmapQuality;
        mUseMultiChannelGainMap = enableMultiChannelGainMap;
        mGamma = gamma;
        mEnableGLES = false;
        mEncPreset = encPreset;
        mMinContentBoost = minContentBoost;
        mMaxContentBoost = maxContentBoost;
        mTargetDispPeakBrightness = targetDispPeakBrightness;
    }

    public UltraHdrApp(String gainmapMetadataCfgFile, String uhdrFile, String outputFile, int oTF,
            int oFmt, boolean enableGLES) {
        mHdrIntentRawFile = null;
        mSdrIntentRawFile = null;
        mSdrIntentCompressedFile = null;
        mGainMapCompressedFile = null;
        mGainMapMetadaCfgFile = gainmapMetadataCfgFile;
        mExifFile = null;
        mUhdrFile = uhdrFile;
        mOutputFile = outputFile;
        mWidth = 0;
        mHeight = 0;
        mHdrCf = UHDR_IMG_FMT_UNSPECIFIED;
        mSdrCf = UHDR_IMG_FMT_UNSPECIFIED;
        mHdrCg = UHDR_CG_UNSPECIFIED;
        mSdrCg = UHDR_CG_UNSPECIFIED;
        mHdrTf = UHDR_CT_UNSPECIFIED;
        mQuality = 95;
        mOTF = oTF;
        mOfmt = oFmt;
        mFullRange = false;
        mMapDimensionScaleFactor = 1;
        mMapCompressQuality = 95;
        mUseMultiChannelGainMap = true;
        mGamma = 1.0f;
        mEnableGLES = enableGLES;
        mEncPreset = UHDR_USAGE_BEST_QUALITY;
        mMinContentBoost = Float.MIN_VALUE;
        mMaxContentBoost = Float.MAX_VALUE;
        mTargetDispPeakBrightness = -1.0f;
    }

    public byte[] readFile(String filename) throws IOException {
        byte[] data;
        try (FileInputStream fis = new FileInputStream(filename)) {
            File descriptor = new File(filename);
            long size = descriptor.length();
            if (size <= 0 || size > Integer.MAX_VALUE) {
                throw new IOException("Unexpected file size received for file: " + filename);
            }
            data = new byte[(int) size];
            if (fis.read(data) != size) {
                throw new IOException("Failed to read file: " + filename + " completely");
            }
        }
        return data;
    }

    public void fillP010ImageHandle() throws IOException {
        final int bpp = 2;
        final int lumaSampleCount = mWidth * mHeight;
        final int chromaSampleCount = (mWidth / 2) * (mHeight / 2) * 2;
        final int expectedSize = (lumaSampleCount + chromaSampleCount) * bpp;
        byte[] data = readFile(mHdrIntentRawFile);
        if (data.length < expectedSize) {
            throw new RuntimeException(
                    "For the configured width, height, P010 Image File is expected to contain "
                            + expectedSize + " bytes, but the file has " + data.length + " bytes");
        }
        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
        byteBuffer.order(ByteOrder.nativeOrder());
        mP010YData = new short[lumaSampleCount];
        byteBuffer.asShortBuffer().get(mP010YData);
        byteBuffer.position(lumaSampleCount * bpp);
        mP010CbCrData = new short[chromaSampleCount];
        byteBuffer.asShortBuffer().get(mP010CbCrData);
    }

    public void fillRGBA1010102ImageHandle() throws IOException {
        final int bpp = 4;
        final int rgbSampleCount = mHeight * mWidth;
        final int expectedSize = rgbSampleCount * bpp;
        byte[] data = readFile(mHdrIntentRawFile);
        if (data.length < expectedSize) {
            throw new RuntimeException("For the configured width, height, RGBA1010102 Image File is"
                    + " expected to contain " + expectedSize + " bytes, but the file has "
                    + data.length + " bytes");
        }
        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
        byteBuffer.order(ByteOrder.nativeOrder());
        mRgba1010102Data = new int[mHeight * mWidth];
        byteBuffer.asIntBuffer().get(mRgba1010102Data);
    }

    public void fillRGBAF16ImageHandle() throws IOException {
        final int bpp = 8;
        final int rgbSampleCount = mHeight * mWidth;
        final int expectedSize = rgbSampleCount * bpp;
        byte[] data = readFile(mHdrIntentRawFile);
        if (data.length < expectedSize) {
            throw new RuntimeException("For the configured width, height, RGBA1010102 Image File is"
                    + " expected to contain " + expectedSize + " bytes, but the file has "
                    + data.length + " bytes");
        }
        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
        byteBuffer.order(ByteOrder.nativeOrder());
        mRgbaF16Data = new long[mHeight * mWidth];
        byteBuffer.asLongBuffer().get(mRgbaF16Data);
    }

    public void fillRGBA8888Handle() throws IOException {
        final int bpp = 4;
        final int rgbSampleCount = mHeight * mWidth;
        final int expectedSize = rgbSampleCount * bpp;
        byte[] data = readFile(mSdrIntentRawFile);
        if (data.length < expectedSize) {
            throw new RuntimeException("For the configured width, height, RGBA8888 Image File is"
                    + " expected to contain " + expectedSize + " bytes, but the file has "
                    + data.length + " bytes");
        }
        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
        byteBuffer.order(ByteOrder.nativeOrder());
        mRgba8888Data = new int[mHeight * mWidth];
        byteBuffer.asIntBuffer().get(mRgba8888Data);
    }

    public void fillYUV420ImageHandle() throws IOException {
        final int lumaSampleCount = mWidth * mHeight;
        final int cbSampleCount = (mWidth / 2) * (mHeight / 2);
        final int crSampleCount = (mWidth / 2) * (mHeight / 2);
        try (FileInputStream fis = new FileInputStream(mSdrIntentRawFile)) {
            mYuv420YData = new byte[lumaSampleCount];
            int bytesRead = fis.read(mYuv420YData);
            if (bytesRead != lumaSampleCount) {
                throw new IOException("Failed to read " + lumaSampleCount + " bytes from file: "
                        + mSdrIntentRawFile);
            }
            mYuv420CbData = new byte[cbSampleCount];
            bytesRead = fis.read(mYuv420CbData);
            if (bytesRead != cbSampleCount) {
                throw new IOException("Failed to read " + cbSampleCount + " bytes from file: "
                        + mSdrIntentRawFile);
            }
            mYuv420CrData = new byte[crSampleCount];
            bytesRead = fis.read(mYuv420CrData);
            if (bytesRead != crSampleCount) {
                throw new IOException("Failed to read " + crSampleCount + " bytes from file: "
                        + mSdrIntentRawFile);
            }
        }
    }

    public void fillSdrCompressedImageHandle() throws IOException {
        mCompressedImageData = readFile(mSdrIntentCompressedFile);
    }

    public void fillGainMapCompressedImageHandle() throws IOException {
        mGainMapCompressedImageData = readFile(mGainMapCompressedFile);
    }

    public void fillExifMemoryBlock() throws IOException {
        mExifData = readFile(mExifFile);
    }

    public void fillUhdrImageHandle() throws IOException {
        mUhdrImagedata = readFile(mUhdrFile);
    }

    public void fillGainMapMetadataDescriptor() throws IOException {
        mMetadata = new GainMapMetadata();
        try (BufferedReader reader = new BufferedReader(new FileReader(mGainMapMetadaCfgFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\s+");
                if (parts.length >= 2 && parts[0].startsWith("--")) {
                    String option = parts[0].substring(2); // remove the "--" prefix
                    float[] values = new float[3];
                    int count = Math.min(parts.length - 1, 3);
                    if (count != 1 && count != 3) {
                        System.err.println("ignoring line: " + line);
                        continue;
                    }
                    for (int i = 0; i < count; i++) {
                        values[i] = Float.parseFloat(parts[i + 1]);
                    }
                    if (count == 1) {
                        values[1] = values[2] = values[0];
                    }
                    switch (option) {
                        case "maxContentBoost":
                            System.arraycopy(values, 0, mMetadata.maxContentBoost, 0, 3);
                            break;
                        case "minContentBoost":
                            System.arraycopy(values, 0, mMetadata.minContentBoost, 0, 3);
                            break;
                        case "gamma":
                            System.arraycopy(values, 0, mMetadata.gamma, 0, 3);
                            break;
                        case "offsetSdr":
                            System.arraycopy(values, 0, mMetadata.offsetSdr, 0, 3);
                            break;
                        case "offsetHdr":
                            System.arraycopy(values, 0, mMetadata.offsetHdr, 0, 3);
                            break;
                        case "hdrCapacityMin":
                            mMetadata.hdrCapacityMin = values[0];
                            break;
                        case "hdrCapacityMax":
                            mMetadata.hdrCapacityMax = values[0];
                            break;
                        case "useBaseColorSpace":
                            mMetadata.useBaseColorSpace = values[0] != 0.0f;
                            break;
                        default:
                            System.err.println("ignoring option: " + option);
                            break;
                    }
                } else {
                    System.err.println("Unable to parse line : " + line);
                }
            }
        }
    }

    public void writeGainMapMetadataToFile(GainMapMetadata metadata) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(mGainMapMetadaCfgFile))) {
            boolean allChannelsIdentical =
                    metadata.maxContentBoost[0] == metadata.maxContentBoost[1]
                            && metadata.maxContentBoost[0] == metadata.maxContentBoost[2]
                            && metadata.minContentBoost[0] == metadata.minContentBoost[1]
                            && metadata.minContentBoost[0] == metadata.minContentBoost[2]
                            && metadata.gamma[0] == metadata.gamma[1]
                            && metadata.gamma[0] == metadata.gamma[2]
                            && metadata.offsetSdr[0] == metadata.offsetSdr[1]
                            && metadata.offsetSdr[0] == metadata.offsetSdr[2]
                            && metadata.offsetHdr[0] == metadata.offsetHdr[1]
                            && metadata.offsetHdr[0] == metadata.offsetHdr[2];
            if (allChannelsIdentical) {
                writer.write("--maxContentBoost " + metadata.maxContentBoost[0] + "\n");
                writer.write("--minContentBoost " + metadata.minContentBoost[0] + "\n");
                writer.write("--gamma " + metadata.gamma[0] + "\n");
                writer.write("--offsetSdr " + metadata.offsetSdr[0] + "\n");
                writer.write("--offsetHdr " + metadata.offsetHdr[0] + "\n");
            } else {
                writer.write("--maxContentBoost " + metadata.maxContentBoost[0] + " "
                        + metadata.maxContentBoost[1] + " " + metadata.maxContentBoost[2] + "\n");
                writer.write("--minContentBoost " + metadata.minContentBoost[0] + " "
                        + metadata.minContentBoost[1] + " " + metadata.minContentBoost[2] + "\n");
                writer.write("--gamma " + metadata.gamma[0] + " " + metadata.gamma[1] + " "
                        + metadata.gamma[2] + "\n");
                writer.write(
                        "--offsetSdr " + metadata.offsetSdr[0] + " " + metadata.offsetSdr[1] + " "
                                + metadata.offsetSdr[2] + "\n");
                writer.write(
                        "--offsetHdr " + metadata.offsetHdr[0] + " " + metadata.offsetHdr[1] + " "
                                + metadata.offsetHdr[2] + "\n");
            }
            writer.write("--hdrCapacityMin " + metadata.hdrCapacityMin + "\n");
            writer.write("--hdrCapacityMax " + metadata.hdrCapacityMax + "\n");
            writer.write("--useBaseColorSpace " + (metadata.useBaseColorSpace ? "1" : "0") + "\n");
        }
    }

    public void writeFile(String fileName, RawImage img) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            if (img.fmt == UHDR_IMG_FMT_32bppRGBA8888 || img.fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat
                    || img.fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
                byte[] data = img.nativeOrderBuffer;
                int bpp = img.fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
                int stride = img.stride * bpp;
                int length = img.w * bpp;
                for (int i = 0; i < img.h; i++) {
                    fos.write(data, i * stride, length);
                }
            } else {
                throw new RuntimeException("Unsupported color format ");
            }
        }
    }

    public void writeFile(String fileName, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(data);
        }
    }

    public void encode() throws Exception {
        try (UltraHDREncoder handle = new UltraHDREncoder()) {
            if (mHdrIntentRawFile != null) {
                if (mHdrCf == UHDR_IMG_FMT_24bppYCbCrP010) {
                    fillP010ImageHandle();
                    handle.setRawImage(mP010YData, mP010CbCrData, mWidth, mHeight, mWidth, mWidth,
                            mHdrCg, mHdrTf, mFullRange ? UHDR_CR_FULL_RANGE : UHDR_CR_LIMITED_RANGE,
                            mHdrCf, UHDR_HDR_IMG);
                } else if (mHdrCf == UHDR_IMG_FMT_32bppRGBA1010102) {
                    fillRGBA1010102ImageHandle();
                    handle.setRawImage(mRgba1010102Data, mWidth, mHeight, mWidth, mHdrCg, mHdrTf,
                            UHDR_CR_FULL_RANGE, mHdrCf, UHDR_HDR_IMG);
                } else if (mHdrCf == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
                    fillRGBAF16ImageHandle();
                    handle.setRawImage(mRgbaF16Data, mWidth, mHeight, mWidth, mHdrCg, mHdrTf,
                            UHDR_CR_FULL_RANGE, mHdrCf, UHDR_HDR_IMG);
                } else {
                    throw new IllegalArgumentException("invalid hdr intent color format " + mHdrCf);
                }
            }
            if (mSdrIntentRawFile != null) {
                if (mSdrCf == UHDR_IMG_FMT_12bppYCbCr420) {
                    fillYUV420ImageHandle();
                    handle.setRawImage(mYuv420YData, mYuv420CbData, mYuv420CrData, mWidth, mHeight,
                            mWidth, mWidth / 2, mWidth / 2, mSdrCg, UHDR_CT_SRGB,
                            UHDR_CR_FULL_RANGE, mSdrCf, UHDR_SDR_IMG);
                } else if (mSdrCf == UHDR_IMG_FMT_32bppRGBA8888) {
                    fillRGBA8888Handle();
                    handle.setRawImage(mRgba8888Data, mWidth, mHeight, mWidth, mSdrCg, UHDR_CT_SRGB,
                            UHDR_CR_FULL_RANGE, mSdrCf, UHDR_SDR_IMG);
                } else {
                    throw new IllegalArgumentException("invalid sdr intent color format " + mSdrCf);
                }
            }
            if (mSdrIntentCompressedFile != null) {
                fillSdrCompressedImageHandle();
                handle.setCompressedImage(mCompressedImageData, mCompressedImageData.length, mSdrCg,
                        UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED,
                        (mGainMapCompressedFile != null && mGainMapMetadaCfgFile != null) ?
                                UHDR_BASE_IMG : UHDR_SDR_IMG);
            }
            if (mGainMapCompressedFile != null && mGainMapMetadaCfgFile != null) {
                fillGainMapCompressedImageHandle();
                fillGainMapMetadataDescriptor();
                handle.setGainMapImageInfo(mGainMapCompressedImageData,
                        mGainMapCompressedImageData.length, mMetadata.maxContentBoost,
                        mMetadata.minContentBoost, mMetadata.gamma, mMetadata.offsetSdr,
                        mMetadata.offsetHdr, mMetadata.hdrCapacityMin, mMetadata.hdrCapacityMax,
                        mMetadata.useBaseColorSpace);
            }
            if (mExifFile != null) {
                fillExifMemoryBlock();
                handle.setExifData(mExifData, mExifData.length);
            }
            handle.setQualityFactor(mQuality, UHDR_BASE_IMG);
            handle.setQualityFactor(mMapCompressQuality, UHDR_GAIN_MAP_IMG);
            handle.setMultiChannelGainMapEncoding(mUseMultiChannelGainMap);
            handle.setGainMapScaleFactor(mMapDimensionScaleFactor);
            handle.setGainMapGamma(mGamma);
            handle.setEncPreset(mEncPreset);
            if (mMinContentBoost != Float.MIN_VALUE || mMaxContentBoost != Float.MAX_VALUE) {
                handle.setMinMaxContentBoost(mMinContentBoost, mMaxContentBoost);
            }
            if (mTargetDispPeakBrightness != -1.0f) {
                handle.setTargetDisplayPeakBrightness(mTargetDispPeakBrightness);
            }
            handle.encode();
            mUhdrImagedata = handle.getOutput();
            writeFile(mOutputFile, mUhdrImagedata);
        }
    }

    public void decode() throws Exception {
        fillUhdrImageHandle();
        try (UltraHDRDecoder handle = new UltraHDRDecoder()) {
            handle.setCompressedImage(mUhdrImagedata, mUhdrImagedata.length, UHDR_CG_UNSPECIFIED,
                    UHDR_CG_UNSPECIFIED, UHDR_CR_UNSPECIFIED);
            handle.setColorTransfer(mOTF);
            handle.setOutputFormat(mOfmt);
            if (mEnableGLES) {
                handle.enableGpuAcceleration(mEnableGLES ? 1 : 0);
            }
            handle.probe();
            if (mGainMapMetadaCfgFile != null) {
                GainMapMetadata metadata = handle.getGainmapMetadata();
                writeGainMapMetadataToFile(metadata);
            }
            handle.decode();
            mDecodedUhdrRgbImage = handle.getDecodedImage();
            writeFile(mOutputFile, mDecodedUhdrRgbImage);
        }
    }

    public static void usage() {
        System.out.println("\n## uhdr demo application. lib version: " + getVersionString());
        System.out.println("Usage : java -Djava.library.path=<path> -jar uhdr-java.jar");
        System.out.println("    -m    mode of operation. [0:encode, 1:decode]");
        System.out.println("\n## encoder options :");
        System.out.println("    -p    raw hdr intent input resource (10-bit), required for encoding"
                + " scenarios 0, 1, 2, 3.");
        System.out.println("    -y    raw sdr intent input resource (8-bit), required for encoding"
                + " scenarios 1, 2.");
        System.out.println("    -a    raw hdr intent color format, optional. [0:p010, "
                + "4: rgbahalffloat, 5:rgba1010102 (default)]");
        System.out.println("    -b    raw sdr intent color format, optional. [1:yuv420, 3:rgba8888"
                + " (default)]");
        System.out.println("    -i    compressed sdr intent input resource (jpeg), required for "
                + "encoding scenarios 2, 3, 4.");
        System.out.println("    -g    compressed gainmap input resource (jpeg), required for "
                + "encoding scenario 4.");
        System.out.println(
                "    -w    input file width, required for encoding scenarios 0, 1, 2, 3.");
        System.out.println(
                "    -h    input file height, required for encoding scenarios 0, 1, 2, 3.");
        System.out.println(
                "    -C    hdr intent color gamut, optional. [0:bt709, 1:p3 (default), 2:bt2100]");
        System.out.println(
                "    -c    sdr intent color gamut, optional. [0:bt709 (default), 1:p3, 2:bt2100]");
        System.out.println(
                "    -t    hdr intent color transfer, optional. [0:linear, 1:hlg (default), 2:pq]");
        System.out.println(
                "          It should be noted that not all combinations of input color format and"
                        + " input color transfer are supported.");
        System.out.println(
                "          srgb color transfer shall be paired with rgba8888 or yuv420 only.");
        System.out.println("          hlg, pq shall be paired with rgba1010102 or p010.");
        System.out.println("          linear shall be paired with rgbahalffloat.");
        System.out.println("    -q    quality factor to be used while encoding sdr intent, "
                + "optional. [0-100], 95 : default.");
        System.out.println("    -R    color range of hdr intent, optional. [0:narrow-range "
                + "(default), 1:full-range].");
        System.out.println("    -s    gainmap image downsample factor, optional. [integer values"
                + " in range [1 - 128] (1 : default)].");
        System.out.println("    -Q    quality factor to be used while encoding gain map image,"
                + " optional. [0-100], 95 : default.");
        System.out.println("    -G    gamma correction to be applied on the gainmap image, "
                + "optional. [any positive real number (1.0 : default)].");
        System.out.println("    -M    select multi channel gain map, optional. [0:disable, "
                + " 1:enable (default)].");
        System.out.println("    -D    select encoding preset, optional. [0:real time,"
                + " 1:best quality (default)].");
        System.out.println("    -k    min content boost recommendation, must be in linear scale,"
                + " optional. any positive real number");
        System.out.println("    -K    max content boost recommendation, must be in linear scale,"
                + " optional. any positive real number");
        System.out.println("    -L    set target display peak brightness in nits, optional");
        System.out.println("          For HLG content, this defaults to 1000 nits.");
        System.out.println("          For PQ content, this defaults to 10000 nits.");
        System.out.println("          any real number in range [203, 10000].");
        System.out.println("    -x    binary input resource containing exif data to insert, "
                + "optional.");
        System.out.println("\n## decoder options :");
        System.out.println("    -j    ultra hdr compressed input resource, required.");
        System.out.println("    -o    output transfer function, optional. [0:linear,"
                + " 1:hlg (default), 2:pq, 3:srgb]");
        System.out.println("    -O    output color format, optional. [3:rgba8888, 4:rgbahalffloat, "
                + "5:rgba1010102 (default)]");
        System.out.println("          It should be noted that not all combinations of output color"
                + " format and output");
        System.out.println("          transfer function are supported.");
        System.out.println(
                "          srgb output color transfer shall be paired with rgba8888 only.");
        System.out.println("          hlg, pq shall be paired with rgba1010102.");
        System.out.println("          linear shall be paired with rgbahalffloat.");
        System.out.println(
                "    -u    enable gles acceleration, optional. [0:disable (default), 1:enable].");
        System.out.println("\n## common options :");
        System.out.println("    -z    output filename, optional.");
        System.out.println("          in encoding mode, default output filename 'out.jpeg'.");
        System.out.println("          in decoding mode, default output filename 'outrgb.raw'.");
        System.out.println("    -f    gainmap metadata config file.");
        System.out.println("          in encoding mode, resource from which gainmap metadata is "
                + "read, required for encoding scenario 4.");
        System.out.println("          in decoding mode, resource to which gainmap metadata is "
                + "written, optional.");
        System.out.println("\n## examples of usage :");
        System.out.println("\n## encode scenario 0 :");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_p010.yuv -w 1920 -h 1080 -q 97 -a 0");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_rgba1010102.raw -w  1920 -h 1080 -q 97 -a 5");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_p010.yuv -w 1920 -h 1080 -q 97 -C 1 -t 2 -a 0");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_rgba1010102.raw -w 1920 -h 1080 -q 97 -C 1 -t 2 -a 5");
        System.out.println("\n## encode scenario 1 :");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 -h 1080 -q 97 "
                + "-a 0 -b 1");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_rgba1010102.raw -y cosmat_1920x1080_rgba8888.raw -w 1920 -h "
                + "1080 -q 97 -a 5 -b 3");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 -h 1080 -q 97 -C"
                + " 2 -c 1 -t 1 -a 0 -b 1");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_rgba1010102.raw -y cosmat_1920x1080_rgba8888.raw -w 1920 "
                + "-h 1080 -q 97 -C 2 -c 1 -t 1 -a 5 -b 3");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 -h 1080 -q 97 -C"
                + " 2 -c 1 -t 1 -a 0 -b 1");
        System.out.println("\n## encode scenario 2 :");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -i "
                + "cosmat_1920x1080_420_8bit.jpg -w 1920 -h 1080 -t 1 -o 3 -O 3 -a 0 -b 1");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_rgba1010102.raw -y cosmat_1920x1080_420.yuv -i "
                + "cosmat_1920x1080_420_8bit.jpg -w 1920 -h 1080 -t 1 -o 3 -O 3 -a 5 -b 1");
        System.out.println("\n## encode scenario 3 :");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_p010.yuv -i cosmat_1920x1080_420_8bit.jpg -w 1920 -h 1080 -t "
                + "1 -o 1 -O 5 -a 0");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "cosmat_1920x1080_rgba1010102.raw -i cosmat_1920x1080_420_8bit.jpg -w 1920 -h "
                + "1080 -t 1 -o 1 -O 5 -a 5");
        System.out.println("\n## encode scenario 4 :");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -i "
                + "cosmat_1920x1080_420_8bit.jpg -g cosmat_1920x1080_420_8bit.jpg -f metadata.cfg");
        System.out.println("\n## encode at high quality :");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
                + "hdr_intent.raw -y sdr_intent.raw -w 640 -h 480 -c <select> -C <select> -t "
                + "<select> -s 1 -M 1 -Q 98 -q 98 -D 1");
        System.out.println("\n## decode api :");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 1 "
                + "-j cosmat_1920x1080_hdr.jpg");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 1 -j "
                + "cosmat_1920x1080_hdr.jpg -o 3 -O 3");
        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 1 -j "
                + "cosmat_1920x1080_hdr.jpg -o 1 -O 5");
        System.out.println("\n");
    }

    public static void main(String[] args) throws Exception {
        String hdr_intent_raw_file = null;
        String sdr_intent_raw_file = null;
        String sdr_intent_compressed_file = null;
        String gainmap_compressed_file = null;
        String uhdr_file = null;
        String gainmap_metadata_cfg_file = null;
        String output_file = null;
        String exif_file = null;
        int width = 0, height = 0;
        int hdr_cg = UHDR_CG_DISPLAY_P3;
        int sdr_cg = UHDR_CG_BT709;
        int hdr_cf = UHDR_IMG_FMT_32bppRGBA1010102;
        int sdr_cf = UHDR_IMG_FMT_32bppRGBA8888;
        int hdr_tf = UHDR_CT_HLG;
        int quality = 95;
        int out_tf = UHDR_CT_HLG;
        int out_cf = UHDR_IMG_FMT_32bppRGBA1010102;
        int mode = -1;
        int gain_map_scale_factor = 1;
        int gainmap_compression_quality = 95;
        int enc_preset = UHDR_USAGE_BEST_QUALITY;
        float gamma = 1.0f;
        boolean enable_gles = false;
        float min_content_boost = Float.MIN_VALUE;
        float max_content_boost = Float.MAX_VALUE;
        float target_disp_max_brightness = -1.0f;
        boolean use_full_range_color_hdr = false;
        boolean use_multi_channel_gainmap = true;

        for (int i = 0; i < args.length; i++) {
            if (args[i].length() == 2 && args[i].charAt(0) == '-') {
                switch (args[i].charAt(1)) {
                    case 'a':
                        hdr_cf = Integer.parseInt(args[++i]);
                        break;
                    case 'b':
                        sdr_cf = Integer.parseInt(args[++i]);
                        break;
                    case 'p':
                        hdr_intent_raw_file = args[++i];
                        break;
                    case 'y':
                        sdr_intent_raw_file = args[++i];
                        break;
                    case 'i':
                        sdr_intent_compressed_file = args[++i];
                        break;
                    case 'g':
                        gainmap_compressed_file = args[++i];
                        break;
                    case 'f':
                        gainmap_metadata_cfg_file = args[++i];
                        break;
                    case 'w':
                        width = Integer.parseInt(args[++i]);
                        break;
                    case 'h':
                        height = Integer.parseInt(args[++i]);
                        break;
                    case 'C':
                        hdr_cg = Integer.parseInt(args[++i]);
                        break;
                    case 'c':
                        sdr_cg = Integer.parseInt(args[++i]);
                        break;
                    case 't':
                        hdr_tf = Integer.parseInt(args[++i]);
                        break;
                    case 'q':
                        quality = Integer.parseInt(args[++i]);
                        break;
                    case 'O':
                        out_cf = Integer.parseInt(args[++i]);
                        break;
                    case 'o':
                        out_tf = Integer.parseInt(args[++i]);
                        break;
                    case 'm':
                        mode = Integer.parseInt(args[++i]);
                        break;
                    case 'R':
                        use_full_range_color_hdr = Integer.parseInt(args[++i]) == 1;
                        break;
                    case 's':
                        gain_map_scale_factor = Integer.parseInt(args[++i]);
                        break;
                    case 'M':
                        use_multi_channel_gainmap = Integer.parseInt(args[++i]) == 1;
                        break;
                    case 'Q':
                        gainmap_compression_quality = Integer.parseInt(args[++i]);
                        break;
                    case 'G':
                        gamma = Float.parseFloat(args[++i]);
                        break;
                    case 'j':
                        uhdr_file = args[++i];
                        break;
                    case 'z':
                        output_file = args[++i];
                        break;
                    case 'x':
                        exif_file = args[++i];
                        break;
                    case 'u':
                        enable_gles = Integer.parseInt(args[++i]) == 1;
                        break;
                    case 'D':
                        enc_preset = Integer.parseInt(args[++i]);
                        break;
                    case 'k':
                        min_content_boost = Float.parseFloat(args[++i]);
                        break;
                    case 'K':
                        max_content_boost = Float.parseFloat(args[++i]);
                        break;
                    case 'L':
                        target_disp_max_brightness = Float.parseFloat(args[++i]);
                        break;
                    default:
                        System.err.println("Unrecognized option, arg: " + args[i]);
                        usage();
                        return;
                }
            } else {
                System.err.println("Invalid argument format, arg: " + args[i]);
                usage();
                return;
            }
        }
        if (mode == 0) {
            if (width <= 0 && gainmap_metadata_cfg_file == null) {
                System.err.println("did not receive valid image width for encoding. width : "
                        + width);
                return;
            }
            if (height <= 0 && gainmap_metadata_cfg_file == null) {
                System.err.println("did not receive valid image height for encoding. height : "
                        + height);
                return;
            }
            if (hdr_intent_raw_file == null && (sdr_intent_compressed_file == null
                    || gainmap_compressed_file == null || gainmap_metadata_cfg_file == null)) {
                System.err.println("did not receive raw resources for encoding.");
                return;
            }
            UltraHdrApp appInput = new UltraHdrApp(hdr_intent_raw_file, sdr_intent_raw_file,
                    sdr_intent_compressed_file, gainmap_compressed_file, gainmap_metadata_cfg_file,
                    exif_file, output_file != null ? output_file : "out.jpeg", width, height,
                    hdr_cf, sdr_cf, hdr_cg, sdr_cg, hdr_tf, quality, out_tf, out_cf,
                    use_full_range_color_hdr, gain_map_scale_factor, gainmap_compression_quality,
                    use_multi_channel_gainmap, gamma, enc_preset, min_content_boost,
                    max_content_boost, target_disp_max_brightness);
            appInput.encode();
        } else if (mode == 1) {
            if (uhdr_file == null) {
                System.err.println("did not receive resources for decoding");
                return;
            }
            UltraHdrApp appInput = new UltraHdrApp(gainmap_metadata_cfg_file, uhdr_file,
                    output_file != null ? output_file : "outrgb.raw", out_tf, out_cf, enable_gles);
            appInput.decode();
        } else {
            if (args.length > 0) {
                System.err.println("did not receive valid mode of operation");
            }
            usage();
        }
    }
}
