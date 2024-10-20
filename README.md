## Introduction

libultrahdr is an image compression library that uses gain map technology
to store and distribute HDR images. Conceptually on the encoding side, the
library accepts SDR and HDR rendition of an image and from these a Gain Map
(quotient between the two renditions) is computed. The library then uses
backward compatible means to store the base image (SDR), gain map image and
some associated metadata. Legacy readers that do not support handling the
gain map image and/or metadata, will display the base image. Readers that
support the format combine the base image with the gain map and render a
high dynamic range image on compatible displays.

For additional information, see android hdr-image-format
[guide](https://developer.android.com/guide/topics/media/platform/hdr-image-format).

## Build from source using CMake

This software suite has been built and tested on platforms:
- Android
- Linux
- macOS
- Windows

Refer to [building.md](docs/building.md) for complete instructions.

## Using libultrahdr

A detailed description of libultrahdr encode and decode api is included in [ultrahdr_api.h](ultrahdr_api.h)
and for sample usage refer [demo app](examples/ultrahdr_app.cpp).

libultrahdr includes two classes of APIs, one to compress and the other to decompress HDR images:

### Encoding api outline:

| Scenario  | Hdr intent raw | Sdr intent raw | Sdr intent compressed | Gain map compressed | Quality |   Exif   | Use Case |
|:---------:| :----------: | :----------: | :---------------------: | :-------------------: | :-------: | :---------: | :-------- |
| API - 0 | P010 or rgba1010102 or rgbaf16 |    No   |  No  |  No  | Optional| Optional | Used if, only hdr raw intent is present. [^1] |
| API - 1 | P010 or rgba1010102 or rgbaf16 | YUV420 or rgba8888 |  No  |  No  | Optional| Optional | Used if, hdr raw and sdr raw intents are present.[^2] |
| API - 2 | P010 or rgba1010102 or rgbaf16 | YUV420 or rgba8888 | Yes  |  No  |    No   |    No    | Used if, hdr raw, sdr raw and sdr compressed intents are present.[^3] |
| API - 3 | P010 or rgba1010102 or rgbaf16 |    No   | Yes  |  No  |    No   |    No    | Used if, hdr raw and sdr compressed intents are present.[^4] |
| API - 4 |  No  |    No   | Yes  | Yes  |    No   |    No    | Used if, sdr compressed, gain map compressed and GainMap Metadata are present.[^5] |

[^1]: Tonemap hdr to sdr. Compute gain map from hdr and sdr. Compress sdr and gainmap at quality configured. Add exif if provided. Combine sdr compressed, gainmap in multi picture format with gainmap metadata.
[^2]: Compute gain map from hdr and sdr. Compress sdr and gainmap at quality configured. Add exif if provided. Combine sdr compressed, gainmap in multi picture format with gainmap metadata.
[^3]: Compute gain map from hdr and raw sdr. Compress gainmap. Combine sdr compressed, gainmap in multi picture format with gainmap metadata.
[^4]: Decode compressed sdr input. Compute gain map from hdr and decoded sdr. Compress gainmap. Combine sdr compressed, gainmap in multi picture format with gainmap metadata.
[^5]: Combine sdr compressed, gainmap in multi picture format with gainmap metadata.

### Decoding api outline:

Configure display device characteristics (display transfer characteristics, max display boost) for optimal usage.

| Input  | Usage |
| ------------- | ------------- |
| max_display_boost  | (optional, >= 1.0) the maximum available boost supported by a display. |
| supported color transfer format pairs  | <table><thead><tr><th>color transfer</th><th>Color format </th></tr></thead><tbody><tr><td>SDR</td><td>32bppRGBA8888</td></tr><tr><td>HDR_LINEAR</td><td>64bppRGBAHalfFloat</td></tr><tr><td>HDR_PQ</td><td>32bppRGBA1010102 PQ</td></tr><tr><td>HDR_HLG</td><td>32bppRGBA1010102 HLG</td></tr></tbody></table> |
