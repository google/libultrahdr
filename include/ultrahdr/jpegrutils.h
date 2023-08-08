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

#ifndef ANDROID_ULTRAHDR_JPEGRUTILS_H
#define ANDROID_ULTRAHDR_JPEGRUTILS_H

#include <ultrahdr/jpegr.h>
#include <utils/RefBase.h>

#include <sstream>
#include <stdint.h>
#include <string>
#include <cstdio>

namespace android::ultrahdr {

static constexpr uint32_t EndianSwap32(uint32_t value) {
    return ((value & 0xFF) << 24) |
           ((value & 0xFF00) << 8) |
           ((value & 0xFF0000) >> 8) |
           (value >> 24);
}
static inline uint16_t EndianSwap16(uint16_t value) {
    return static_cast<uint16_t>((value >> 8) | ((value & 0xFF) << 8));
}

#if USE_BIG_ENDIAN
    #define Endian_SwapBE32(n) EndianSwap32(n)
    #define Endian_SwapBE16(n) EndianSwap16(n)
#else
    #define Endian_SwapBE32(n) (n)
    #define Endian_SwapBE16(n) (n)
#endif

struct ultrahdr_metadata_struct;
/*
 * Mutable data structure. Holds information for metadata.
 */
class DataStruct : public RefBase {
private:
    void* data;
    int writePos;
    int length;
    ~DataStruct();

public:
    DataStruct(int s);
    void* getData();
    int getLength();
    int getBytesWritten();
    bool write8(uint8_t value);
    bool write16(uint16_t value);
    bool write32(uint32_t value);
    bool write(const void* src, int size);
};

/*
 * Helper function used for writing data to destination.
 *
 * @param destination destination of the data to be written.
 * @param source source of data being written.
 * @param length length of the data to be written.
 * @param position cursor in desitination where the data is to be written.
 * @return status of succeed or error code.
 */
status_t Write(jr_compressed_ptr destination, const void* source, size_t length, int &position);


/*
 * Parses XMP packet and fills metadata with data from XMP
 *
 * @param xmp_data pointer to XMP packet
 * @param xmp_size size of XMP packet
 * @param metadata place to store HDR metadata values
 * @return true if metadata is successfully retrieved, false otherwise
*/
bool getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size, ultrahdr_metadata_struct* metadata);

/*
 * This method generates XMP metadata for the primary image.
 *
 * below is an example of the XMP metadata that this function generates where
 * secondary_image_length = 1000
 *
 * <x:xmpmeta
 *   xmlns:x="adobe:ns:meta/"
 *   x:xmptk="Adobe XMP Core 5.1.2">
 *   <rdf:RDF
 *     xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
 *     <rdf:Description
 *       xmlns:Container="http://ns.google.com/photos/1.0/container/"
 *       xmlns:Item="http://ns.google.com/photos/1.0/container/item/"
 *       xmlns:hdrgm="http://ns.adobe.com/hdr-gain-map/1.0/"
 *       hdrgm:Version="1">
 *       <Container:Directory>
 *         <rdf:Seq>
 *           <rdf:li
 *             rdf:parseType="Resource">
 *             <Container:Item
 *               Item:Semantic="Primary"
 *               Item:Mime="image/jpeg"/>
 *           </rdf:li>
 *           <rdf:li
 *             rdf:parseType="Resource">
 *             <Container:Item
 *               Item:Semantic="GainMap"
 *               Item:Mime="image/jpeg"
 *               Item:Length="1000"/>
 *           </rdf:li>
 *         </rdf:Seq>
 *       </Container:Directory>
 *     </rdf:Description>
 *   </rdf:RDF>
 * </x:xmpmeta>
 *
 * @param secondary_image_length length of secondary image
 * @return XMP metadata in type of string
 */
std::string generateXmpForPrimaryImage(int secondary_image_length,
                                       ultrahdr_metadata_struct& metadata);

/*
 * This method generates XMP metadata for the recovery map image.
 *
 * below is an example of the XMP metadata that this function generates where
 * max_content_boost = 8.0
 * min_content_boost = 0.5
 *
 * <x:xmpmeta
 *   xmlns:x="adobe:ns:meta/"
 *   x:xmptk="Adobe XMP Core 5.1.2">
 *   <rdf:RDF
 *     xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
 *     <rdf:Description
 *       xmlns:hdrgm="http://ns.adobe.com/hdr-gain-map/1.0/"
 *       hdrgm:Version="1"
 *       hdrgm:GainMapMin="-1"
 *       hdrgm:GainMapMax="3"
 *       hdrgm:Gamma="1"
 *       hdrgm:OffsetSDR="0"
 *       hdrgm:OffsetHDR="0"
 *       hdrgm:HDRCapacityMin="0"
 *       hdrgm:HDRCapacityMax="3"
 *       hdrgm:BaseRenditionIsHDR="False"/>
 *   </rdf:RDF>
 * </x:xmpmeta>
 *
 * @param metadata JPEG/R metadata to encode as XMP
 * @return XMP metadata in type of string
 */
 std::string generateXmpForSecondaryImage(ultrahdr_metadata_struct& metadata);
}  // namespace android::ultrahdr

#endif //ANDROID_ULTRAHDR_JPEGRUTILS_H
