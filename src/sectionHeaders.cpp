/**
 * @file sectionHeaders.cpp
 * @brief 节表解析实现。
 * @author Ch15hu1
 */

#include "peParser.h"
#include <windows.h>
#include <cstring>

namespace PEPParser {

void PeParser::parseSectionHeaders() {
    if (!m_ntHeadersPtr) return;

    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        m_ntHeadersPtr + sizeof(uint32_t));
    uint16_t numSections = fileHeader->NumberOfSections;
    if (numSections == 0) return;

    /* 定位第一个节表项 */
    uint32_t optHeaderSize = fileHeader->SizeOfOptionalHeader;
    const uint8_t* sectionBase = m_ntHeadersPtr + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + optHeaderSize;

    m_sections.clear();
    m_sections.reserve(numSections);

    for (uint16_t i = 0; i < numSections; ++i) {
        const auto* rawSec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            sectionBase + i * sizeof(IMAGE_SECTION_HEADER));

        Section sec;
        /* 节名称（最多8字符，非空终止） */
        sec.name.assign(reinterpret_cast<const char*>(rawSec->Name), strnlen(reinterpret_cast<const char*>(rawSec->Name), 8));
        sec.virtualAddress = rawSec->VirtualAddress;
        sec.virtualSize = rawSec->Misc.VirtualSize;
        sec.rawDataPointer = rawSec->PointerToRawData;
        sec.rawDataSize = rawSec->SizeOfRawData;
        sec.characteristics = rawSec->Characteristics;

        /* 读取节数据 */
        if (sec.rawDataPointer != 0 && sec.rawDataSize > 0 &&
            sec.rawDataPointer + sec.rawDataSize <= m_fileData.size()) {
            sec.data.resize(sec.rawDataSize);
            std::memcpy(sec.data.data(), m_fileData.data() + sec.rawDataPointer, sec.rawDataSize);
        }

        m_sections.push_back(std::move(sec));
    }
}

const std::vector<Section>& PeParser::getSections() const {
    return m_sections;
}

const Section* PeParser::getSectionByName(const std::string& name) const {
    for (const auto& sec : m_sections) {
        if (sec.name == name) return &sec;
    }
    return nullptr;
}

uint32_t PeParser::rvaToOffset(uint32_t rva) const {
    for (const auto& sec : m_sections) {
        if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
            uint32_t offsetInSec = rva - sec.virtualAddress;
            if (offsetInSec < sec.rawDataSize) {
                return sec.rawDataPointer + offsetInSec;
            } else {
                /* 这部分在文件中可能不存在（比如.bss节） */
                return 0;
            }
        }
    }
    return 0;
}

} /* namespace PEPParser */