/**
 * @file dosHeader.cpp
 * @brief DOS头解析实现。
 * @author Ch15hu1
 */

#include "peParser.h"
#include <windows.h>
#include <stdexcept>

namespace PEPParser {
void
PeParser::parseDosHeader() {
    if (m_fileData.size() < sizeof(IMAGE_DOS_HEADER))
        throw std::runtime_error("File too small for DOS header");

    m_dosHeaderPtr = m_fileData.data();
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_dosHeaderPtr);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        throw std::runtime_error("Invalid DOS signature (not MZ)");

    /* 计算NT头偏移 */
    uint32_t ntOffset = dos->e_lfanew;
    if (ntOffset + sizeof(uint32_t) > m_fileData.size())
        throw std::runtime_error("NT headers offset out of bounds");

    m_ntHeadersPtr = m_fileData.data() + ntOffset;
}

uint16_t PeParser::getDosMagic() const {
    if (!m_dosHeaderPtr) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_dosHeaderPtr);
    return dos->e_magic;
}

uint32_t PeParser::getNtHeadersOffset() const {
    if (!m_dosHeaderPtr) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_dosHeaderPtr);
    return dos->e_lfanew;
}
} /* namespace PEPParser */