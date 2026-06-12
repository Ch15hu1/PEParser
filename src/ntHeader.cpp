/**
 * @file ntHeader.cpp
 * @brief NT头解析实现。
 * @author Ch15hu1
 */

#include "peParser.h"
#include <windows.h>
#include <stdexcept>

namespace PEPParser {
  void 
  PeParser::parseNtHeaders() {
    if (!m_ntHeadersPtr) throw std::runtime_error("NT headers not located");
    /* 检查PE签名 */
    uint32_t signature = *reinterpret_cast<const uint32_t*>(m_ntHeadersPtr);
    if (signature != IMAGE_NT_SIGNATURE)
        throw std::runtime_error("Invalid PE signature");

    /* 判断是32位还是64位 */
    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        m_ntHeadersPtr + sizeof(uint32_t));
    uint16_t magic = 0;
    if (fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
        const auto* opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
            m_ntHeadersPtr + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER));
        magic = opt32->Magic;
    }

    m_is32bit = (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    /* 注意：也可以直接从可选头魔数判断，这里简化 */
}

uint32_t 
PeParser::getEntryPointRva() const {
  if (!m_ntHeadersPtr) return 0;
  const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
    m_ntHeadersPtr + sizeof(uint32_t));
    uint16_t optSize = fileHeader->SizeOfOptionalHeader;
    if (optSize == 0) return 0;

    if (m_is32bit) {
        const auto* opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(m_ntHeadersPtr + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER));
        return opt32->AddressOfEntryPoint;
    } else {
      const auto* opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
      m_ntHeadersPtr + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER));

      return static_cast<uint32_t>(opt64->AddressOfEntryPoint);
  }
}

uint64_t PeParser::getImageBase() const {
    if (!m_ntHeadersPtr) return 0;
    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        m_ntHeadersPtr + sizeof(uint32_t));
    uint16_t optSize = fileHeader->SizeOfOptionalHeader;
    if (optSize == 0) return 0;

    if (m_is32bit) {
        const auto* opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
            m_ntHeadersPtr + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER));
        return opt32->ImageBase;
    } else {
        const auto* opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
            m_ntHeadersPtr + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER));
        return opt64->ImageBase;
    }
}

uint16_t PeParser::getNumberOfSections() const {
    if (!m_ntHeadersPtr) return 0;
    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        m_ntHeadersPtr + sizeof(uint32_t));
    return fileHeader->NumberOfSections;
}

} /* namespace PEPParser */