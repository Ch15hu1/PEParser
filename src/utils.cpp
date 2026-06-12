/**
 * @file utils.cpp
 * @brief PE文件解析器的核心实现。
 * @author Ch15hu1
 */

#include "peParser.h"
#include <fstream>
#include <stdexcept>

namespace PEPParser {

bool PeParser::isValidPeFile() const {
    return (m_dosHeaderPtr != nullptr && m_ntHeadersPtr != nullptr);
}

bool PeParser::is32Bit() const {
    return m_is32bit;
}

bool PeParser::is64Bit() const {
    return !m_is32bit;
}

void PeParser::loadFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
        throw std::runtime_error("Cannot open file: " + filePath);

    std::streamsize size = file.tellg();
    if (size <= 0)
        throw std::runtime_error("File is empty");

    file.seekg(0, std::ios::beg);
    m_fileData.resize(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(m_fileData.data()), size))
        throw std::runtime_error("Failed to read file");
}

PeParser::PeParser(const std::string& filePath) {
    loadFile(filePath);
    parseDosHeader();
    parseNtHeaders();
    parseSectionHeaders();
    parseImportTable();
}

PeParser::~PeParser() = default;

} /* namespace PEPParser */