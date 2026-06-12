/**
 * @file dataDirectories.cpp
 * @brief 数据目录解析（导入表等）。
 * @author Ch15hu1
 */
#include "peParser.h"
#include <windows.h>

namespace PEPParser {

void PeParser::parseImportTable() {
    if (!m_ntHeadersPtr) return;

    /* 定位可选头中的数据目录数组 */
    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        m_ntHeadersPtr + sizeof(uint32_t));
    uint16_t optSize = fileHeader->SizeOfOptionalHeader;
    if (optSize < sizeof(IMAGE_DATA_DIRECTORY)) return;

    const uint8_t* optHeaderBase = m_ntHeadersPtr + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
    const IMAGE_DATA_DIRECTORY* dataDirs = nullptr;
    uint32_t numDataDirs = 0;

    if (m_is32bit) {
        const auto* opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optHeaderBase);
        numDataDirs = opt32->NumberOfRvaAndSizes;
        dataDirs = opt32->DataDirectory;
    } else {
        const auto* opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optHeaderBase);
        numDataDirs = opt64->NumberOfRvaAndSizes;
        dataDirs = opt64->DataDirectory;
    }

    if (numDataDirs <= IMAGE_DIRECTORY_ENTRY_IMPORT) return;
    uint32_t importRva = dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    uint32_t importSize = dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (importRva == 0 || importSize == 0) return;

    uint32_t importOffset = rvaToOffset(importRva);
    if (importOffset == 0) return;

    /* 遍历导入描述符数组（以全零项结束） */
    const IMAGE_IMPORT_DESCRIPTOR* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        m_fileData.data() + importOffset);

    for (; desc->Name != 0; ++desc) {
        ImportedDll dll;
        /* 获取DLL名称 */
        uint32_t nameOffset = rvaToOffset(desc->Name);
        if (nameOffset != 0) {
            dll.name = reinterpret_cast<const char*>(m_fileData.data() + nameOffset);
        }

        dll.originalFirstThunk = desc->OriginalFirstThunk;
        dll.firstThunk = desc->FirstThunk;

        /* 解析导入的函数 */
        uint32_t thunkTableRva = (desc->OriginalFirstThunk != 0) ? desc->OriginalFirstThunk : desc->FirstThunk;
        uint32_t thunkOffset = rvaToOffset(thunkTableRva);
        if (thunkOffset != 0) {
            if (m_is32bit) {
                const uint32_t* thunk = reinterpret_cast<const uint32_t*>(m_fileData.data() + thunkOffset);
                for (; *thunk != 0; ++thunk) {
                    ImportFunction func;
                    if (*thunk & IMAGE_ORDINAL_FLAG32) {
                        func.hint = static_cast<uint16_t>(*thunk & 0xFFFF);
                        func.name.clear(); /* 序号导入 */
                    } else {
                        uint32_t hintNameOffset = rvaToOffset(*thunk);
                        if (hintNameOffset != 0) {
                            const uint16_t* hintPtr = reinterpret_cast<const uint16_t*>(m_fileData.data() + hintNameOffset);
                            func.hint = *hintPtr;
                            const char* namePtr = reinterpret_cast<const char*>(hintPtr + 1);
                            func.name = namePtr;
                        }
                    }
                    dll.functions.push_back(func);
                }
            } else {
                /* 64位处理 */
                const uint64_t* thunk = reinterpret_cast<const uint64_t*>(m_fileData.data() + thunkOffset);
                for (; *thunk != 0; ++thunk) {
                    ImportFunction func;
                    if (*thunk & IMAGE_ORDINAL_FLAG64) {
                        func.hint = static_cast<uint16_t>(*thunk & 0xFFFF);
                        func.name.clear();
                    } else {
                        uint32_t hintNameOffset = rvaToOffset(static_cast<uint32_t>(*thunk));
                        if (hintNameOffset != 0) {
                            const uint16_t* hintPtr = reinterpret_cast<const uint16_t*>(m_fileData.data() + hintNameOffset);
                            func.hint = *hintPtr;
                            const char* namePtr = reinterpret_cast<const char*>(hintPtr + 1);
                            func.name = namePtr;
                        }
                    }
                    dll.functions.push_back(func);
                }
            }
        }

        m_imports.push_back(std::move(dll));
    }
}

const std::vector<ImportedDll>& PeParser::getImportTable() const {
    return m_imports;
}

} /* namespace PEPParser */