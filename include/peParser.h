/**
 * @file peParser.h
 * @brief PE文件解析器的公共接口。
 * @author Ch15hu1
 */

#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <cstdint>
#include <string>
#include <vector>

namespace PEPParser {   /* 注意：你原注释中写了 PEPParser，保持一致性 */

/**
 * @brief 表示PE文件中的一个节（Section）。
 */
struct Section {
    std::string name;               ///< 节名称（如 .text）
    uint32_t virtualAddress;        ///< 虚拟地址（RVA）
    uint32_t virtualSize;           ///< 虚拟大小
    uint32_t rawDataPointer;        ///< 文件中的原始数据指针
    uint32_t rawDataSize;           ///< 原始数据大小
    uint32_t characteristics;       ///< 节属性标志
    std::vector<uint8_t> data;      ///< 节的实际数据（从文件中读取）
};

/**
 * @brief 导入表中的一个函数。
 */
struct ImportFunction {
    uint16_t hint;          ///< 提示索引
    std::string name;       ///< 函数名称（按序号导入时名称为空）
    uint64_t address;       ///< 导入地址表中的地址（仅内存模式）
};

/**
 * @brief 一个导入的DLL及其函数列表。
 */
struct ImportedDll {
    std::string name;                       ///< DLL名称
    std::vector<ImportFunction> functions;  ///< 导入的函数列表
    uint32_t originalFirstThunk;            ///< INT表RVA
    uint32_t firstThunk;                    ///< IAT表RVA
};

/**
 * @brief PE解析器的主类。
 * @details 负责加载、解析并提供对PE文件各组件（DOS头、NT头、节表、导入表等）的访问。
 */
class PeParser {
public:
    /**
     * @brief 构造函数，从文件路径加载PE文件。
     * @param filePath PE文件的路径。
     * @throws std::runtime_error 如果文件无效或解析失败。
     */
    explicit PeParser(const std::string& filePath);

    /**
     * @brief 析构函数，释放内部资源。
     */
    ~PeParser();

    /* ---- 基本校验 ---- */
    bool isValidPeFile() const;      /* 是否为有效的PE文件 */
    bool is32Bit() const;            /* 是否为32位PE */
    bool is64Bit() const;            /* 是否为64位PE */

    /* ---- 头信息访问 ---- */
    uint16_t getDosMagic() const;            /* DOS头的MZ签名 */
    uint32_t getNtHeadersOffset() const;     /* NT头在文件中的偏移 */
    uint32_t getEntryPointRva() const;       /* 入口点RVA */
    uint64_t getImageBase() const;           /* 镜像基址（32/64自适应） */
    uint16_t getNumberOfSections() const;    /* 节的数量 */

    /* ---- 节表相关 ---- */
    const std::vector<Section>& getSections() const;   /* 获取所有节的列表 */
    const Section* getSectionByName(const std::string& name) const; /* 按名称查找节 */

    /* ---- 导入表相关 ---- */
    const std::vector<ImportedDll>& getImportTable() const;   /* 获取导入表 */

    /* ---- 实用工具 ---- */
    uint32_t rvaToOffset(uint32_t rva) const;   /* 将RVA转换为文件偏移 */

private:
    /* 内部初始化与解析 */
    void loadFile(const std::string& filePath);
    void parseDosHeader();
    void parseNtHeaders();
    void parseSectionHeaders();
    void parseImportTable();

    /* 原始文件数据 */
    std::vector<uint8_t> m_fileData;            ///< 整个PE文件的二进制数据

    /* 头指针（指向m_fileData中的位置） */
    const uint8_t* m_dosHeaderPtr = nullptr;    ///< DOS头起始
    const uint8_t* m_ntHeadersPtr = nullptr;    ///< NT头起始
    bool m_is32bit = true;                      ///< 默认32位

    /* 解析结果 */
    std::vector<Section> m_sections;
    std::vector<ImportedDll> m_imports;
};

} /* namespace PEPParser */

#endif /* PE_PARSER_H */