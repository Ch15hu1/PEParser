/**
 * @file main.cpp
 * @brief 使用PEParser库的示例。
 * @author Ch15hu1
 */

#include "peParser.h"
#include <print>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::println(stderr, "Usage: {} <PE file>", argv[0]);
        return 1;
    }

    try {
        PEPParser::PeParser parser(argv[1]);

        std::println("=== PE File Info ===");
        std::println("DOS Magic: 0x{:x}", parser.getDosMagic());
        std::println("NT Headers offset: 0x{:x}", parser.getNtHeadersOffset());
        std::println("Entry point RVA: 0x{:x}", parser.getEntryPointRva());
        std::println("Image base: 0x{:x}", parser.getImageBase());
        std::println("Number of sections: {}", parser.getNumberOfSections());
        std::println("Is 32-bit: {}", (parser.is32Bit() ? "Yes" : "No"));

        std::println("\n=== Sections ===");
        for (const auto& sec : parser.getSections()) {
            std::println("  Name: {}, VA: 0x{:x}, Size: 0x{:x}, Raw: 0x{:x}",
                         sec.name, sec.virtualAddress, sec.virtualSize, sec.rawDataPointer);
        }

        std::println("\n=== Imports ===");
        for (const auto& dll : parser.getImportTable()) {
            std::println("  DLL: {}", dll.name);
            for (const auto& func : dll.functions) {
                if (!func.name.empty())
                    std::println("    Function: {} (hint={})", func.name, func.hint);
                else
                    std::println("    Ordinal: {}", func.hint);
            }
        }

    } catch (const std::exception& e) {
        std::println(stderr, "Error: {}", e.what());
        return 1;
    }
    
    return 0;
}