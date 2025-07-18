#pragma once
#include <cstdint>

#define FAS_MAGIC 0x1A736166 // 'fas' | 0x1a << 24
#define FAS_SYM_STRTAB 0x80000000
#define FAS_SYM_DEFINED 0x0001
#define FAS_SYM_ASMVAR 0x0002
#define FAS_SYM_RLABEL 0x0100
#define FAS_SRC_MACROG 0x80000000
#define FAS_ASM_VIRTUAL 0x0001

struct fasHead {
    uint32_t magic;          // Magic (FAS_MAGIC = 0x1A736166).
    uint8_t major;           // Major version of flat assembler.
    uint8_t minor;           // Minor version of flat assembler.
    uint16_t lHead;          // Size of this header.
    uint32_t oSource;        // Offset of the source file name in the string table.
    uint32_t oOutput;        // Offset of the output file name in the string table.
    uint32_t oStr;           // Offset of the string table (null-terminated strings).
    uint32_t lStr;           // Size of the string table.
    uint32_t oSym;           // Offset of the symbol table (fasSym elements).
    uint32_t lSym;           // Size of the symbol table.
    uint32_t oSrc;           // Offset of the preprocessed source (fasSrc elements and data).
    uint32_t lSrc;           // Size of the preprocessed source.
    uint32_t oAsm;           // Offset of the assembly dump (fasAsm elements and terminating dword).
    uint32_t lAsm;           // Size of the assembly dump (including terminating dword).
    uint32_t oScn;           // Offset of the section table (dwords).
    uint32_t lScn;           // Size of the section table.
    uint32_t oXrefs;         // Offset of the cross-references table.
    uint32_t lXrefs;         // Size of the cross-references table.
};

struct fasSym {
    uint64_t value;          // Value of the symbol.
    uint16_t flags;          // Flags of the symbol.
    uint8_t size;            // Size of data labelled by the symbol.
    uint8_t type;            // Type of the symbol.
    uint8_t sib[4];          // Extended SIB (FAS_REG_*, FAS_REG_*, scale, scale).
    uint16_t passdef;        // Number of pass in which symbol was defined last time.
    uint16_t passusd;        // Number of pass in which symbol was used last time.
    uint32_t rel;            // Section or external symbol, to which the symbol is relative.
    uint32_t name;           // Symbol name offset inside preprocessed source or string table.
    uint32_t src;            // Offset inside preprocessed source of the line which generated this symbol.
};

struct fasSrc {
    uint32_t origin;         // Offset in preprocessed source of the file/macro name.
    uint32_t line;           // Number of this line, FAS_SRC_MACROG indicates macrogenerated line.
    uint32_t src;            // Offset of this line in the source file or macro.
    uint32_t srcm;           // Offset of the preprocessed line inside the definition of macro.
};

struct fasAsm {
    uint32_t outpos;         // Position inside output file.
    uint32_t src;            // Offset of line in preprocessed source.
    uint64_t addr;           // Value of $-address.
    uint8_t sib[4];          // Extended SIB (FAS_REG_*, FAS_REG_*, scale, scale).
    uint32_t rel;            // Section or external symbol, to which the $-address is relative.
    uint8_t type;            // Type of $-address.
    uint8_t bits;            // Type of code (16-bit, 32-bit, 64-bit).
    uint8_t flags;           // Flags (FAS_ASM_*).
    uint8_t addrhi;          // Higher bits of the .addr.
};