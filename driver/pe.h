#pragma once

#include <stdint.h>
#include <stdbool.h>

#define IMAGE_DOS_SIGNATURE 0x5A4D     // MZ
#define IMAGE_NT_SIGNATURE  0x00004550 // PE00

#define IMAGE_FILE_MACHINE_IA64  0x0200
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_I386  0x014c

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_EXPORT     0
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5
#define IMAGE_DIRECTORY_ENTRY_TLS        9

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x010b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x020b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC  0x0107

#define IMAGE_SCN_CNT_CODE    0x00000020
#define IMAGE_SCN_MEM_EXECUTE 0x20000000

#define IMAGE_SIZEOF_SHORT_NAME 8

struct DOSHeader {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct NTHeaders64 {
    uint32_t Signature;
    // -- IMAGE_FILE_HEADER FileHeader;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
    // -- IMAGE_OPTIONAL_HEADER OptionalHeader;
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    struct DataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct SectionHeader {
    uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
