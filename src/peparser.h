   /* DESCRIPTION
   The program is designed for 32-bit systems and allows
   searching for information based on the PE signature.
   */

/*
   Structures/macros that will be used predominantly in the program.
   For example, IMAGE DOS HEADER.
   The program is written using Win32API.
   */

/* TYPES
    unsigned short - 16bit
    unsigned long - 32bit
    */

/* DEFINITIONS
    |================================================================================|
    |RAW - Offset relative to the beginning of the file (raw pointer, file offset).	 |
    |RVA - Offset in bytes from the start of the module load in memory (programming).|
    |VA  - RVA on a table that is an array element.									 |
    =================================================================================|
    ==================================================================================================|
    |Sections - Are areas that are unloaded into virtual memory.									  |
    |RawSection - Offset to section from the beginning of the file.								      |
    |RVASection - Section RVA (this field is stored inside the section).						      |
    |SectionAligment - Section alignment. The value can be found in Optional-header.		          |
    |SectionVirtualAddress - RVA of the section - stored directly in the section					  |
    |VA (Virtual address) is an address relative to the beginning of virtual memory,				  |
    |and RVA (Relative Virtual Address) is relative to the location where the program was unloaded.	  |
    ==================================================================================================|
    */

/* FORMULS
    VA = image_base + RVA.
    RAW = RVA - (section_RVA + raw_section).
    */

/* SCHEMES
    EXPORT: NT HEADERS -> OPTIONAL HEADERS -> DATA DIRECTORIES -> EXPORT TABLE.
    IMPORT: NT HEADERS -> OPTIONAL HEADERS -> DATA DIRECTORIES -> IMPORT TABLE.
    */

#ifndef PEPARSER_H
#define PEPARSER_H

#include <QObject>
#include <QString>
#include <QVector>
#include <QDebug>
#include <fstream>
#include <cstdint>
#include <cstring>

#define MZ_MAGIC 0x5A4D
#define NT_OPTIONAL_32_MAGIC 0x10B
#define PE_MAGIC 0x4550
#define DIRECTORY_ENTRY_IMPORT 1
#define DIRECTORY_ENTRY_EXPORT 0
#define NUMBEROF_DIRECTORY_ENTRIES 16

#pragma pack(push, 1)

typedef struct DOS_HEADER {
    std::uint16_t e_magic;         // MZ signature
    std::uint16_t e_cbpl;
    std::uint16_t e_cp;
    std::uint16_t e_crlc;
    std::uint16_t e_cparhdr;
    std::uint16_t e_minalloc;
    std::uint16_t e_maxalloc;
    std::uint16_t e_ss;
    std::uint16_t e_sp;
    std::uint16_t e_csum;
    std::uint16_t e_ip;
    std::uint16_t e_cs;
    std::uint16_t e_lfarlc;
    std::uint16_t e_ovno;
    std::uint16_t e_res[4];
    std::uint16_t e_oemid;
    std::uint16_t e_oeminfo;
    std::uint16_t e_res2[10];
    std::uint32_t e_lfanew;                 // Offset PE header relatively start file. (PE\x0\x0) - default: 0x3C.
} DOS_HEADER;

typedef struct FILE_HEADER {
    std::uint16_t machine;                  // Processor arcitecture.
    std::uint16_t number_of_section;
    std::uint32_t time_date_stamp;
    std::uint32_t pointer_to_symbol_table;  // Offset(raw) to table symbols.
    std::uint32_t number_of_symbols;
    std::uint16_t size_of_optional_header;  // Size table. The table stores debugging information. Most often cleared with zeros.
    std::uint16_t characteristics;
} FILE_HEADER;

typedef struct DATA_DIRECTORY {
    std::uint32_t virtual_addr;             // RVA to the table to which the array element corresponds.
    std::uint32_t size;                     // Size table in bytes.
} DATA_DIRECTORY;

typedef struct OPTIONAL_HEADER {
    std::uint16_t magic;                    // Format (PE32 or PE32+, PE32+ - 64bit)
    std::uint8_t major_linker_version;
    std::uint8_t minor_linker_version;
    std::uint32_t size_of_code;
    std::uint32_t size_of_initialized_data;
    std::uint32_t size_of_uninitialized_data;
    std::uint32_t addr_of_entry_point;          // RVA is the entry point address. It can point to any point in the address space. For .exe files,
                                                // the entry point corresponds to the address from which the program begins execution and cannot be zero.
    std::uint32_t base_of_code;                 // RVA section .code
    std::uint32_t base_of_data;                 // RVA section .data
    std::uint32_t image_base;                   // The preferred base address for loading the program. Must be a multiple of 64 KB. In most cases, this is 0x00400000.
    std::uint32_t section_alignment;            // Alignment size (bytes) of a section when unloaded into virtual memory.
    std::uint32_t file_alignment;               // Alignment size (bytes) of a section inside the file.
    std::uint16_t major_operating_system_version;
    std::uint16_t minor_operating_system_version;
    std::uint16_t major_image_version;
    std::uint16_t minor_image_verison;
    std::uint16_t major_subsystem_version;
    std::uint16_t minor_subsystem_version;
    std::uint32_t win32_version_value;
    std::uint32_t size_of_image;                // The file size (in bytes) in memory, including all headers. The Alignment section should be reduced.
    std::uint32_t size_of_headers;              // The size of all headers(DOS, DOS - Stub, PE, Section) aligned to file_aligment.
    std::uint32_t check_sum;
    std::uint16_t sub_system;
    std::uint16_t dll_characterstics;
    std::uint32_t size_of_stack_reserve;
    std::uint32_t size_of_stack_commit;
    std::uint32_t size_of_heap_reserve;
    std::uint32_t size_of_heap_commit;
    std::uint32_t loader_flags;
    std::uint32_t number_of_rva_and_sizes;      // Number of directories in the directory table.
    DATA_DIRECTORY data_directory[NUMBEROF_DIRECTORY_ENTRIES];
} OPTIONAL_HEADER;

typedef struct SECTION_HEADER {
    unsigned char name[8];                      // Name section (max length-8).
    union {
        std::uint32_t physical_addr;
        std::uint32_t virtual_size;             // Size section in virtual memory.
    } Misc;
    std::uint32_t virtual_addr;                 // RVA address section.
    std::uint32_t size_of_raw_data;             // Size section in file.
    std::uint32_t pointer_to_raw_data;          // RAW offset to the start of the section. Must also be a multiple of FileAligment.
    std::uint32_t pointer_to_relocations;
    std::uint32_t pointer_to_linenumbers;
    std::uint16_t number_of_relocations;
    std::uint16_t number_of_linenumbers;
    std::uint32_t characteristics;              // Access attributes to the section and rules for loading it into virtual memory.
} SECTION_HEADER;

typedef struct NT_HEADERS {
    std::uint32_t signature;
    FILE_HEADER file_header;
    OPTIONAL_HEADER optional_header;
} NT_HEADERS;

typedef struct IMPORT_DESCRIPTOR {
    union {
        std::uint32_t characteristics;
        std::uint32_t original_first_thunk; // RVA of the import name table(INT).
    } DUMMYUNIONNAME;
    std::uint32_t time_date_stamp;
    std::uint32_t forwarder_chain;          // Index of the first forwarded character.
    std::uint32_t name;                     // RVA strings with the library name.
    std::uint32_t first_thunk;              // RVA of the Import Address Table (IAT).
} IMPORT_DESCRIPTOR;

typedef struct THUNK_DATA32 {
    union {
        std::uint32_t forwarder_string;
        std::uint32_t function;
        std::uint32_t ordinal;
        std::uint32_t addr_of_data;
    } ul;
} THUNK_DATA32;

// Export directory
typedef struct EXPORT_DIRECTORY {
    std::uint32_t characteristics;
    std::uint32_t time_date_stamp;
    std::uint16_t major_version;
    std::uint16_t minor_version;
    std::uint32_t name;                     // RVA of the dynamic library name
    std::uint32_t base;
    std::uint32_t number_of_functions;
    std::uint32_t number_of_names;
    std::uint32_t addr_of_functions;        // Table addr of functions.
    std::uint32_t addr_of_names;            // Table name of functions.
    std::uint32_t addr_of_name_ordinals;    // Table name of ordinals.
} EXPORT_DIRECTORY;

#pragma pack(pop)

struct ImportFunction {
    QString name;
    uint16_t hint;
    uint16_t ordinal;
    bool isByName;
};

struct ImportLibrary {
    QString name;
    QVector<ImportFunction> functions;
};

struct ExportFunction {
    QString name;
    uint32_t rva;
    uint16_t ordinal;
    bool hasName;
};

class PEParser : public QObject {
    Q_OBJECT

public:
    explicit PEParser(QObject *parent = nullptr);
    ~PEParser();

    bool parseFile(const QString &filePath);

    DOS_HEADER getDosHeader() const { return dosHeader; }
    NT_HEADERS getNtHeader() const { return ntHeader; }
    QVector<SECTION_HEADER> getSections() const { return sections; }
    QVector<ImportLibrary> getImports() const { return imports; }
    QVector<ExportFunction> getExports() const { return exports; }
    QString getLastError() const { return lastError; }

    QString getMachineTypeString(uint16_t machine);
    QString getCharacteristicsString(uint16_t characteristics);
    QString getSectionCharacteristicsString(uint32_t characteristics);
    QString getSubsystemString(uint16_t subsystem);

private:
    bool readDosHeader();
    bool readNtHeaders();
    bool readSections();
    bool readImportTable();
    bool readExportTable();

    uint32_t rvaToRaw(uint32_t rva);
    QString readStringAtOffset(uint32_t rawOffset);

    std::ifstream file;
    QString currentFilePath;

    DOS_HEADER dosHeader;
    NT_HEADERS ntHeader;
    QVector<SECTION_HEADER> sections;
    QVector<ImportLibrary> imports;
    QVector<ExportFunction> exports;

    QString lastError;
};
#endif // PEPARSER_H
