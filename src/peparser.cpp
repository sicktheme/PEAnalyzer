#include "peparser.h"
#include <QFileInfo>

PEParser::PEParser(QObject *parent) : QObject(parent) {
    memset(&dosHeader, 0, sizeof(DOS_HEADER));
    memset(&ntHeader, 0, sizeof(NT_HEADERS));
}

PEParser::~PEParser() {
    if (file.is_open()) {
        file.close();
    }
}

uint32_t PEParser::rvaToRaw(uint32_t rva) {
    for (int i = 0; i < sections.size(); i++) {
        uint32_t section_start = sections[i].virtual_addr;
        uint32_t section_end = section_start + sections[i].Misc.virtual_size;

        if (rva >= section_start && rva < section_end) {
            uint32_t offset = rva - section_start;
            return sections[i].pointer_to_raw_data + offset;
        }
    }
    return 0;
}

QString PEParser::readStringAtOffset(uint32_t rawOffset) {
    QString result;
    char c;

    std::streampos current_pos = file.tellg();
    file.seekg(rawOffset, std::ios::beg);

    while (file.get(c) && c != '\0') {
        result += c;
    }

    file.seekg(current_pos);
    return result;
}

bool PEParser::readDosHeader() {
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(DOS_HEADER));

    if (!file) {
        lastError = "Failed to read DOS header";
        return false;
    }

    if (dosHeader.e_magic != MZ_MAGIC) {
        lastError = "Invalid DOS signature (not MZ)";
        return false;
    }

    return true;
}

bool PEParser::readNtHeaders() {
    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    file.read(reinterpret_cast<char*>(&ntHeader), sizeof(NT_HEADERS));

    if (!file) {
        lastError = "Failed to read NT headers";
        return false;
    }

    if (ntHeader.signature != PE_MAGIC) {
        lastError = "Invalid PE signature";
        return false;
    }

    if (ntHeader.optional_header.magic != NT_OPTIONAL_32_MAGIC) {
        lastError = "Only 32-bit PE files are supported";
        return false;
    }

    return true;
}

bool PEParser::readSections() {
    int sectionOffset = dosHeader.e_lfanew + sizeof(uint32_t) +
                        sizeof(FILE_HEADER) + ntHeader.file_header.size_of_optional_header;

    file.seekg(sectionOffset, std::ios::beg);

    int numSections = ntHeader.file_header.number_of_section;
    sections.clear();

    for (int i = 0; i < numSections; i++) {
        SECTION_HEADER section;
        memset(&section, 0, sizeof(SECTION_HEADER));

        file.read(reinterpret_cast<char*>(&section), sizeof(SECTION_HEADER));

        if (!file) {
            lastError = QString("Failed to read section %1").arg(i + 1);
            return false;
        }
        sections.append(section);
    }
    return true;
}

bool PEParser::readImportTable() {
    uint32_t importRva = ntHeader.optional_header.data_directory[DIRECTORY_ENTRY_IMPORT].virtual_addr;
    uint32_t importSize = ntHeader.optional_header.data_directory[DIRECTORY_ENTRY_IMPORT].size;

    if (importRva == 0 || importSize == 0) {
        return true;
    }

    uint32_t importRaw = rvaToRaw(importRva);
    if (importRaw == 0) {
        lastError = "Failed to locate import table";
        return false;
    }

    imports.clear();
    uint32_t currentOffset = 0;

    while (true) {
        file.seekg(importRaw + currentOffset, std::ios::beg);
        IMPORT_DESCRIPTOR importDesc;
        file.read(reinterpret_cast<char*>(&importDesc), sizeof(IMPORT_DESCRIPTOR));

        if (importDesc.original_first_thunk == 0 &&
            importDesc.time_date_stamp == 0 &&
            importDesc.forwarder_chain == 0 &&
            importDesc.name == 0 &&
            importDesc.first_thunk == 0) {
            break;
        }

        if (importDesc.name != 0) {
            uint32_t nameRaw = rvaToRaw(importDesc.name);
            if (nameRaw != 0) {
                ImportLibrary lib;
                lib.name = readStringAtOffset(nameRaw);

                uint32_t thunkRva = importDesc.original_first_thunk != 0 ?
                                        importDesc.original_first_thunk : importDesc.first_thunk;

                if (thunkRva != 0) {
                    uint32_t thunkRaw = rvaToRaw(thunkRva);
                    if (thunkRaw != 0) {
                        file.seekg(thunkRaw, std::ios::beg);

                        while (true) {
                            THUNK_DATA32 thunk;
                            file.read(reinterpret_cast<char*>(&thunk), sizeof(THUNK_DATA32));

                            if (thunk.ul.function == 0) break;

                            ImportFunction func;
                            func.isByName = !(thunk.ul.ordinal & 0x80000000);

                            if (func.isByName) {
                                uint32_t importByNameRaw = rvaToRaw(thunk.ul.function);
                                if (importByNameRaw != 0) {
                                    std::streampos savedPos = file.tellg();
                                    file.seekg(importByNameRaw, std::ios::beg);

                                    uint16_t hint;
                                    file.read(reinterpret_cast<char*>(&hint), sizeof(uint16_t));
                                    func.hint = hint;
                                    func.name = readStringAtOffset(importByNameRaw + 2);

                                    file.seekg(savedPos);
                                }
                            } else {
                                func.ordinal = thunk.ul.ordinal & 0xFFFF;
                                func.name = QString("[Ordinal: %1]").arg(func.ordinal);
                            }

                            lib.functions.append(func);
                        }
                    }
                }

                if (!lib.functions.isEmpty()) {
                    imports.append(lib);
                }
            }
        }
        currentOffset += sizeof(IMPORT_DESCRIPTOR);
    }
    return true;
}

bool PEParser::readExportTable() {
    uint32_t exportRva = ntHeader.optional_header.data_directory[DIRECTORY_ENTRY_EXPORT].virtual_addr;
    uint32_t exportSize = ntHeader.optional_header.data_directory[DIRECTORY_ENTRY_EXPORT].size;

    if (exportRva == 0 || exportSize == 0) {
        return true;
    }

    uint32_t exportRaw = rvaToRaw(exportRva);
    if (exportRaw == 0) {
        lastError = "Failed to locate export table";
        return false;
    }

    EXPORT_DIRECTORY exportDir;
    file.seekg(exportRaw, std::ios::beg);
    file.read(reinterpret_cast<char*>(&exportDir), sizeof(EXPORT_DIRECTORY));

    exports.clear();

    uint32_t functionsRaw = rvaToRaw(exportDir.addr_of_functions);
    if (functionsRaw == 0) return true;

    QVector<uint32_t> functionAddresses(exportDir.number_of_functions);
    file.seekg(functionsRaw, std::ios::beg);
    for (uint32_t i = 0; i < exportDir.number_of_functions; i++) {
        file.read(reinterpret_cast<char*>(&functionAddresses[i]), sizeof(uint32_t));
    }

    QVector<QString> functionNames;
    QVector<uint16_t> nameOrdinals;

    if (exportDir.number_of_names > 0) {
        uint32_t namesRaw = rvaToRaw(exportDir.addr_of_names);
        uint32_t ordinalsRaw = rvaToRaw(exportDir.addr_of_name_ordinals);

        if (namesRaw != 0 && ordinalsRaw != 0) {
            QVector<uint32_t> nameRvas(exportDir.number_of_names);
            file.seekg(namesRaw, std::ios::beg);
            for (uint32_t i = 0; i < exportDir.number_of_names; i++) {
                file.read(reinterpret_cast<char*>(&nameRvas[i]), sizeof(uint32_t));
            }

            nameOrdinals.resize(exportDir.number_of_names);
            file.seekg(ordinalsRaw, std::ios::beg);
            for (uint32_t i = 0; i < exportDir.number_of_names; i++) {
                file.read(reinterpret_cast<char*>(&nameOrdinals[i]), sizeof(uint16_t));
            }

            for (uint32_t i = 0; i < exportDir.number_of_names; i++) {
                if (nameRvas[i] != 0) {
                    uint32_t nameRawOffset = rvaToRaw(nameRvas[i]);
                    if (nameRawOffset != 0) {
                        functionNames.append(readStringAtOffset(nameRawOffset));
                    } else {
                        functionNames.append("");
                    }
                } else {
                    functionNames.append("");
                }
            }
        }
    }

    for (uint32_t i = 0; i < exportDir.number_of_functions; i++) {
        if (functionAddresses[i] != 0) {
            ExportFunction exp;
            exp.rva = functionAddresses[i];
            exp.ordinal = exportDir.base + i;
            exp.hasName = false;

            for (int j = 0; j < nameOrdinals.size(); j++) {
                if (nameOrdinals[j] == i && j < functionNames.size()) {
                    exp.name = functionNames[j];
                    exp.hasName = true;
                    break;
                }
            }

            if (!exp.hasName) {
                exp.name = QString("[Ordinal: %1]").arg(exp.ordinal);
            }

            exports.append(exp);
        }
    }

    return true;
}

bool PEParser::parseFile(const QString &filePath) {
    if (file.is_open()) {
        file.close();
    }

    currentFilePath = filePath;
    file.open(filePath.toStdString(), std::ios::binary);

    if (!file.is_open()) {
        lastError = "Cannot open file: " + filePath;
        return false;
    }

    // Read all structures
    if (!readDosHeader()) return false;
    if (!readNtHeaders()) return false;
    if (!readSections()) return false;
    if (!readImportTable()) return false;
    if (!readExportTable()) return false;

    return true;
}

QString PEParser::getMachineTypeString(uint16_t machine) {
    switch (machine) {
    case 0x014c: return "Intel 386";
    case 0x8664: return "AMD64 (x86-64)";
    case 0x01c0: return "ARM";
    case 0xaa64: return "ARM64";
    case 0x0200: return "IA64";
    default: return QString("Unknown (0x%1)").arg(machine, 4, 16, QChar('0'));
    }
}

QString PEParser::getCharacteristicsString(uint16_t characteristics) {
    QStringList result;
    if (characteristics & 0x0001) result << "RELOCS_STRIPPED";
    if (characteristics & 0x0002) result << "EXECUTABLE_IMAGE";
    if (characteristics & 0x2000) result << "DLL";
    if (characteristics & 0x4000) result << "SYSTEM";
    return result.join(" | ");
}

QString PEParser::getSectionCharacteristicsString(uint32_t characteristics) {
    QStringList result;
    if (characteristics & 0x00000020) result << "CODE";
    if (characteristics & 0x00000040) result << "INITIALIZED_DATA";
    if (characteristics & 0x00000080) result << "UNINITIALIZED_DATA";
    if (characteristics & 0x20000000) result << "EXECUTE";
    if (characteristics & 0x40000000) result << "READ";
    if (characteristics & 0x80000000) result << "WRITE";
    return result.join(" | ");
}

QString PEParser::getSubsystemString(uint16_t subsystem) {
    switch (subsystem) {
    case 1: return "Native";
    case 2: return "Windows GUI";
    case 3: return "Windows CUI";
    case 5: return "OS2 CUI";
    case 7: return "POSIX CUI";
    case 9: return "Windows CE GUI";
    default: return QString("Unknown (%1)").arg(subsystem);
    }
}
