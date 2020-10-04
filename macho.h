#ifndef GENSIG_MACHO_H
#define GENSIG_MACHO_H

#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <netinet/in.h>
#include <iostream>
#include "emit.h"

enum {
    MH_EXECUTE = 0x2,
    MH_PRELOAD = 0x5,
    MH_DYLIB = 0x6,
    MH_DYLINKER = 0x7,
    MH_BUNDLE = 0x8,
    MH_KEXT_BUNDLE = 0xb,
};

enum LCType {
    LC_CODE_SIGNATURE = 0x1d,
    LC_SEGMENT_64 = 0x19,
};

struct MachOHeader {
    uint32_t cpuType;
    uint32_t cpuSubType;
    uint32_t filetype;
    uint32_t nCommands;
    uint32_t sizeOfCmds;
    uint32_t flags;
    uint32_t reserved; // only for 64-bit
} __attribute__((packed));

struct LoadCommand {
    uint32_t type;
    uint32_t cmdSize;

    explicit LoadCommand(uint32_t type, uint32_t cmdSize) : type(type), cmdSize(cmdSize) {};
};

struct Segment64LoadCommand : public LoadCommand {
    explicit Segment64LoadCommand(uint32_t type, uint32_t cmdSize)
      : LoadCommand(type, cmdSize) {};

    struct {
        char segname[16];
        uint64_t vmaddr;
        uint64_t vmsize;
        uint64_t fileoff;
        uint64_t filesize;
    } __attribute__((packed)) data {};
};

struct CodeSignatureLoadCommand : public LoadCommand {
    explicit CodeSignatureLoadCommand(uint32_t type, uint32_t cmdSize)
      : LoadCommand(type, cmdSize) {};

    struct {
        uint32_t dataOff;
        uint32_t dataSize;
    } __attribute__((packed)) data {};
};

struct MachO {
    explicit MachO(const std::string& filename);
    MachOHeader header;

    std::shared_ptr<Segment64LoadCommand> getSegment64LoadCommand(const std::string& name);
    std::shared_ptr<CodeSignatureLoadCommand> getCodeSignatureLoadCommand();

    bool requiresSignature();

private:
    std::vector<std::shared_ptr<LoadCommand>> loadCommands;
};

struct NotAMachOFileException : public std::exception {
    uint32_t magic;
    explicit NotAMachOFileException(uint32_t magic) : magic{magic} {}
};

#endif //GENSIG_MACHO_H
