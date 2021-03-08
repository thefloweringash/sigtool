#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <sstream>
#include <sys/stat.h>

#include "commands.h"
#include "macho.h"
#include "signature.h"

constexpr const unsigned int pageSize = 4096;

static std::string readFile(const std::string &filename) {
    std::ifstream in{filename, std::ifstream::in | std::ifstream::binary};
    if (!in.is_open()) {
        throw std::runtime_error{"Failed opening file for read: '"
                                 + filename + "' :" + strerror(errno)};
    }

    std::string str;

    in.seekg(0, std::ifstream::end);
    str.resize(in.tellg());
    in.seekg(0, std::ifstream::beg);
    in.read(&str[0], str.size());

    return str;
}

static Hash hashBlob(const std::shared_ptr<Blob>& blob) {
    std::basic_ostringstream<char> buf;
    blob->emit(buf);
    return Hash{buf.str()};
}

std::string cpuTypeName(uint32_t cpuType) {
    switch (cpuType) {
        case CPUTYPE_X86_64:
            return "x86_64";
        case CPUTYPE_ARM64:
            return "arm64";
        default:
            throw std::runtime_error{std::string{"Unsupported cpu type"} + std::to_string(cpuType)};
    }
}

int Commands::checkRequiresSignature(const std::string &file) {
    try {
        MachOList test{file};
        bool anyRequires = std::any_of(test.machos.begin(), test.machos.end(), [](const std::shared_ptr<MachO>& h) {
            return h->requiresSignature();
        });
        return anyRequires ? 0 : 1;
    } catch (NotAMachOFileException &e) {
        // A shell script or text file, for example, does not require a signature.
        return 1;
    }
}

int Commands::showArch(const std::string &file) {
    MachOList test{file};

    for (const auto &macho : test.machos) {
        std::cout << cpuTypeName(macho->header.cpuType) << std::endl;
    }

    return 0;
}

static SuperBlob signMachO(
        const Commands::SignOptions& options,
        const std::shared_ptr<MachO> &target
) {
    SuperBlob sb{};

    // blob 1: code directory
    auto codeDirectory = std::make_shared<CodeDirectory>();

    codeDirectory->identifier = options.identifier.empty() ? options.filename : options.identifier;
    codeDirectory->setPageSize(pageSize);

    // TOOD: is this sane?
    if (target->header.filetype == MH_EXECUTE) {
        codeDirectory->data.execSegFlags |= CS_EXECSEG_MAIN_BINARY;
    }

    auto textSegment = target->getSegment64LoadCommand("__TEXT");
    if (textSegment) {
        codeDirectory->data.execSegBase = textSegment->data.fileoff;
        codeDirectory->data.execSegLimit = textSegment->data.fileoff + textSegment->data.filesize;
    }

    size_t limit = target->size;

    auto codeSignature = target->getCodeSignatureLoadCommand();
    if (codeSignature) {
        limit = codeSignature->data.dataOff;
        codeDirectory->setCodeLimit(codeSignature->data.dataOff);
    }

    std::ifstream machoFileRaw;
    machoFileRaw.open(options.filename, std::ifstream::in | std::ifstream::binary);
    machoFileRaw.seekg(target->offset);

    if (machoFileRaw.fail()) {
        throw std::runtime_error(std::string{"opening macho file: "} + strerror(errno));
    }

    unsigned int totalPages = (limit + (pageSize - 1)) / pageSize;

    for (int page = 0; page < totalPages; page++) {
        char pageBytes[pageSize];

        off_t thisPageStart = page * pageSize;
        size_t thisPageSize = pageSize;

        if (thisPageStart + thisPageSize > limit) {
            thisPageSize = limit - thisPageStart;
        }

        machoFileRaw.read(&pageBytes[0], thisPageSize);
        if (machoFileRaw.fail()) {
            throw std::runtime_error(std::string{"reading page: "}
                                     + std::to_string(page) + " " + strerror(errno) + " expcted_bytes="
                                     + std::to_string(thisPageSize) + " actual_bytes" +
                                     std::to_string(machoFileRaw.gcount()));
        }

        Hash pageHash{&pageBytes[0], thisPageSize};
        codeDirectory->addCodeHash(pageHash);
    }

    machoFileRaw.close();

    sb.blobs.push_back(codeDirectory);

    // blob 2: requirements index with 0 entries
    auto requirements = std::make_shared<Requirements>();
    codeDirectory->setSpecialHash(requirements->slotType(), hashBlob(requirements));
    sb.blobs.push_back(requirements);

    // optional blob: entitlements
    if (!options.entitlements.empty()) {
        auto entitlements = std::make_shared<Entitlements>(readFile(options.entitlements));
        codeDirectory->setSpecialHash(entitlements->slotType(), hashBlob(entitlements));
        sb.blobs.push_back(entitlements);
    }

    // blob: empty signature slot
    sb.blobs.emplace_back(std::make_shared<Signature>());

    return sb;
}


int Commands::showSize(const SignOptions& options) {
    MachOList list{options.filename};
    for (const auto &macho : list.machos) {
        auto sb = signMachO(options, macho);
        std::cout << cpuTypeName(macho->header.cpuType) << " " << sb.length() << std::endl;
    }

    return 0;
}

int Commands::generate(const SignOptions& options) {
    MachOList list{options.filename};
    for (const auto &macho : list.machos) {
        auto sb = signMachO(options, macho);
        // TODO: packing them all together is not helpful, but this is still usable
        // for the thin case.
        sb.emit(std::cout);
    }

    return 0;
}

int Commands::inject(const SignOptions& options) {
    MachOList list{options.filename};
    for (const auto &macho : list.machos) {
        auto sb = signMachO(options, macho);

        auto codeSignature = macho->getCodeSignatureLoadCommand();

        if (!codeSignature) {
            throw std::runtime_error{"cannot inject signature without appropriate load command"};
        }

        if (sb.length() > codeSignature->data.dataSize) {
            throw std::runtime_error{
                    std::string{"allocated size too small: need "}
                    + std::to_string(sb.length())
                    + std::string{"but have "}
                    + std::to_string(codeSignature->data.dataSize)
            };
        }

        std::ofstream machoFileWrite;
        machoFileWrite.open(options.filename, std::ofstream::in | std::ofstream::out | std::ofstream::binary);
        if (machoFileWrite.fail()) {
            throw std::runtime_error(std::string{"opening macho file: "} + strerror(errno));
        }

        machoFileWrite.seekp(macho->offset + codeSignature->data.dataOff);
        sb.emit(machoFileWrite);
        machoFileWrite.close();
    }

    return 0;
}

