#include <iostream>
#include <memory>
#include "signature.h"
#include "macho.h"

#include <CLI/App.hpp>
#include <CLI/Formatter.hpp>
#include <CLI/Config.hpp>

#include <cryptopp/sha.h>
#include <sstream>

static Hash hashString(const std::string& str) {
    Hash result {};

    CryptoPP::SHA256 foo;
    foo.Update(reinterpret_cast<const CryptoPP::byte *>(str.data()), str.length());
    foo.Final(reinterpret_cast<CryptoPP::byte *>(&result.bytes[0]));

    return result;
}

constexpr const unsigned int pageSize = 4096;

int main(int argc, char **argv) {
    CLI::App app{"gensig"};
    app.require_subcommand();

    std::string file, identifier;
    app.add_option("-f,--file", file, "Mach-O target file")
            ->required();
    app.add_option("-i,--identifier", identifier, "File identifier");

    app.add_subcommand("check-requires-signature",
                       "Determine if this is a macho file that must be signed");

    app.add_subcommand("size", "Determine size of embedded signature");
    app.add_subcommand("generate", "Generate an embedded signature and emit on stdout");
    app.add_subcommand("inject", "Generate and inject embedded signature");

    app.require_subcommand();

    CLI11_PARSE(app, argc, argv);

    if (app.got_subcommand("check-requires-signature")) {
        try {
            MachO test{file};
            return test.requiresSignature() ? 0 : 1;
        } catch (NotAMachOFileException& e) {
            return 1;
        }
    }

    SuperBlob sb {};

    // blob 1: code directory
    auto codeDirectory = std::make_shared<CodeDirectory>();

    codeDirectory->identifier = identifier.empty() ? file : identifier;
    codeDirectory->setPageSize(pageSize);


    MachO target{file};

    // TOOD: is this sane?
    if (target.header.filetype == MH_EXECUTE) {
        codeDirectory->data.execSegFlags |= CS_EXECSEG_MAIN_BINARY;
    }

    auto textSegment = target.getSegment64LoadCommand("__TEXT");
    if (textSegment) {
        codeDirectory->data.execSegBase = textSegment->data.fileoff;
        codeDirectory->data.execSegLimit = textSegment->data.filesize;
    }

    struct stat64 targetFileStat {};
    stat64(file.c_str(), &targetFileStat);

    size_t limit = targetFileStat.st_size;

    auto codeSignature = target.getCodeSignatureLoadCommand();
    if (codeSignature) {
        limit = codeSignature->data.dataOff;
        codeDirectory->setCodeLimit(codeSignature->data.dataOff);
    }

    std::ifstream machoFileRaw;
    machoFileRaw.open(file, std::ifstream::in | std::ifstream::binary);

    if (machoFileRaw.fail()) {
        throw std::runtime_error(std::string{"opening macho file: "} + strerror(errno));
    }

    unsigned int totalPages = (limit + (pageSize - 1)) / pageSize;

    for (int page = 0; page < totalPages; page++) {
        char pageBytes[pageSize];

        off_t thisPageStart = page * pageSize;
        off_t thisPageSize = pageSize;

        if (thisPageStart + thisPageSize > limit) {
            thisPageSize -= (thisPageStart + thisPageSize) - limit;
        }

        machoFileRaw.read(&pageBytes[0], thisPageSize);
        if (machoFileRaw.fail()) {
            throw std::runtime_error(std::string{"reading page: "}
            + std::to_string(page) + " " + strerror(errno) + " expcted_bytes="
            + std::to_string(thisPageSize) + " actual_bytes" + std::to_string(machoFileRaw.gcount()));
        }

        Hash pageHash {};

        CryptoPP::SHA256 pageHasher;
        pageHasher.Update(reinterpret_cast<const CryptoPP::byte *>(&pageBytes[0]), thisPageSize);
        pageHasher.Final(reinterpret_cast<CryptoPP::byte *>(&pageHash.bytes[0]));

        codeDirectory->addCodeHash(pageHash);
    }

    machoFileRaw.close();

    sb.blobs.push_back(codeDirectory);

    // blob 2: requirements index with 0 entries
    auto requirements = std::make_shared<Requirements>();
    std::basic_ostringstream<char> requirementsBuf;
    requirements->emit(requirementsBuf);
    codeDirectory->setSpecialHash(2, hashString(requirementsBuf.str()));
    sb.blobs.push_back(requirements);

    // blob 3: empty signature slot
    sb.blobs.emplace_back(std::make_shared<Signature>());

    if (app.got_subcommand("size")) {
        std::cout << sb.length() << std::endl;
    } else if (app.got_subcommand("generate")) {
        sb.emit(std::cout);
    } else if (app.got_subcommand("inject")) {
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
        machoFileWrite.open(file, std::ofstream::in | std::ofstream::out | std::ofstream::binary);
        if (machoFileWrite.fail()) {
            throw std::runtime_error(std::string{"opening macho file: "} + strerror(errno));
         }

        machoFileWrite.seekp(codeSignature->data.dataOff);
        sb.emit(machoFileWrite);
        machoFileWrite.close();
    }

    return 0;
}
